#include "handlers/info_handler.hpp"

#include <chrono>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <optional>
#include <sstream>
#include <string_view>
#include <vector>

#include <fmt/format.h>
#include <jwt-cpp/jwt.h>

#include "util/device_fingerprint.hpp"
#include "version.h"

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace certctrl {
namespace {
namespace fs = std::filesystem;

std::optional<std::string> read_trimmed(const fs::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    return std::nullopt;
  }
  std::string contents((std::istreambuf_iterator<char>(ifs)), {});
  auto first = contents.find_first_not_of("\r\n\t \f\v");
  if (first == std::string::npos) {
    return std::nullopt;
  }
  auto last = contents.find_last_not_of("\r\n\t \f\v");
  if (last == std::string::npos || last < first) {
    return std::nullopt;
  }
  return contents.substr(first, last - first + 1);
}

bool is_valid_device_public_id(std::string_view candidate) {
  if (candidate.size() != 36) {
    return false;
  }
  for (size_t i = 0; i < candidate.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (candidate[i] != '-') {
        return false;
      }
      continue;
    }
    if (!std::isxdigit(static_cast<unsigned char>(candidate[i]))) {
      return false;
    }
  }
  return true;
}

std::optional<std::string> write_text_0600(const fs::path &path,
                                           std::string_view text) {
  try {
    std::error_code ec;
    if (auto parent = path.parent_path(); !parent.empty()) {
      fs::create_directories(parent, ec);
      if (ec) {
        return std::string{"create_directories failed: "} + ec.message();
      }
    }
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
      return std::string{"open failed for "} + path.string();
    }
    ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!ofs) {
      return std::string{"write failed for "} + path.string();
    }
#ifndef _WIN32
    ::chmod(path.c_str(), 0600);
#endif
    return std::nullopt;
  } catch (const std::exception &ex) {
    return std::string{"write_text_0600 exception: "} + ex.what();
  }
}

std::optional<std::string> decode_device_id(const std::string &token) {
  try {
    auto decoded = jwt::decode(token);
    if (decoded.has_payload_claim("device_id")) {
      return decoded.get_payload_claim("device_id").as_string();
    }
    if (decoded.has_payload_claim("sub")) {
      return decoded.get_payload_claim("sub").as_string();
    }
  } catch (...) {
  }
  return std::nullopt;
}

std::optional<std::chrono::system_clock::time_point>
decode_expiry(const std::string &token) {
  try {
    auto decoded = jwt::decode(token);
    if (decoded.has_payload_claim("exp")) {
      return decoded.get_payload_claim("exp").as_date();
    }
  } catch (...) {
  }
  return std::nullopt;
}

std::string format_utc(const std::chrono::system_clock::time_point &tp) {
  std::time_t raw = std::chrono::system_clock::to_time_t(tp);
  std::tm tm {};
#if defined(_WIN32)
  gmtime_s(&tm, &raw);
#else
  gmtime_r(&raw, &tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%SZ");
  return oss.str();
}

} // namespace

InfoHandler::InfoHandler(cjj365::ConfigSources &config_sources,
                         certctrl::ICertctrlConfigProvider &config_provider,
                         customio::ConsoleOutput &output_hub,
                         CliCtx &cli_ctx)
    : config_sources_(config_sources),
      certctrl_config_provider_(config_provider),
      output_hub_(output_hub), cli_ctx_(cli_ctx) {}

monad::IO<void> InfoHandler::start() {
  using VoidIO = monad::IO<void>;

  auto &printer = output_hub_.printer();
  printer.green() << "cert-ctrl environment summary" << std::endl;

  fs::path runtime_dir = cli_ctx_.params.runtime_dir;
  if (runtime_dir.empty()) {
    runtime_dir = certctrl_config_provider_.get().runtime_dir;
  }

  std::vector<fs::path> search_paths(config_sources_.paths_.begin(),
                                     config_sources_.paths_.end());

  printer.cyan() << "Configuration" << std::endl;
  if (search_paths.empty()) {
    printer.white() << "  (no configuration directories discovered)"
                    << std::endl;
  } else {
    for (const auto &dir : search_paths) {
      auto proxy = printer.white();
      proxy << "  - " << dir.string();
      if (!runtime_dir.empty() && dir == runtime_dir) {
        proxy << "  (runtime)";
      }
      proxy << std::endl;
    }
  }

  auto runtime_proxy = printer.white();
  if (!runtime_dir.empty()) {
    runtime_proxy << "  Runtime dir: " << runtime_dir.string() << std::endl;
  } else {
    runtime_proxy << "  Runtime dir: <unset>" << std::endl;
  }

  if (!runtime_dir.empty()) {
    std::error_code ec;
    const fs::path state_dir = runtime_dir / "state";
    bool state_exists = fs::exists(state_dir, ec) && !ec;
    auto proxy = printer.white();
    proxy << "  State dir: " << state_dir.string();
    if (!state_exists) {
      proxy << " (missing)";
    }
    proxy << std::endl;
  }

  if (auto logging_cfg = config_sources_.logging_config(); logging_cfg.is_ok()) {
    auto proxy = printer.white();
    proxy << "  Log dir: " << logging_cfg.value().log_dir << std::endl;
  } else {
    output_hub_.logger().warning()
        << "Unable to resolve log configuration: "
        << logging_cfg.error().what << std::endl;
  }

  printer.cyan() << "Device" << std::endl;
  auto device_info = cjj365::device::gather_device_info(
      fmt::format("cert-ctrl/{}", MYAPP_VERSION));
  auto fingerprint =
      cjj365::device::generate_device_fingerprint_hex(device_info);
  auto public_id =
      cjj365::device::device_public_id_from_fingerprint(fingerprint);
  std::optional<std::string> stored_device_id;
  fs::path device_id_path;
  if (!runtime_dir.empty()) {
    device_id_path = runtime_dir / "state" / "device_public_id.txt";
    stored_device_id = read_trimmed(device_id_path);
    const bool stored_valid =
        stored_device_id && is_valid_device_public_id(*stored_device_id);
    if (!stored_valid) {
      if (stored_device_id) {
        output_hub_.logger().warning()
            << "Ignoring malformed device_public_id stored at "
            << device_id_path << "; rewriting derived identifier."
            << std::endl;
      } else {
        output_hub_.logger().info()
            << "device_public_id.txt missing; writing derived identifier to "
            << device_id_path << std::endl;
      }
      if (auto err = write_text_0600(device_id_path, public_id)) {
        output_hub_.logger().warning()
            << "Failed to persist device_public_id: " << *err << std::endl;
      } else {
        stored_device_id = public_id;
      }
    }
  }
  auto default_name = fmt::format(
      "CLI Device {}",
      device_info.hostname.empty() ? std::string{"unknown"}
                                   : device_info.hostname);

  {
    auto proxy = printer.white();
    proxy << "  Hostname: ";
    if (device_info.hostname.empty()) {
      proxy << "<unknown>";
    } else {
      proxy << device_info.hostname;
    }
    proxy << std::endl;
  }
  {
    auto proxy = printer.white();
    proxy << "  Platform: " << device_info.platform;
    if (!device_info.os_version.empty()) {
      proxy << ' ' << device_info.os_version;
    }
    proxy << std::endl;
  }
  if (!device_info.model.empty()) {
    auto proxy = printer.white();
    proxy << "  Model: " << device_info.model << std::endl;
  }
  if (!device_info.cpu_model.empty()) {
    auto proxy = printer.white();
    proxy << "  CPU: " << device_info.cpu_model << std::endl;
  }
  if (!device_info.memory_info.empty()) {
    auto proxy = printer.white();
    proxy << "  Memory: " << device_info.memory_info << std::endl;
  }
  {
    auto proxy = printer.white();
    proxy << "  Derived device ID: " << public_id;
    if (stored_device_id && *stored_device_id != public_id) {
      proxy << "  (differs from stored)";
    }
    proxy << std::endl;
  }
  if (!runtime_dir.empty()) {
    auto proxy = printer.white();
    proxy << "  Stored device ID: ";
    if (stored_device_id) {
      proxy << *stored_device_id;
    } else {
      proxy << "<missing>";
    }
    proxy << std::endl;
  }
  {
    auto proxy = printer.white();
    proxy << "  Suggested device name: " << default_name << std::endl;
  }

  printer.cyan() << "Session" << std::endl;
  std::optional<std::string> access_token;
  std::optional<std::string> refresh_token;
  if (!runtime_dir.empty()) {
    const fs::path state_dir = runtime_dir / "state";
    access_token = read_trimmed(state_dir / "access_token.txt");
    refresh_token = read_trimmed(state_dir / "refresh_token.txt");
  }

  {
    auto proxy = printer.white();
    proxy << "  Access token: "
      << (access_token ? "present" : "missing") << std::endl;
  }
  {
    auto proxy = printer.white();
    proxy << "  Refresh token: "
      << (refresh_token ? "present" : "missing") << std::endl;
  }

  if (access_token) {
    if (auto device_id = decode_device_id(*access_token); device_id) {
      auto proxy = printer.white();
      proxy << "  Token device_id: " << *device_id << std::endl;
    }
    if (auto expiry = decode_expiry(*access_token); expiry) {
      auto proxy = printer.white();
      proxy << "  Access token expires: " << format_utc(*expiry);
      auto now = std::chrono::system_clock::now();
      if (*expiry < now) {
        proxy << " (expired)";
      } else {
        auto remaining =
            std::chrono::duration_cast<std::chrono::seconds>(*expiry - now)
                .count();
        proxy << " (in " << remaining << "s)";
      }
      proxy << std::endl;
    }
  }

  return VoidIO::pure();
}

} // namespace certctrl
