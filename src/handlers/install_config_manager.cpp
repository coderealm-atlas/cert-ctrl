#include "handlers/install_config_manager.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/import_ca_action.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/log/trivial.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fmt/format.h>
#include <fstream>
#include <functional>
#include <iostream>
#include <random>
#include <sstream>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sodium.h>
#ifdef _WIN32
#include <windows.h>
#include <codecvt>
#include <locale>
#endif
#ifndef _WIN32
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "base64.h"
#include "my_error_codes.hpp"
#include "openssl/openssl_raii.hpp"
#include "result_monad.hpp"
#include "util/secret_util.hpp"
#include "util/user_key_crypto.hpp"

namespace certctrl {

namespace {

constexpr const char kPfxPasswordEnvVar[] = "CERTCTRL_PFX_PASSWORD";

struct CertActionScanResult {
  bool has_matching_items{false};
  bool has_copy_targets{false};
  bool has_exec_targets{false};

  bool actionable() const { return has_copy_targets || has_exec_targets; }
};

bool has_non_empty_entry(
    const std::optional<std::vector<std::string>> &values) {
  if (!values) {
    return false;
  }
  return std::any_of(values->begin(), values->end(),
                     [](const std::string &value) { return !value.empty(); });
}

CertActionScanResult
scan_cert_actionability(const dto::DeviceInstallConfigDto &config,
                        std::int64_t cert_id) {
  CertActionScanResult result;
  for (const auto &item : config.installs) {
    if (!item.enabled) {
      continue;
    }
    if (!item.ob_type || *item.ob_type != "cert") {
      continue;
    }
    if (!item.ob_id || *item.ob_id != cert_id) {
      continue;
    }

    result.has_matching_items = true;

    if (item.type == "copy" && has_non_empty_entry(item.to)) {
      result.has_copy_targets = true;
    }

    const bool has_cmd =
        (item.cmd && !item.cmd->empty()) || has_non_empty_entry(item.cmd_argv);
    if (has_cmd) {
      result.has_exec_targets = true;
    }

    if (result.actionable()) {
      break;
    }
  }
  return result;
}

std::string generate_temp_suffix() {
  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<std::uint64_t> dist;
  std::uint64_t random_part = dist(gen);
  return fmt::format("{}.{}", now, random_part);
}

std::string to_lower_copy(const std::string &value) {
  std::string lower = value;
  std::transform(
      lower.begin(), lower.end(), lower.begin(),
      [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return lower;
}

struct ScriptBundleParseResult {
  bool had_blocks{false};
  std::unordered_map<std::string, std::string> blocks; // key is lower-case
};

static std::string trim_copy(std::string value) {
  auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
  value.erase(value.begin(),
              std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
              value.end());
  return value;
}

static ScriptBundleParseResult parse_script_bundle(const std::string &content) {
  ScriptBundleParseResult result;

  std::istringstream iss(content);
  std::string line;

  bool in_block = false;
  std::string current_name;
  std::ostringstream current_body;

  while (std::getline(iss, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    if (!in_block) {
      constexpr std::string_view kBegin = "@@@BEGIN";
      if (line.rfind(kBegin.data(), 0) == 0) {
        std::string name = trim_copy(line.substr(kBegin.size()));
        if (!name.empty() && name.front() == ' ') {
          name = trim_copy(name);
        }
        if (!name.empty()) {
          in_block = true;
          result.had_blocks = true;
          current_name = to_lower_copy(name);
          current_body.str(std::string());
          current_body.clear();
        }
      }
      continue;
    }

    constexpr std::string_view kEnd = "@@@END";
    if (line.rfind(kEnd.data(), 0) == 0) {
      if (!current_name.empty()) {
        result.blocks[current_name] = current_body.str();
      }
      in_block = false;
      current_name.clear();
      continue;
    }

    current_body << line << '\n';
  }

  // If an unterminated block exists, keep it as-is.
  if (in_block && !current_name.empty()) {
    result.blocks[current_name] = current_body.str();
  }

  return result;
}

static bool is_bypass_auto_apply_event(const std::string &type) {
  // Cert/CA material events should bypass auto_apply_config.
  return type == "cert.updated" || type == "cert.unassigned" ||
         type == "cert.wrap_ready" || type == "ca.assigned" ||
         type == "ca.unassigned";
}

static std::optional<std::pair<std::string, std::string>>
select_platform_script(const std::string &bundle_content) {
  auto parsed = parse_script_bundle(bundle_content);

  if (!parsed.had_blocks) {
#ifdef _WIN32
    return std::make_pair(std::string("windows.pwsh"), bundle_content);
#else
    return std::make_pair(std::string("posix.sh"), bundle_content);
#endif
  }

#ifdef _WIN32
  static const char *kCandidates[] = {"windows.pwsh", "windows.powershell",
                                      "windows.cmd"};
  for (const auto *name : kCandidates) {
    auto it = parsed.blocks.find(name);
    if (it != parsed.blocks.end() && !it->second.empty()) {
      return std::make_pair(std::string(name), it->second);
    }
  }
  return std::nullopt;
#else
  auto it = parsed.blocks.find("posix.sh");
  if (it != parsed.blocks.end() && !it->second.empty()) {
    return std::make_pair(std::string("posix.sh"), it->second);
  }
  return std::nullopt;
#endif
}

static std::optional<std::string>
persist_after_update_script_atomic(const std::filesystem::path &state_dir,
                                  const std::string &variant_name,
                                  const std::string &content) {
  try {
    std::error_code ec;
    std::filesystem::create_directories(state_dir, ec);

    std::filesystem::path target = state_dir;
#ifdef _WIN32
    if (variant_name == "windows.cmd") {
      target /= "after_update_script.cmd";
    } else {
      target /= "after_update_script.ps1";
    }
#else
    (void)variant_name;
    target /= "after_update_script.sh";
#endif

    auto tmp = target;
    tmp += ".tmp-";
    tmp += generate_temp_suffix();

    {
      std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
      if (!ofs.is_open()) {
        return std::optional<std::string>("failed to open temp script file");
      }
      ofs << content;
    }

    std::filesystem::rename(tmp, target, ec);
    if (ec) {
      return std::optional<std::string>(
          std::string("failed to rename script file: ") + ec.message());
    }

#ifndef _WIN32
    std::filesystem::permissions(target,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace,
                                 ec);
#endif

    return std::nullopt;
  } catch (const std::exception &ex) {
    return std::optional<std::string>(ex.what());
  }
}

static std::optional<std::string>
run_script_file_best_effort(const std::filesystem::path &script_path,
                            const std::string &variant_name,
                            const std::string &event_name) {
#ifdef _WIN32
  // On Windows, use a best-effort approach. We construct argv in a way that
  // avoids relying on shebang/executable bits.
  std::vector<std::string> argv;
  if (variant_name == "windows.cmd") {
    // cmd.exe /C "<script>" "<event>"
    argv = {"cmd.exe", "/C",
            fmt::format("\"{}\" \"{}\"", script_path.string(), event_name)};
  } else if (variant_name == "windows.powershell") {
    argv = {"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
            script_path.string(), event_name};
  } else {
    // windows.pwsh (default)
    argv = {"pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
            script_path.string(), event_name};
  }

  // Use CreateProcessW similarly to ExecActionHandler (simplified; no env).
  std::wstring cmd_line;
  for (std::size_t i = 0; i < argv.size(); ++i) {
    if (i != 0) {
      cmd_line.push_back(L' ');
    }
    // Naive quoting: wrap args containing spaces or quotes.
    std::wstring warg;
    {
      std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
      warg = conv.from_bytes(argv[i]);
    }
    const bool needs_quote =
        (warg.find(L' ') != std::wstring::npos ||
         warg.find(L'\t') != std::wstring::npos ||
         warg.find(L'\"') != std::wstring::npos);
    if (!needs_quote) {
      cmd_line += warg;
      continue;
    }
    cmd_line.push_back(L'\"');
    for (wchar_t ch : warg) {
      if (ch == L'\"') {
        cmd_line += L"\\\"";
      } else {
        cmd_line.push_back(ch);
      }
    }
    cmd_line.push_back(L'\"');
  }

  std::vector<wchar_t> cmd_buffer(cmd_line.begin(), cmd_line.end());
  cmd_buffer.push_back(L'\0');

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  BOOL created = CreateProcessW(nullptr, cmd_buffer.data(), nullptr, nullptr,
                                FALSE, 0, nullptr, nullptr, &si, &pi);
  if (!created) {
    return std::optional<std::string>("CreateProcess failed");
  }

  const DWORD timeout_ms = 30000;
  DWORD wait_result = WaitForSingleObject(pi.hProcess, timeout_ms);
  if (wait_result == WAIT_TIMEOUT) {
    TerminateProcess(pi.hProcess, 1u);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return std::optional<std::string>("script timed out");
  }
  if (wait_result != WAIT_OBJECT_0) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return std::optional<std::string>("WaitForSingleObject failed");
  }

  DWORD exit_code = 0;
  if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return std::optional<std::string>("GetExitCodeProcess failed");
  }

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  if (exit_code != 0) {
    return std::optional<std::string>(
        fmt::format("script exited with code {}", exit_code));
  }
  return std::nullopt;
#else
  (void)variant_name;
  std::vector<std::string> argv = {"sh", script_path.string(), event_name};

  std::vector<char *> cargv;
  cargv.reserve(argv.size() + 1);
  for (auto &s : argv) {
    cargv.push_back(const_cast<char *>(s.c_str()));
  }
  cargv.push_back(nullptr);

  pid_t pid = fork();
  if (pid < 0) {
    return std::optional<std::string>(std::string("fork failed: ") +
                                      std::strerror(errno));
  }

  if (pid == 0) {
    execvp(cargv[0], cargv.data());
    _exit(127);
  }

  int status = 0;
  auto start = std::chrono::steady_clock::now();
  const auto timeout = std::chrono::milliseconds(30000);
  while (true) {
    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w == pid) {
      break;
    }
    if (w == -1) {
      return std::optional<std::string>(std::string("waitpid failed: ") +
                                        std::strerror(errno));
    }
    if (std::chrono::steady_clock::now() - start >= timeout) {
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      return std::optional<std::string>("script timed out");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  if (WIFEXITED(status)) {
    int rc = WEXITSTATUS(status);
    if (rc != 0) {
      return std::optional<std::string>(
          fmt::format("script exited with code {}", rc));
    }
    return std::nullopt;
  }
  if (WIFSIGNALED(status)) {
    return std::optional<std::string>(
        fmt::format("script killed by signal {}", WTERMSIG(status)));
  }
  return std::optional<std::string>("unknown script result");
#endif
}

std::optional<std::string>
read_file_as_string(const std::filesystem::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    return std::nullopt;
  }
  std::ostringstream oss;
  oss << ifs.rdbuf();
  return oss.str();
}

std::optional<boost::json::object> parse_bundle_data(const std::string &body) {
  boost::system::error_code ec;
  auto parsed = boost::json::parse(body, ec);
  if (ec || !parsed.is_object()) {
    return std::nullopt;
  }
  auto &obj = parsed.as_object();
  if (auto *data = obj.if_contains("data"); data && data->is_object()) {
    return data->as_object();
  }
  return std::nullopt;
}

std::optional<std::string> join_pem_entries(const boost::json::value &value) {
  if (value.is_string()) {
    return boost::json::value_to<std::string>(value);
  }
  if (!value.is_array()) {
    return std::nullopt;
  }
  std::ostringstream oss;
  bool first = true;
  for (const auto &entry : value.as_array()) {
    if (!entry.is_string())
      continue;
    if (!first) {
      oss << '\n';
    }
    oss << entry.as_string();
    first = false;
  }
  auto result = oss.str();
  if (result.empty())
    return std::nullopt;
  return result;
}

std::vector<std::string> split_pem_certificates(const std::string &pem_blob) {
  constexpr std::string_view kBegin = "-----BEGIN CERTIFICATE-----";
  constexpr std::string_view kEnd = "-----END CERTIFICATE-----";

  std::vector<std::string> blocks;
  std::size_t search_pos = 0;
  while (search_pos < pem_blob.size()) {
    auto begin_pos = pem_blob.find(kBegin.data(), search_pos, kBegin.size());
    if (begin_pos == std::string::npos) {
      break;
    }
    auto end_pos = pem_blob.find(kEnd.data(), begin_pos, kEnd.size());
    if (end_pos == std::string::npos) {
      break;
    }
    end_pos += kEnd.size();
    while (end_pos < pem_blob.size() &&
           (pem_blob[end_pos] == '\n' || pem_blob[end_pos] == '\r')) {
      ++end_pos;
    }
    blocks.emplace_back(pem_blob.substr(begin_pos, end_pos - begin_pos));
    search_pos = end_pos;
  }
  return blocks;
}

std::string join_cert_blocks(const std::vector<std::string> &blocks,
                             std::size_t start_index) {
  std::string result;
  for (std::size_t i = start_index; i < blocks.size(); ++i) {
    if (!result.empty() && result.back() != '\n') {
      result.push_back('\n');
    }
    result += blocks[i];
    if (!result.empty() && result.back() != '\n') {
      result.push_back('\n');
    }
  }
  return result;
}

std::optional<std::vector<unsigned char>>
decode_base64_to_bytes(const boost::json::value &value) {
  if (!value.is_string()) {
    return std::nullopt;
  }
  try {
    auto encoded = boost::json::value_to<std::string>(value);
    std::string decoded = base64_decode(encoded);
    return std::vector<unsigned char>(decoded.begin(), decoded.end());
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::vector<unsigned char>>
decode_base64_string_raw(const std::string &value) {
  try {
    auto decoded = base64_decode(value);
    return std::vector<unsigned char>(decoded.begin(), decoded.end());
  } catch (...) {
    return std::nullopt;
  }
}

struct DeviceKeyPair {
  std::array<unsigned char, crypto_box_PUBLICKEYBYTES> pk{};
  std::array<unsigned char, crypto_box_SECRETKEYBYTES> sk{};
};

std::optional<DeviceKeyPair>
load_device_keypair_from_paths(const std::vector<std::filesystem::path> &paths,
                               std::string &error_out) {
  if (sodium_init() < 0) {
    error_out = "libsodium initialization failed";
    return std::nullopt;
  }
  for (const auto &candidate : paths) {
    if (!std::filesystem::exists(candidate)) {
      continue;
    }
    std::ifstream ifs(candidate, std::ios::binary);
    if (!ifs.is_open()) {
      continue;
    }
    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(ifs)),
                                      std::istreambuf_iterator<char>());
    if (buffer.empty()) {
      continue;
    }

    auto normalize_secret = [&](std::vector<unsigned char> raw)
        -> std::optional<std::array<unsigned char, crypto_box_SECRETKEYBYTES>> {
      if (raw.size() == crypto_box_SECRETKEYBYTES) {
        std::array<unsigned char, crypto_box_SECRETKEYBYTES> out{};
        std::copy(raw.begin(), raw.end(), out.begin());
        return out;
      }
      std::string text(raw.begin(), raw.end());
      text.erase(std::remove_if(text.begin(), text.end(),
                                [](char ch) {
                                  return ch == '\n' || ch == '\r' ||
                                         ch == ' ' || ch == '\t';
                                }),
                 text.end());
      if (text.empty())
        return std::nullopt;
      try {
        auto decoded = base64_decode(text);
        if (decoded.size() != crypto_box_SECRETKEYBYTES) {
          return std::nullopt;
        }
        std::array<unsigned char, crypto_box_SECRETKEYBYTES> out{};
        std::copy(decoded.begin(), decoded.end(), out.begin());
        return out;
      } catch (...) {
        return std::nullopt;
      }
    };

    auto secret = normalize_secret(std::move(buffer));
    if (!secret) {
      continue;
    }

    DeviceKeyPair pair{};
    pair.sk = *secret;
    crypto_scalarmult_base(pair.pk.data(), pair.sk.data());
    return pair;
  }

  std::ostringstream oss;
  oss << "Device secret key not found. Checked:";
  for (const auto &p : paths) {
    oss << ' ' << p.string();
  }
  error_out = oss.str();
  return std::nullopt;
}

std::optional<std::string>
convert_der_private_key_to_pem(const std::vector<unsigned char> &der,
                               std::string &error_out) {
  if (der.empty()) {
    error_out = "DER private key payload is empty";
    return std::nullopt;
  }
  std::string der_string(der.begin(), der.end());
  auto pkey = cjj365::opensslutil::load_private_key(der_string, true);
  if (!pkey) {
    error_out = "Failed to parse DER private key";
    return std::nullopt;
  }
  try {
    auto pem = cjj365::opensslutil::key_to_pem(pkey, true);
    return pem;
  } catch (const std::exception &ex) {
    error_out = std::string("Failed to convert DER to PEM: ") + ex.what();
    return std::nullopt;
  }
}

std::optional<std::string>
extract_private_key_from_detail(const boost::json::object &detail_obj,
                                std::string &error_out) {
  auto get_string_field =
      [](const boost::json::object &obj,
         std::string_view key) -> std::optional<std::string> {
    if (auto *val = obj.if_contains(key)) {
      if (val->is_string()) {
        auto str = val->as_string();
        if (!str.empty()) {
          return std::string(str.c_str());
        }
      }
    }
    return std::nullopt;
  };

  const boost::json::object *view = &detail_obj;
  if (auto *cert_node = detail_obj.if_contains("certificate")) {
    if (cert_node->is_object()) {
      view = &cert_node->as_object();
    }
  }

  if (auto pem = get_string_field(*view, "private_key_pem")) {
    return pem;
  }
  if (auto pem = get_string_field(detail_obj, "private_key_pem")) {
    return pem;
  }

  auto decode_der_field =
      [&](const boost::json::object &source,
          std::string_view key) -> std::optional<std::string> {
    if (auto encoded = get_string_field(source, key)) {
      if (auto bytes = decode_base64_string_raw(*encoded)) {
        std::string local_error;
        if (auto pem = convert_der_private_key_to_pem(*bytes, local_error)) {
          return pem;
        }
        if (!local_error.empty()) {
          error_out = local_error;
        }
      }
    }
    return std::nullopt;
  };

  if (auto pem = decode_der_field(*view, "private_key_der_b64")) {
    return pem;
  }
  if (auto pem = decode_der_field(detail_obj, "private_key_der_b64")) {
    return pem;
  }
  if (auto pem = decode_der_field(*view, "key_der_b64")) {
    return pem;
  }
  if (auto pem = decode_der_field(detail_obj, "key_der_b64")) {
    return pem;
  }
  if (auto pem = decode_der_field(detail_obj, "der")) {
    return pem;
  }

  if (error_out.empty()) {
    error_out = "Certificate detail response missing private key payload";
  }
  return std::nullopt;
}

std::optional<std::string>
decrypt_private_key_pem(const boost::json::object &bundle_data,
                        const std::filesystem::path &runtime_dir,
                        const std::filesystem::path &state_dir,
                        std::string &error_out) {
  std::string enc_scheme;
  if (auto *enc_scheme_val = bundle_data.if_contains("enc_scheme")) {
    if (enc_scheme_val->is_string()) {
      enc_scheme = to_lower_copy(enc_scheme_val->as_string().c_str());
    } else if (enc_scheme_val->is_int64()) {
      enc_scheme = std::to_string(enc_scheme_val->as_int64());
    }
  }

  if (enc_scheme.empty()) {
    enc_scheme = "aes256gcm";
  }

  if (enc_scheme == "plaintext" || enc_scheme == "0") {
    if (auto *pem_val = bundle_data.if_contains("private_key_pem");
        pem_val && pem_val->is_string()) {
      return boost::json::value_to<std::string>(*pem_val);
    }
    if (auto *der_val = bundle_data.if_contains("private_key_der_b64");
        der_val && der_val->is_string()) {
      auto der = decode_base64_to_bytes(*der_val);
      if (der && !der->empty()) {
        return convert_der_private_key_to_pem(*der, error_out);
      }
    }
    error_out = "Plaintext bundle missing private key payload";
    return std::nullopt;
  }

  if (enc_scheme == "aes256gcm" || enc_scheme == "1") {
    std::vector<std::filesystem::path> candidates{
        runtime_dir / "keys" / "dev_sk.bin", state_dir / "dev_sk.bin"};
    auto device_keys = load_device_keypair_from_paths(candidates, error_out);
    if (!device_keys) {
      return std::nullopt;
    }

    if (auto *fp_val = bundle_data.if_contains("device_keyfp_b64")) {
      auto expected_fp = decode_base64_to_bytes(*fp_val);
      if (expected_fp) {
        try {
          auto computed_fp =
              cjj365::cryptutil::fingerprint_public_key(device_keys->pk.data());
          if (expected_fp->size() != computed_fp.size() ||
              !std::equal(expected_fp->begin(), expected_fp->end(),
                          computed_fp.begin())) {
            error_out = "Device key fingerprint mismatch";
            return std::nullopt;
          }
        } catch (const std::exception &ex) {
          error_out =
              std::string("Failed to fingerprint device key: ") + ex.what();
          return std::nullopt;
        }
      }
    }

    auto enc_key_val = bundle_data.if_contains("enc_data_key_b64");
    auto cipher_val = bundle_data.if_contains("enc_privkey_b64");
    auto nonce_val = bundle_data.if_contains("privkey_nonce_b64");
    auto tag_val = bundle_data.if_contains("privkey_tag_b64");
    if (!enc_key_val || !cipher_val || !nonce_val || !tag_val) {
      error_out = "Encrypted bundle missing required fields";
      return std::nullopt;
    }

    auto enc_key = decode_base64_to_bytes(*enc_key_val);
    auto ciphertext = decode_base64_to_bytes(*cipher_val);
    auto nonce = decode_base64_to_bytes(*nonce_val);
    auto tag = decode_base64_to_bytes(*tag_val);
    if (!enc_key || !ciphertext || !nonce || !tag) {
      error_out = "Failed to decode encrypted private key fields";
      return std::nullopt;
    }
    if (tag->size() != crypto_aead_aes256gcm_ABYTES) {
      error_out = "Unexpected AES-GCM tag length";
      return std::nullopt;
    }

    std::vector<unsigned char> combined_cipher = *ciphertext;
    combined_cipher.insert(combined_cipher.end(), tag->begin(), tag->end());

    std::string decrypted;
    if (!cjj365::cryptutil::decrypt_hybrid_gcm_sealed(
            device_keys->pk.data(), device_keys->sk.data(),
            std::string(reinterpret_cast<const char *>(combined_cipher.data()),
                        combined_cipher.size()),
            std::string(reinterpret_cast<const char *>(nonce->data()),
                        nonce->size()),
            std::string(reinterpret_cast<const char *>(enc_key->data()),
                        enc_key->size()),
            decrypted, std::string_view{})) {
      error_out = "Failed to decrypt AES-GCM private key";
      return std::nullopt;
    }

    if (decrypted.rfind("-----BEGIN", 0) == 0) {
      return decrypted;
    }

    std::vector<unsigned char> der(decrypted.begin(), decrypted.end());
    return convert_der_private_key_to_pem(der, error_out);
  }

  error_out = "Unsupported enc_scheme: " + enc_scheme;
  return std::nullopt;
}

std::optional<std::vector<unsigned char>>
extract_bundle_pfx_bytes(const boost::json::object &bundle_data) {
  if (auto *pfx_val = bundle_data.if_contains("bundle_pfx_b64")) {
    return decode_base64_to_bytes(*pfx_val);
  }
  if (auto *pkcs_val = bundle_data.if_contains("pkcs12_b64")) {
    return decode_base64_to_bytes(*pkcs_val);
  }
  return std::nullopt;
}

std::optional<boost::json::object>
load_bundle_object(const std::filesystem::path &resource_root) {
  auto raw_path = resource_root.parent_path() / "bundle_raw.json";
  auto raw_content = read_file_as_string(raw_path);
  if (!raw_content) {
    return std::nullopt;
  }
  return parse_bundle_data(*raw_content);
}

std::filesystem::perms default_directory_perms() {
#ifdef _WIN32
  return std::filesystem::perms::owner_all;
#else
  return std::filesystem::perms::owner_read |
         std::filesystem::perms::owner_write |
         std::filesystem::perms::owner_exec |
         std::filesystem::perms::group_read |
         std::filesystem::perms::group_exec;
#endif
}

} // namespace

InstallConfigManager::InstallConfigManager(
    cjj365::IoContextManager &io_context_manager,
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    client_async::HttpClientManager &http_client,
    install_actions::IResourceMaterializer::Factory
        resource_materializer_factory,
    install_actions::ImportCaActionHandler::Factory
        import_ca_action_handler_factory,
    install_actions::ExecActionHandler::Factory exec_handler_factory,
    certctrl::install_actions::CopyActionHandler::Factory copy_handler_factory,
    install_actions::IExecEnvironmentResolver::Factory
        exec_env_resolver_factory,
    install_actions::IDeviceInstallConfigFetcher &config_fetcher,
    install_actions::IAccessTokenLoader &access_token_loader,
    install_actions::IMaterializePasswordManager &password_manager,
    std::shared_ptr<ISessionRefresher> session_refresher)
    : runtime_dir_(config_provider.get().runtime_dir),
      config_provider_(config_provider), output_(output),
      http_client_(http_client),
      resource_materializer_factory_(std::move(resource_materializer_factory)),
      import_ca_action_handler_factory_(
          std::move(import_ca_action_handler_factory)),
      exec_handler_factory_(std::move(exec_handler_factory)),
      exec_env_resolver_factory_(std::move(exec_env_resolver_factory)),
      copy_handler_factory_(std::move(copy_handler_factory)),
      config_fetcher_(config_fetcher), io_context_(io_context_manager.ioc()),
      access_token_loader_(access_token_loader),
      password_manager_(password_manager),
      session_refresher_(std::move(session_refresher)) {
  if (!runtime_dir_.empty()) {
    try {
      std::filesystem::create_directories(state_dir());
#ifndef _WIN32
      std::filesystem::permissions(state_dir(), default_directory_perms(),
                                   std::filesystem::perm_options::replace);
#endif
    } catch (const std::exception &e) {
      BOOST_LOG_SEV(lg, trivial::error)
          << "Failed to prepare runtime state dir: " << e.what();
    }
  }

  if (auto config = load_from_disk()) {
    cached_config_ = std::make_shared<dto::DeviceInstallConfigDto>(
        std::move(config.value()));
    local_version_ = cached_config_->version;
  }
}

InstallConfigManager::~InstallConfigManager() {}

void InstallConfigManager::clear_cache() { invalidate_all_caches(); }

void InstallConfigManager::invalidate_all_caches() {
  cached_config_.reset();
  local_version_.reset();
  password_manager_.clear();

  remove_file_quiet(config_file_path());
  remove_file_quiet(version_file_path());

  if (!runtime_dir_.empty()) {
    auto resources_root = runtime_dir_ / "resources";
    remove_cached_resource_scope(resources_root);
  }
}

void InstallConfigManager::invalidate_resource_cache(const std::string &ob_type,
                                                     std::int64_t ob_id) {
  if (runtime_dir_.empty()) {
    return;
  }
  auto current_dir = resource_current_dir(ob_type, ob_id);
  auto resource_scope = current_dir.parent_path();
  remove_cached_resource_scope(resource_scope);
  password_manager_.forget(ob_type, ob_id);
}

void InstallConfigManager::remove_cached_resource_scope(
    const std::filesystem::path &root) {
  if (root.empty()) {
    return;
  }
  std::error_code ec;
  auto removed = std::filesystem::remove_all(root, ec);
  if (ec) {
    BOOST_LOG_SEV(lg, trivial::error) << "Failed to remove cached resource scope '"
                               << root << "': " << ec.message();
    return;
  }
  if (removed > 0) {
    BOOST_LOG_SEV(lg, trivial::info) << "Removed cached resource scope '" << root
                            << "' (" << removed << " entries).";
  }
}

void InstallConfigManager::remove_file_quiet(
    const std::filesystem::path &file_path) {
  if (file_path.empty()) {
    return;
  }
  std::error_code ec;
  std::filesystem::remove(file_path, ec);
  if (ec && ec != std::errc::no_such_file_or_directory) {
    BOOST_LOG_SEV(lg, trivial::error) << "Failed to remove cached file '" << file_path
                               << "': " << ec.message();
  }
}

std::shared_ptr<dto::DeviceInstallConfigDto>
InstallConfigManager::cached_config_snapshot() {
  if (!cached_config_) {
    if (auto disk_config = load_from_disk()) {
      cached_config_ = std::make_shared<dto::DeviceInstallConfigDto>(
          std::move(disk_config.value()));
      local_version_ = cached_config_->version;
    }
  }
  return cached_config_;
}

monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
InstallConfigManager::ensure_cached_config() {
  using ReturnIO =
      monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>;
  if (cached_config_) {
    return ReturnIO::pure(cached_config_);
  }

  if (auto disk_config = load_from_disk()) {
    cached_config_ = std::make_shared<dto::DeviceInstallConfigDto>(
        std::move(disk_config.value()));
    local_version_ = cached_config_->version;
    return ReturnIO::pure(cached_config_);
  }

  return refresh_from_remote(std::nullopt, std::nullopt);
}

monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
InstallConfigManager::ensure_config_version(
    std::optional<std::int64_t> expected_version,
    const std::optional<std::string> &expected_hash) {
  using ReturnIO =
      monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>;

  // Ensure cache is loaded from disk if available
  if (!cached_config_) {
    if (auto disk_config = load_from_disk()) {
      cached_config_ = std::make_shared<dto::DeviceInstallConfigDto>(
          std::move(disk_config.value()));
      local_version_ = cached_config_->version;
    }
  }

  if (expected_version && local_version_ &&
      *local_version_ >= *expected_version) {
    // Already current (or newer)
    if (cached_config_) {
      return ReturnIO::pure(cached_config_);
    }
    // Local version satisfied but config missing (should not happen).
    return refresh_from_remote(expected_version, expected_hash);
  }

  return refresh_from_remote(expected_version, expected_hash);
}

monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
InstallConfigManager::refresh_from_remote(
    std::optional<std::int64_t> expected_version,
    const std::optional<std::string> &expected_hash) {
  using ReturnIO =
      monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>;
  using namespace monad;

  return refresh_from_remote_with_retry(expected_version, expected_hash,
                                        /*attempted_refresh=*/false);
}

monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
InstallConfigManager::refresh_from_remote_with_retry(
    std::optional<std::int64_t> expected_version,
    const std::optional<std::string> &expected_hash, bool attempted_refresh) {
  using ReturnIO =
      monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>;
  using namespace monad;

  auto token_opt = access_token_loader_.load_token();
  const bool token_missing = !token_opt || token_opt->empty();

  return config_fetcher_
      .fetch_install_config(token_opt, expected_version, expected_hash)
      .then([this](dto::DeviceInstallConfigDto config) -> ReturnIO {
        return persist_config(std::move(config)).then([this]() -> ReturnIO {
          if (!cached_config_) {
            output_.logger().error()
                << "refresh_from_remote completed without cached_config_"
                << std::endl;
          }
          return ReturnIO::pure(cached_config_);
        });
      })
      .catch_then([this, expected_version, expected_hash, attempted_refresh,
                   token_missing](monad::Error err) -> ReturnIO {
        const bool is_auth_error =
            err.response_status == 401 || err.response_status == 403;
        const bool token_unavailable_error =
            err.code == my_errors::GENERAL::INVALID_ARGUMENT &&
            err.what.find("Device access token unavailable") !=
                std::string::npos;

        const bool should_retry_with_refresh =
            !attempted_refresh &&
            (is_auth_error || (token_missing && token_unavailable_error));

        if (!should_retry_with_refresh) {
          if (is_auth_error) {
            err.what += " (device session refresh already attempted)";
          }
          return ReturnIO::fail(std::move(err));
        }

        if (!session_refresher_) {
          return ReturnIO::fail(monad::make_error(
              my_errors::GENERAL::UNEXPECTED_RESULT,
              "Session refresher unavailable; rerun cert-ctrl login."));
        }

        output_.logger().warning() << "install-config fetch authentication "
                                      "failure; attempting session refresh"
                                   << std::endl;

        std::string reason = "install-config fetch auth failure";
        if (err.response_status > 0) {
          reason =
              fmt::format("install-config fetch HTTP {}", err.response_status);
        } else if (token_missing && token_unavailable_error) {
          reason = "install-config fetch missing access token";
        }

        return session_refresher_->refresh(std::move(reason))
            .then([this, expected_version, expected_hash]() -> ReturnIO {
              return refresh_from_remote_with_retry(expected_version,
                                                    expected_hash,
                                                    /*attempted_refresh=*/true);
            });
      });
}

std::optional<dto::DeviceInstallConfigDto>
InstallConfigManager::load_from_disk() {
  std::ifstream ifs(config_file_path());
  if (!ifs.is_open()) {
    return std::nullopt;
  }

  std::string content((std::istreambuf_iterator<char>(ifs)),
                      std::istreambuf_iterator<char>());

  try {
    auto jv = boost::json::parse(content);
    dto::DeviceInstallConfigDto dto_config =
        boost::json::value_to<dto::DeviceInstallConfigDto>(jv);
    local_version_ = dto_config.version;
    return dto_config;
  } catch (const std::exception &e) {
    BOOST_LOG_SEV(lg, trivial::error)
        << "Failed to parse cached install_config.json: " << e.what();
    return std::nullopt;
  }
}

monad::IO<void> InstallConfigManager::persist_config(
    const dto::DeviceInstallConfigDto &config) {
  using ReturnIO = monad::IO<void>;
  try {
    std::filesystem::create_directories(state_dir());

    auto config_json = boost::json::value_from(config);
    std::string serialized = boost::json::serialize(config_json);

    auto tmp_name = config_file_path();
    tmp_name += ".tmp-";
    tmp_name += generate_temp_suffix();

    {
      std::ofstream ofs(tmp_name, std::ios::binary | std::ios::trunc);
      ofs << serialized;
    }

    // Atomic replace
    std::filesystem::rename(tmp_name, config_file_path());

#ifndef _WIN32
    std::filesystem::permissions(config_file_path(),
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
#endif

    // Update version file
    auto version_tmp = version_file_path();
    version_tmp += ".tmp-";
    version_tmp += generate_temp_suffix();
    {
      std::ofstream ofs(version_tmp, std::ios::binary | std::ios::trunc);
      ofs << config.version;
    }
    std::filesystem::rename(version_tmp, version_file_path());
#ifndef _WIN32
    std::filesystem::permissions(version_file_path(),
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
#endif

    cached_config_ = std::make_shared<dto::DeviceInstallConfigDto>(config);
    output_.logger().info()
        << "persist_config cached_config_="
        << static_cast<const void *>(cached_config_.get())
        << " version=" << cached_config_->version << std::endl;
    local_version_ = config.version;

    return ReturnIO::pure();
  } catch (const std::exception &e) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::FILE_READ_WRITE, e.what()));
  }
}

std::filesystem::path InstallConfigManager::state_dir() const {
  return runtime_dir_ / "state";
}

std::filesystem::path InstallConfigManager::config_file_path() const {
  return state_dir() / "install_config.json";
}

std::filesystem::path InstallConfigManager::version_file_path() const {
  return state_dir() / "install_version.txt";
}

std::filesystem::path
InstallConfigManager::resource_current_dir(const std::string &ob_type,
                                           std::int64_t ob_id) const {
  std::filesystem::path resource_root = runtime_dir_ / "resources";
  if (ob_type == "cert") {
    resource_root /= "certs";
  } else if (ob_type == "ca") {
    resource_root /= "cas";
  } else {
    resource_root /= "unknown";
  }
  resource_root /= std::to_string(ob_id);
  resource_root /= "current";
  return resource_root;
}

monad::IO<void> InstallConfigManager::apply_copy_actions(
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id) {

  auto copy_handler = copy_handler_factory_();
  if (!copy_handler) {
    return monad::IO<void>::fail(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                          "CopyActionHandler factory returned null"));
  }
  // First perform copy actions
  return copy_handler->apply(config, target_ob_type, target_ob_id)
      .then([this, copy_handler, &config, target_ob_type, target_ob_id]() {
        (void)copy_handler;
        BOOST_LOG_SEV(lg, trivial::trace)
            << "apply_copy_actions exec stage start target_ob_type="
            << (target_ob_type ? *target_ob_type : std::string("<none>"))
            << " target_ob_id="
            << (target_ob_id ? std::to_string(*target_ob_id) : "<none>");
        // After copy actions, always run exec items (cmd/cmd_argv) that may be
        // present regardless of item.type. Limit exec targets to the same
        // target_ob_type/target_ob_id when specified.
        std::optional<std::vector<std::string>> allowed_types = std::nullopt;
        if (target_ob_type) {
          allowed_types = std::vector<std::string>{*target_ob_type};
        }

        auto exec_handler = exec_handler_factory_();
        return exec_handler->apply(config, allowed_types);
      })
      .catch_then([this, copy_handler](monad::Error err) {
        (void)copy_handler;
        BOOST_LOG_SEV(lg, trivial::error)
            << "apply_copy_actions encountered error code=" << err.code
            << " status=" << err.response_status << " what=" << err.what
            << " params=" << boost::json::serialize(err.params);
        return monad::IO<void>::fail(std::move(err));
      });
}

monad::IO<void> InstallConfigManager::apply_import_ca_actions(
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id) {
  if (!import_ca_action_handler_factory_) {
    return monad::IO<void>::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "ImportCaActionHandler factory not configured"));
  }

  auto import_handler = import_ca_action_handler_factory_();
  if (!import_handler) {
    return monad::IO<void>::fail(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                          "ImportCaActionHandler factory returned null"));
  }

  BOOST_LOG_SEV(lg, trivial::trace)
      << "apply_import_ca_actions start target_ob_type="
      << (target_ob_type ? *target_ob_type : std::string("<none>"))
      << " target_ob_id="
      << (target_ob_id ? std::to_string(*target_ob_id) : "<none>");

  return import_handler->apply(config, target_ob_type, target_ob_id)
      .then([this, import_handler, &config, target_ob_type, target_ob_id]() {
        (void)import_handler;
        std::optional<std::vector<std::string>> allowed_types = std::nullopt;
        if (target_ob_type) {
          allowed_types = std::vector<std::string>{*target_ob_type};
        }
        auto exec_handler = exec_handler_factory_();
        return exec_handler->apply(config, allowed_types);
      })
      .catch_then([this, import_handler](monad::Error err) {
        (void)import_handler;
        BOOST_LOG_SEV(lg, trivial::error)
            << "apply_import_ca_actions encountered error code=" << err.code
            << " status=" << err.response_status << " what=" << err.what
            << " params=" << boost::json::serialize(err.params);
        return monad::IO<void>::fail(std::move(err));
      });
}

monad::IO<void> InstallConfigManager::apply_copy_actions_for_signal(
    const ::data::DeviceUpdateSignal &signal) {
  using ReturnIO = monad::IO<void>;

  if (signal.type == "install.updated") {
    using ReturnIO = monad::IO<void>;
    if (!config_provider_.get().auto_apply_config) {
      BOOST_LOG_SEV(lg, trivial::info)
          << "auto_apply_config disabled; install.updated ignored. Run 'cert-ctrl"
          << " install-config pull/apply' to stage changes manually.";
      return ReturnIO::pure();
    }

    auto typed = ::data::get_install_updated(signal);
    std::optional<std::int64_t> expected_version;
    std::optional<std::string> expected_hash;
    if (typed) {
      expected_version = typed->version;
      expected_hash = typed->installs_hash_b64;
    }

    return ensure_config_version(expected_version, expected_hash)
        .then([this](auto config_ptr) {
          return apply_copy_actions(*config_ptr, std::nullopt, std::nullopt);
        });
  }

  if (signal.type == "cert.updated") {
    if (auto typed = ::data::get_cert_updated(signal)) {
      const auto cert_id = typed->cert_id;
      invalidate_resource_cache("cert", cert_id);
      return ensure_cached_config().then([this, cert_id](auto config_ptr) {
        auto scan = scan_cert_actionability(*config_ptr, cert_id);
        if (!scan.actionable()) {
          if (!scan.has_matching_items) {
            BOOST_LOG_SEV(lg, trivial::info)
                << "cert.updated for cert " << cert_id
                << " ignored: no install items reference this cert";
          } else {
            BOOST_LOG_SEV(lg, trivial::info)
                << "cert.updated for cert " << cert_id
                << " ignored: install items lack destinations or commands";
          }
          return ReturnIO::pure();
        }

        BOOST_LOG_SEV(lg, trivial::info)
            << "Applying install config items for cert " << cert_id
            << " due to cert.updated signal";
        return apply_copy_actions(*config_ptr, std::string("cert"), cert_id);
      });
    }
  }

  if (signal.type == "cert.unassigned") {
    if (auto typed = ::data::get_cert_unassigned(signal)) {
      invalidate_resource_cache("cert", typed->cert_id);

      BOOST_LOG_SEV(lg, trivial::info)
          << "cert.unassigned received; cache purged for cert "
          << typed->cert_id;
    } else {
      BOOST_LOG_SEV(lg, trivial::warning)
          << "cert.unassigned signal missing cert_id";
    }
    return ReturnIO::pure();
  }

  return ReturnIO::pure();
}

monad::IO<void> InstallConfigManager::maybe_run_after_update_script_for_signal(
    const ::data::DeviceUpdateSignal &signal) {
  using ReturnIO = monad::IO<void>;

  try {
    const auto &cfg = config_provider_.get();

    // Allowlist gating.
    if (cfg.events_trigger_script.empty()) {
      return ReturnIO::pure();
    }
    const bool allowlisted =
        std::find(cfg.events_trigger_script.begin(),
                  cfg.events_trigger_script.end(),
                  signal.type) != cfg.events_trigger_script.end();
    if (!allowlisted) {
      return ReturnIO::pure();
    }

    // auto_apply_config gating, bypassed for cert/CA material events.
    if (!cfg.auto_apply_config && !is_bypass_auto_apply_event(signal.type)) {
      BOOST_LOG_SEV(lg, trivial::debug)
          << "auto_apply_config disabled; after_update_script skipped for type="
          << signal.type;
      return ReturnIO::pure();
    }

    auto config_ptr = cached_config_snapshot();
    if (!config_ptr) {
      BOOST_LOG_SEV(lg, trivial::debug)
          << "after_update_script skipped: install config not cached";
      return ReturnIO::pure();
    }

    if (!config_ptr->after_update_script ||
        config_ptr->after_update_script->empty()) {
      return ReturnIO::pure();
    }

    auto selected = select_platform_script(*config_ptr->after_update_script);
    if (!selected || selected->second.empty()) {
      BOOST_LOG_SEV(lg, trivial::debug)
          << "after_update_script bundle has no matching platform block";
      return ReturnIO::pure();
    }

    const auto &variant_name = selected->first;
    const auto &script_content = selected->second;

    const auto script_path =
#ifdef _WIN32
        (variant_name == "windows.cmd")
            ? (state_dir() / "after_update_script.cmd")
            : (state_dir() / "after_update_script.ps1");
#else
        (state_dir() / "after_update_script.sh");
#endif

    if (auto err = persist_after_update_script_atomic(state_dir(), variant_name,
                                                      script_content)) {
      BOOST_LOG_SEV(lg, trivial::warning)
          << "after_update_script persist failed: " << *err;
      return ReturnIO::pure();
    }

    if (auto err = run_script_file_best_effort(script_path, variant_name,
                                               signal.type)) {
      BOOST_LOG_SEV(lg, trivial::warning)
          << "after_update_script execution failed for type=" << signal.type
          << " variant=" << variant_name << " error=" << *err;
      return ReturnIO::pure();
    }

    BOOST_LOG_SEV(lg, trivial::info)
        << "after_update_script executed for type=" << signal.type
        << " variant=" << variant_name;
    return ReturnIO::pure();
  } catch (const std::exception &ex) {
    BOOST_LOG_SEV(lg, trivial::warning)
        << "after_update_script unexpected error: " << ex.what();
    return ReturnIO::pure();
  }
}

monad::IO<void>
InstallConfigManager::handle_ca_assignment(std::int64_t ca_id,
                                           std::optional<std::string> ca_name) {
  using ReturnIO = monad::IO<void>;

  if (ca_id <= 0) {
    return ReturnIO::pure();
  }

  if (!import_ca_action_handler_factory_) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "ImportCaActionHandler factory not configured"));
  }

  auto import_handler = import_ca_action_handler_factory_();
  if (!import_handler) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                          "ImportCaActionHandler factory returned null"));
  }

  invalidate_resource_cache("ca", ca_id);

  dto::InstallItem ca_item;
  ca_item.id = fmt::format("ca-{}-auto", ca_id);
  ca_item.type = "import_ca";
  ca_item.enabled = true;
  ca_item.ob_type = std::string("ca");
  ca_item.ob_id = ca_id;
  if (ca_name && !ca_name->empty()) {
    ca_item.ob_name = *ca_name;
  }
  ca_item.tags = {"ca-install", "auto"};
  ca_item.from = std::vector<std::string>{"ca.pem"};

  dto::DeviceInstallConfigDto config;
  config.installs.emplace_back(std::move(ca_item));

  output_.logger().info() << "Applying ca.assigned for CA " << ca_id
                          << std::endl;

  return import_handler->apply(config, std::string("ca"), ca_id);
}

monad::IO<void> InstallConfigManager::handle_ca_unassignment(
    std::int64_t ca_id, std::optional<std::string> ca_name) {
  using ReturnIO = monad::IO<void>;
  if (ca_id <= 0) {
    return ReturnIO::pure();
  }

  if (!import_ca_action_handler_factory_) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "ImportCaActionHandler factory not configured"));
  }

  auto import_handler = import_ca_action_handler_factory_();
  if (!import_handler) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                          "ImportCaActionHandler factory returned null"));
  }

  invalidate_resource_cache("ca", ca_id);

  output_.logger().info() << "Applying ca.unassigned for CA " << ca_id
                          << std::endl;

  return import_handler->remove_ca(ca_id, ca_name);
}

std::optional<std::unordered_map<std::string, std::string>>
InstallConfigManager::resolve_exec_env_for_item(const dto::InstallItem &item) {
  if (!item.ob_type || !item.ob_id) {
    return std::nullopt;
  }
  if (*item.ob_type != "cert") {
    return std::nullopt;
  }

  auto password = password_manager_.lookup(*item.ob_type, *item.ob_id);
  if (!password || password->empty()) {
    return std::nullopt;
  }

  std::unordered_map<std::string, std::string> env;
  env.emplace(kPfxPasswordEnvVar, *password);
  return env;
}

} // namespace certctrl
