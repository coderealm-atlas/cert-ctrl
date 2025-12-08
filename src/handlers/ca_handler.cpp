#include "handlers/ca_handler.hpp"

#include <algorithm>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <unordered_map>

#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <fmt/format.h>

#include "openssl/crypt_util.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace certctrl {
namespace {
namespace fs = std::filesystem;

#ifdef _WIN32
inline std::time_t timegm_portable(std::tm *tm) { return _mkgmtime(tm); }
#else
inline std::time_t timegm_portable(std::tm *tm) { return timegm(tm); }
#endif

std::optional<std::chrono::system_clock::time_point>
asn1_time_to_time_point(const ASN1_TIME *asn1_time) {
  if (!asn1_time) {
    return std::nullopt;
  }

  std::tm tm{};
  if (ASN1_TIME_to_tm(asn1_time, &tm) != 1) {
    return std::nullopt;
  }

  std::time_t epoch = timegm_portable(&tm);
  if (epoch == static_cast<std::time_t>(-1)) {
    return std::nullopt;
  }

  return std::chrono::system_clock::from_time_t(epoch);
}

std::string x509_name_to_string(X509_NAME *name) {
  if (!name) {
    return {};
  }
  BIO *bio_raw = BIO_new(BIO_s_mem());
  if (!bio_raw) {
    return {};
  }
  cjj365::cryptutil::BIO_ptr bio(bio_raw, &BIO_free);
  if (X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253) != 1) {
    return {};
  }
  BUF_MEM *mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &mem);
  if (!mem || !mem->data) {
    return {};
  }
  return std::string(mem->data, mem->length);
}

std::string serial_to_hex(const ASN1_INTEGER *serial) {
  if (!serial) {
    return {};
  }
  BIGNUM *bn = ASN1_INTEGER_to_BN(serial, nullptr);
  if (!bn) {
    return {};
  }
  cjj365::cryptutil::BIGNUM_ptr guard(bn, &BN_free);
  char *hex = BN_bn2hex(bn);
  if (!hex) {
    return {};
  }
  std::string hex_str(hex);
  OPENSSL_free(hex);
  return hex_str;
}

std::string fingerprint_sha256(const X509 *cert) {
  unsigned int len = 0;
  unsigned char md[EVP_MAX_MD_SIZE];
  if (X509_digest(cert, EVP_sha256(), md, &len) != 1) {
    return {};
  }
  std::ostringstream oss;
  for (unsigned int i = 0; i < len; ++i) {
    if (i) {
      oss << ':';
    }
    oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(md[i]);
  }
  return oss.str();
}

std::optional<std::string> read_text_file(const fs::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    return std::nullopt;
  }
  std::ostringstream oss;
  oss << ifs.rdbuf();
  return oss.str();
}

struct ParsedCertificate {
  std::string subject;
  std::string issuer;
  std::optional<std::chrono::system_clock::time_point> not_before;
  std::optional<std::chrono::system_clock::time_point> not_after;
  std::string fingerprint;
  std::string serial_hex;
};

std::optional<ParsedCertificate> parse_certificate_pem(const std::string &pem,
                                                       std::string &error) {
  BIO *raw = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!raw) {
    error = "Failed to allocate BIO";
    return std::nullopt;
  }
  cjj365::cryptutil::BIO_ptr bio(raw, &BIO_free);
  X509 *x509_raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (!x509_raw) {
    error = "Failed to parse certificate PEM";
    return std::nullopt;
  }
  cjj365::cryptutil::X509_ptr cert(x509_raw, &X509_free);

  ParsedCertificate info;
  info.subject = x509_name_to_string(X509_get_subject_name(cert.get()));
  info.issuer = x509_name_to_string(X509_get_issuer_name(cert.get()));
  info.not_before = asn1_time_to_time_point(X509_get0_notBefore(cert.get()));
  info.not_after = asn1_time_to_time_point(X509_get0_notAfter(cert.get()));
  info.fingerprint = fingerprint_sha256(cert.get());
  info.serial_hex = serial_to_hex(X509_get0_serialNumber(cert.get()));

  return info;
}

std::vector<std::string> filter_tokens(
    const std::vector<std::string> &source,
    const std::vector<std::string> &excluded) {
  if (excluded.empty()) {
    return source;
  }

  std::vector<std::string> result;
  result.reserve(source.size());
  std::vector<std::string> remaining = excluded;

  for (const auto &token : source) {
    auto it = std::find(remaining.begin(), remaining.end(), token);
    if (it != remaining.end()) {
      remaining.erase(it);
      continue;
    }
    result.push_back(token);
  }
  return result;
}

} // namespace

CaHandler::CaHandler(cjj365::ConfigSources &config_sources, CliCtx &cli_ctx,
                     customio::ConsoleOutput &output,
                     std::unique_ptr<InstallConfigManager> install_config_manager)
    : config_sources_(config_sources), cli_ctx_(cli_ctx), output_(output),
      install_config_manager_(std::move(install_config_manager)) {}

monad::IO<void> CaHandler::start() {
  if (cli_ctx_.positionals.size() < 2) {
    output_.logger().info()
        << "Usage: cert-ctrl cas <list|show> [options]" << std::endl;
    return monad::IO<void>::pure();
  }

  const std::string action = cli_ctx_.positionals[1];
  if (action == "list") {
    return handle_list();
  }
  if (action == "show") {
    return handle_show();
  }

  output_.logger().error()
      << "Unknown cas action '" << action << "'. Expected 'list' or 'show'."
      << std::endl;
  return monad::IO<void>::pure();
}

CaHandler::ListOptions
CaHandler::parse_list_options(const std::string &action) {
  ListOptions opts;
  namespace po = boost::program_options;

  po::options_description desc("cas list options");
  desc.add_options()("json", po::bool_switch(&opts.json),
                     "Emit JSON output");

  try {
    auto args = filter_tokens(cli_ctx_.unrecognized,
                              std::vector<std::string>{command(), action});
    po::variables_map vm;
    po::store(po::command_line_parser(args)
                  .options(desc)
                  .allow_unregistered()
                  .run(),
              vm);
    po::notify(vm);
  } catch (const std::exception &ex) {
    output_.logger().warning()
        << "Failed to parse cas list options: " << ex.what() << std::endl;
  }

  return opts;
}

CaHandler::ShowOptions
CaHandler::parse_show_options(const std::string &action) {
  ShowOptions opts;
  namespace po = boost::program_options;

  po::options_description desc("cas show options");
  desc.add_options()("json", po::bool_switch(&opts.json),
                     "Emit JSON output")
      ("refresh", po::bool_switch(&opts.refresh),
       "Refresh CA materials before rendering")
      ("id", po::value<std::int64_t>(), "CA identifier");

  try {
    auto args = filter_tokens(cli_ctx_.unrecognized,
                              std::vector<std::string>{command(), action});
    po::variables_map vm;
    po::store(po::command_line_parser(args)
                  .options(desc)
                  .allow_unregistered()
                  .run(),
              vm);
    po::notify(vm);
    if (vm.count("id")) {
      opts.id = vm["id"].as<std::int64_t>();
    }
  } catch (const std::exception &ex) {
    output_.logger().warning()
        << "Failed to parse cas show options: " << ex.what() << std::endl;
  }

  if (!opts.id) {
    for (std::size_t idx = 2; idx < cli_ctx_.positionals.size(); ++idx) {
      const auto &token = cli_ctx_.positionals[idx];
      try {
        opts.id = std::stoll(token);
        break;
      } catch (const std::exception &) {
      }
    }
  }

  return opts;
}

monad::IO<void> CaHandler::handle_list() {
  using ReturnIO = monad::IO<void>;

  auto options = parse_list_options("list");
  auto self = shared_from_this();

  return install_config_manager_
      ->ensure_config_version(std::nullopt, std::nullopt)
      .then([self, options](
                std::shared_ptr<const dto::DeviceInstallConfigDto> config_ptr)
                -> ReturnIO {
        if (!config_ptr) {
          self->output_.logger().warning()
              << "No install-config cached yet; run 'cert-ctrl install-config "
                 "pull' first."
              << std::endl;
          return ReturnIO::pure();
        }

        auto summaries = self->gather_cas(*config_ptr);
        if (summaries.empty()) {
          self->output_.logger().info()
              << "No CA resources found in staged install-config."
              << std::endl;
          return ReturnIO::pure();
        }

        if (options.json) {
          boost::json::array arr;
          arr.reserve(summaries.size());
          auto now = std::chrono::system_clock::now();
          for (const auto &summary : summaries) {
            boost::json::object obj;
            obj["id"] = summary.id;
            if (!summary.name.empty()) {
              obj["name"] = summary.name;
            }
            std::string status = summary.artifacts.has_material ? "ok"
                                                                : "missing";
            if (summary.artifacts.has_material &&
                summary.artifacts.not_after &&
                *summary.artifacts.not_after < now) {
              status = "expired";
            }
            obj["status"] = status;
            obj["not_after"] = format_time(summary.artifacts.not_after);
            obj["subject"] = summary.artifacts.subject;
            obj["issuer"] = summary.artifacts.issuer;
            obj["fingerprint_sha256"] = summary.artifacts.fingerprint_sha256;
            if (!summary.artifacts.error.empty()) {
              obj["error"] = summary.artifacts.error;
            }
            arr.emplace_back(std::move(obj));
          }
          self->output_.printer().stream()
              << boost::json::serialize(arr) << std::endl;
          return ReturnIO::pure();
        }

        auto header = fmt::format("{:>6}  {:<24}  {:<10}  {:<20}  {}", "ID",
                                  "Name", "Status", "Not After",
                                  "Subject");
        self->output_.printer().yellow() << header << std::endl;

        auto now = std::chrono::system_clock::now();
        for (const auto &summary : summaries) {
          std::string status = summary.artifacts.has_material ? "ok"
                                                              : "missing";
          if (summary.artifacts.has_material &&
              summary.artifacts.not_after &&
              *summary.artifacts.not_after < now) {
            status = "expired";
          }
          std::string name = summary.name.empty() ? "-" : summary.name;
          if (name.size() > 24) {
            name = name.substr(0, 21) + "...";
          }
          const std::string not_after =
              format_time(summary.artifacts.not_after);
          const std::string subject = summary.artifacts.subject.empty()
                                          ? "-"
                                          : summary.artifacts.subject;

          self->output_.printer().stream()
              << fmt::format("{:>6}  {:<24}  {:<10}  {:<20}  {}", summary.id,
                             name, status, not_after, subject)
              << std::endl;
        }

        return ReturnIO::pure();
      });
}

monad::IO<void> CaHandler::handle_show() {
  using ReturnIO = monad::IO<void>;

  auto options = parse_show_options("show");
  if (!options.id) {
    output_.logger().error()
        << "Provide a CA identifier via '--id <value>' or positional argument."
        << std::endl;
    return ReturnIO::pure();
  }

  auto self = shared_from_this();
  return install_config_manager_
      ->ensure_config_version(std::nullopt, std::nullopt)
      .then([self, options](
                std::shared_ptr<const dto::DeviceInstallConfigDto> config_ptr)
                -> ReturnIO {
        if (!config_ptr) {
          self->output_.logger().warning()
              << "No install-config cached yet; pull one before running "
                 "'cert-ctrl cas show'."
              << std::endl;
          return ReturnIO::pure();
        }

        auto perform_render = [self, config_ptr, options]() -> ReturnIO {
          return self->render_show(*config_ptr, *options.id, options);
        };

        if (options.refresh) {
          self->install_config_manager_->invalidate_resource_cache("ca",
                                                                   *options.id);
          std::optional<std::string> target_type{"ca"};
          return self->install_config_manager_
              ->apply_import_ca_actions(*config_ptr, target_type, options.id)
              .then([perform_render]() { return perform_render(); });
        }

        return perform_render();
      });
}

monad::IO<void> CaHandler::render_show(
    const dto::DeviceInstallConfigDto &config, std::int64_t ca_id,
    const ShowOptions &options) {
  using ReturnIO = monad::IO<void>;

  const dto::InstallItem *match = nullptr;
  for (const auto &item : config.installs) {
    if (item.ob_type && *item.ob_type == "ca" && item.ob_id &&
        *item.ob_id == ca_id) {
      match = &item;
      break;
    }
  }

  std::string name = match && match->ob_name ? *match->ob_name : std::string{};
  std::vector<std::string> targets =
      match && match->to ? *match->to : std::vector<std::string>{};

  auto artifacts = load_ca_artifacts(ca_id);

  if (options.json) {
    boost::json::object obj;
    obj["id"] = ca_id;
    if (!name.empty()) {
      obj["name"] = name;
    }
    obj["subject"] = artifacts.subject;
    obj["issuer"] = artifacts.issuer;
    obj["not_before"] = format_time(artifacts.not_before);
    obj["not_after"] = format_time(artifacts.not_after);
    obj["fingerprint_sha256"] = artifacts.fingerprint_sha256;
    obj["serial_hex"] = artifacts.serial_hex;
    obj["ca_pem_path"] = artifacts.ca_pem_path.string();
    obj["bundle_path"] = artifacts.bundle_path.string();
    obj["has_material"] = artifacts.has_material;
    boost::json::array targets_json;
    for (const auto &target : targets) {
      targets_json.emplace_back(target);
    }
    obj["targets"] = std::move(targets_json);
    if (!artifacts.error.empty()) {
      obj["error"] = artifacts.error;
    }
    output_.printer().stream() << boost::json::serialize(obj) << std::endl;
    return ReturnIO::pure();
  }

  output_.printer().yellow()
      << fmt::format("CA {}{}", ca_id,
                     name.empty() ? std::string{}
                                  : fmt::format(" ({})", name))
      << std::endl;

  if (!artifacts.has_material) {
    output_.printer().red()
        << "  Local materials missing. Run 'cert-ctrl install-config pull --ca-id "
        << ca_id << "' to stage them." << std::endl;
    if (!artifacts.error.empty()) {
      output_.printer().red() << "  Error: " << artifacts.error << std::endl;
    }
    return ReturnIO::pure();
  }

  output_.printer().stream() << "  Subject: " << artifacts.subject
                             << std::endl;
  if (!artifacts.issuer.empty()) {
    output_.printer().stream() << "  Issuer: " << artifacts.issuer
                               << std::endl;
  }
  output_.printer().stream()
      << "  Serial: "
      << (artifacts.serial_hex.empty() ? std::string{"-"}
                                       : artifacts.serial_hex)
      << std::endl;
  output_.printer().stream()
      << "  Not Before: " << format_time(artifacts.not_before) << std::endl;
  output_.printer().stream()
      << "  Not After:  " << format_time(artifacts.not_after) << std::endl;
  output_.printer().stream()
      << "  Fingerprint (SHA-256): "
      << (artifacts.fingerprint_sha256.empty() ? std::string{"-"}
                                               : artifacts.fingerprint_sha256)
      << std::endl;

  if (!targets.empty()) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < targets.size(); ++i) {
      if (i) {
        oss << ", ";
      }
      oss << targets[i];
    }
    output_.printer().stream()
        << "  Install targets: " << (oss.str().empty() ? "-" : oss.str())
        << std::endl;
  }

  output_.printer().stream() << "  Paths:" << std::endl
                             << "    ca.pem:        "
                             << artifacts.ca_pem_path.string() << std::endl
                             << "    bundle_raw:    "
                             << artifacts.bundle_path.string() << std::endl;

  return ReturnIO::pure();
}

std::vector<CaHandler::CaSummary>
CaHandler::gather_cas(const dto::DeviceInstallConfigDto &config) const {
  std::unordered_map<std::int64_t, CaSummary> summaries_by_id;
  for (const auto &item : config.installs) {
    if (!item.ob_type || *item.ob_type != "ca" || !item.ob_id) {
      continue;
    }
    auto &entry = summaries_by_id[*item.ob_id];
    entry.id = *item.ob_id;
    if (entry.name.empty() && item.ob_name) {
      entry.name = *item.ob_name;
    }
  }

  std::vector<CaSummary> summaries;
  summaries.reserve(summaries_by_id.size());
  for (auto &kv : summaries_by_id) {
    kv.second.artifacts = load_ca_artifacts(kv.first);
    summaries.push_back(std::move(kv.second));
  }
  std::sort(summaries.begin(), summaries.end(),
            [](const CaSummary &lhs, const CaSummary &rhs) {
              return lhs.id < rhs.id;
            });
  return summaries;
}

CaHandler::CaArtifacts
CaHandler::load_ca_artifacts(std::int64_t ca_id) const {
  CaArtifacts info;

  const auto &runtime_dir = install_config_manager_->runtime_dir();
  if (runtime_dir.empty()) {
    info.error = "Runtime directory not configured";
    return info;
  }

  fs::path root = runtime_dir / "resources" / "cas" /
                  std::to_string(ca_id);
  fs::path current = root / "current";

  info.ca_pem_path = current / "ca.pem";
  info.bundle_path = root / "bundle_raw.json";

  auto pem = read_text_file(info.ca_pem_path);
  if (!pem) {
    info.error = "ca.pem not found";
    return info;
  }

  info.has_material = true;
  std::string parse_error;
  if (auto parsed = parse_certificate_pem(*pem, parse_error)) {
    info.subject = std::move(parsed->subject);
    info.issuer = std::move(parsed->issuer);
    info.not_before = parsed->not_before;
    info.not_after = parsed->not_after;
    info.fingerprint_sha256 = std::move(parsed->fingerprint);
    info.serial_hex = std::move(parsed->serial_hex);
  } else {
    info.error = std::move(parse_error);
  }

  return info;
}

std::string CaHandler::format_time(
    const std::optional<std::chrono::system_clock::time_point> &tp) {
  if (!tp) {
    return "-";
  }

  std::time_t t = std::chrono::system_clock::to_time_t(*tp);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%SZ", &tm) == 0) {
    return "-";
  }
  return std::string(buf);
}

} // namespace certctrl
