#include "handlers/certificates_handler.hpp"

#include <algorithm>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <unordered_map>

#include <boost/json.hpp>
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

  std::tm tm {};
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

std::vector<std::string> extract_sans(const X509 *cert) {
  std::vector<std::string> sans;
  STACK_OF(GENERAL_NAME) *names = static_cast<STACK_OF(GENERAL_NAME) *>(
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  if (!names) {
    return sans;
  }
  std::unique_ptr<STACK_OF(GENERAL_NAME), decltype(&GENERAL_NAMES_free)>
      guard(names, &GENERAL_NAMES_free);
  int name_count = sk_GENERAL_NAME_num(names);
  for (int i = 0; i < name_count; ++i) {
    const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
    if (!name) {
      continue;
    }
    if (name->type == GEN_DNS) {
      const unsigned char *data = ASN1_STRING_get0_data(name->d.dNSName);
      if (data && ASN1_STRING_length(name->d.dNSName) > 0) {
        sans.emplace_back(reinterpret_cast<const char *>(data));
      }
    } else if (name->type == GEN_URI) {
      const unsigned char *data = ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
      if (data && ASN1_STRING_length(name->d.uniformResourceIdentifier) > 0) {
        sans.emplace_back(reinterpret_cast<const char *>(data));
      }
    } else if (name->type == GEN_IPADD) {
      const unsigned char *data = ASN1_STRING_get0_data(name->d.iPAddress);
      int length = ASN1_STRING_length(name->d.iPAddress);
      if (data && length > 0) {
        std::ostringstream oss;
        if (length == 4) {
          oss << static_cast<int>(data[0]) << "." << static_cast<int>(data[1])
              << "." << static_cast<int>(data[2]) << "."
              << static_cast<int>(data[3]);
        } else if (length == 16) {
          for (int idx = 0; idx < length; idx += 2) {
            if (idx) {
              oss << ':';
            }
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(data[idx])
                << static_cast<int>(data[idx + 1]);
          }
        }
        if (!oss.str().empty()) {
          sans.push_back(oss.str());
        }
      }
    }
  }
  return sans;
}

struct ParsedCertificate {
  std::string subject;
  std::string issuer;
  std::vector<std::string> sans;
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
  info.sans = extract_sans(cert.get());
  info.not_before = asn1_time_to_time_point(X509_get0_notBefore(cert.get()));
  info.not_after = asn1_time_to_time_point(X509_get0_notAfter(cert.get()));
  info.fingerprint = fingerprint_sha256(cert.get());
  info.serial_hex = serial_to_hex(X509_get0_serialNumber(cert.get()));

  return info;
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

CertificatesHandler::CertificatesHandler(
    cjj365::ConfigSources &config_sources, CliCtx &cli_ctx,
    customio::ConsoleOutput &output,
    std::unique_ptr<InstallConfigManager> install_config_manager)
    : config_sources_(config_sources), cli_ctx_(cli_ctx), output_(output),
      install_config_manager_(std::move(install_config_manager)) {}

monad::IO<void> CertificatesHandler::start() {
  if (cli_ctx_.positionals.size() < 2) {
    output_.logger().info()
        << "Usage: cert-ctrl certificates <list|show> [options]" << std::endl;
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
      << "Unknown certificates action '" << action
      << "'. Expected 'list' or 'show'." << std::endl;
  return monad::IO<void>::pure();
}

CertificatesHandler::ListOptions
CertificatesHandler::parse_list_options(const std::string &action) {
  ListOptions opts;
  namespace po = boost::program_options;

  po::options_description desc("certificates list options");
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
        << "Failed to parse certificates list options: " << ex.what()
        << std::endl;
  }

  return opts;
}

CertificatesHandler::ShowOptions
CertificatesHandler::parse_show_options(const std::string &action) {
  ShowOptions opts;
  namespace po = boost::program_options;

  po::options_description desc("certificates show options");
  desc.add_options()("json", po::bool_switch(&opts.json),
                     "Emit JSON output")
      ("refresh", po::bool_switch(&opts.refresh),
       "Refresh certificate materials before rendering")
      ("id", po::value<std::int64_t>(), "Certificate identifier");

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
        << "Failed to parse certificates show options: " << ex.what()
        << std::endl;
  }

  if (!opts.id) {
    for (std::size_t idx = 2; idx < cli_ctx_.positionals.size(); ++idx) {
      const auto &token = cli_ctx_.positionals[idx];
      try {
        opts.id = std::stoll(token);
        break;
      } catch (const std::exception &) {
        // continue trying other tokens
      }
    }
  }

  return opts;
}

monad::IO<void> CertificatesHandler::handle_list() {
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

        auto summaries = self->gather_certificates(*config_ptr);
        if (summaries.empty()) {
          self->output_.logger().info()
              << "No certificate resources found in staged install-config."
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
            std::string status = summary.artifacts.has_material
                                     ? "ok"
                                     : "missing";
            if (summary.artifacts.has_material &&
                summary.artifacts.not_after &&
                *summary.artifacts.not_after < now) {
              status = "expired";
            }
            obj["status"] = status;
            obj["not_after"] = format_time(summary.artifacts.not_after);
            obj["primary_san"] = summary.artifacts.sans.empty()
                                      ? ""
                                      : summary.artifacts.sans.front();
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
                                  "Primary SAN");
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
          const std::string primary_san = summary.artifacts.sans.empty()
                                              ? "-"
                                              : summary.artifacts.sans.front();

          self->output_.printer().stream()
              << fmt::format("{:>6}  {:<24}  {:<10}  {:<20}  {}", summary.id,
                             name, status, not_after, primary_san)
              << std::endl;
        }

        return ReturnIO::pure();
      });
}

monad::IO<void> CertificatesHandler::handle_show() {
  using ReturnIO = monad::IO<void>;

  auto options = parse_show_options("show");
  if (!options.id) {
    output_.logger().error()
        << "Provide a certificate identifier via '--id <value>' or"
        << " positional argument." << std::endl;
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
              << "No install-config cached yet; pull one before running"
              << " 'cert-ctrl certificates show'." << std::endl;
          return ReturnIO::pure();
        }

        auto perform_render = [self, config_ptr, options]() -> ReturnIO {
          return self->render_show(*config_ptr, *options.id, options);
        };

        if (options.refresh) {
          self->install_config_manager_->invalidate_resource_cache(
              "cert", *options.id);
          std::optional<std::string> target_type{"cert"};
          return self->install_config_manager_
              ->apply_copy_actions(*config_ptr, target_type, options.id)
              .then([perform_render]() { return perform_render(); });
        }

        return perform_render();
      });
}

monad::IO<void> CertificatesHandler::render_show(
    const dto::DeviceInstallConfigDto &config, std::int64_t cert_id,
    const ShowOptions &options) {
  using ReturnIO = monad::IO<void>;

  const dto::InstallItem *match = nullptr;
  for (const auto &item : config.installs) {
    if (item.ob_type && *item.ob_type == "cert" && item.ob_id &&
        *item.ob_id == cert_id) {
      match = &item;
      break;
    }
  }

  std::string name = match && match->ob_name ? *match->ob_name : std::string{};
  std::vector<std::string> targets =
      match && match->to ? *match->to : std::vector<std::string>{};

  auto artifacts = load_certificate_artifacts(cert_id);

  if (options.json) {
    boost::json::object obj;
    obj["id"] = cert_id;
    if (!name.empty()) {
      obj["name"] = name;
    }
    obj["subject"] = artifacts.subject;
    obj["issuer"] = artifacts.issuer;
    boost::json::array sans_json;
    for (const auto &san : artifacts.sans) {
      sans_json.emplace_back(san);
    }
    obj["sans"] = std::move(sans_json);
    obj["not_before"] = format_time(artifacts.not_before);
    obj["not_after"] = format_time(artifacts.not_after);
    obj["fingerprint_sha256"] = artifacts.fingerprint_sha256;
    obj["serial_hex"] = artifacts.serial_hex;
    obj["certificate_path"] = artifacts.certificate_path.string();
    obj["bundle_path"] = artifacts.bundle_path.string();
    obj["private_key_path"] = artifacts.private_key_path.string();
    obj["detail_path"] = artifacts.detail_path.string();
    boost::json::array targets_json;
    for (const auto &target : targets) {
      targets_json.emplace_back(target);
    }
    obj["targets"] = std::move(targets_json);
    obj["has_material"] = artifacts.has_material;
    if (!artifacts.error.empty()) {
      obj["error"] = artifacts.error;
    }
    output_.printer().stream() << boost::json::serialize(obj) << std::endl;
    return ReturnIO::pure();
  }

  output_.printer().yellow()
      << fmt::format("Certificate {}{}", cert_id,
                     name.empty() ? std::string{}
                                  : fmt::format(" ({})", name))
      << std::endl;

  if (!artifacts.has_material) {
    output_.printer().red()
        << "  Local materials missing. Run 'cert-ctrl install-config pull --cert-id "
        << cert_id << "' to stage them." << std::endl;
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

  output_.printer().stream()
      << "  SANs (" << artifacts.sans.size() << "): "
      << (artifacts.sans.empty() ? std::string{"-"}
                                 : join_sans(artifacts.sans))
      << std::endl;

  if (!targets.empty()) {
    output_.printer().stream()
        << "  Install targets: " << join_sans(targets) << std::endl;
  }

  output_.printer().stream() << "  Paths:" << std::endl
                             << "    certificate.pem: "
                             << artifacts.certificate_path.string()
                             << std::endl
                             << "    bundle.pfx:      "
                             << artifacts.bundle_path.string() << std::endl
                             << "    private.key:     "
                             << artifacts.private_key_path.string()
                             << std::endl
                             << "    detail JSON:     "
                             << artifacts.detail_path.string()
                             << std::endl;

  return ReturnIO::pure();
}

std::vector<CertificatesHandler::CertificateSummary>
CertificatesHandler::gather_certificates(
    const dto::DeviceInstallConfigDto &config) const {
  std::unordered_map<std::int64_t, CertificateSummary> summaries_by_id;
  for (const auto &item : config.installs) {
    if (!item.ob_type || *item.ob_type != "cert" || !item.ob_id) {
      continue;
    }
    auto &entry = summaries_by_id[*item.ob_id];
    entry.id = *item.ob_id;
    if (entry.name.empty() && item.ob_name) {
      entry.name = *item.ob_name;
    }
  }

  std::vector<CertificateSummary> summaries;
  summaries.reserve(summaries_by_id.size());
  for (auto &kv : summaries_by_id) {
    kv.second.artifacts = load_certificate_artifacts(kv.first);
    summaries.push_back(std::move(kv.second));
  }
  std::sort(summaries.begin(), summaries.end(),
            [](const CertificateSummary &lhs, const CertificateSummary &rhs) {
              return lhs.id < rhs.id;
            });
  return summaries;
}

CertificatesHandler::CertificateArtifacts
CertificatesHandler::load_certificate_artifacts(std::int64_t cert_id) const {
  CertificateArtifacts info;

  const auto &runtime_dir = install_config_manager_->runtime_dir();
  if (runtime_dir.empty()) {
    info.error = "Runtime directory not configured";
    return info;
  }

  std::filesystem::path root = runtime_dir / "resources" / "certs" /
                               std::to_string(cert_id);
  std::filesystem::path current = root / "current";

  info.certificate_path = current / "certificate.pem";
  info.bundle_path = current / "bundle.pfx";
  info.private_key_path = current / "private.key";
  info.detail_path = root / "certificate_detail.json";

  auto pem = read_text_file(info.certificate_path);
  if (!pem) {
    info.error = "certificate.pem not found";
    return info;
  }

  info.has_material = true;
  std::string parse_error;
  if (auto parsed = parse_certificate_pem(*pem, parse_error)) {
    info.subject = std::move(parsed->subject);
    info.issuer = std::move(parsed->issuer);
    info.sans = std::move(parsed->sans);
    info.not_before = parsed->not_before;
    info.not_after = parsed->not_after;
    info.fingerprint_sha256 = std::move(parsed->fingerprint);
    info.serial_hex = std::move(parsed->serial_hex);
  } else {
    info.error = std::move(parse_error);
  }

  return info;
}

std::string CertificatesHandler::format_time(
    const std::optional<std::chrono::system_clock::time_point> &tp) {
  if (!tp) {
    return "-";
  }

  std::time_t t = std::chrono::system_clock::to_time_t(*tp);
  std::tm tm {};
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

std::string CertificatesHandler::join_sans(
    const std::vector<std::string> &sans) {
  if (sans.empty()) {
    return "-";
  }
  std::ostringstream oss;
  for (std::size_t i = 0; i < sans.size(); ++i) {
    if (i) {
      oss << ", ";
    }
    oss << sans[i];
  }
  return oss.str();
}

} // namespace certctrl