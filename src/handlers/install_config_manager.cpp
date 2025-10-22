#include "handlers/install_config_manager.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/import_ca_action.hpp"

#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <fmt/format.h>
#include <future>
#include <iostream>
#include <random>
#include <thread>
#include <unordered_map>
#include <array>
#include <sstream>

#include <sodium.h>

#include "http_client_monad.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "base64.h"
#include "openssl/openssl_raii.hpp"
#include "util/secret_util.hpp"
#include "util/user_key_crypto.hpp"
#include "util/my_logging.hpp"

namespace certctrl {

using monad::Error;

namespace {

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
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return lower;
}

std::optional<std::string> read_file_as_string(const std::filesystem::path &path) {
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
    if (!entry.is_string()) continue;
    if (!first) {
      oss << '\n';
    }
    oss << entry.as_string();
    first = false;
  }
  auto result = oss.str();
  if (result.empty()) return std::nullopt;
  return result;
}

std::optional<std::vector<unsigned char>> decode_base64_to_bytes(
    const boost::json::value &value) {
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

struct DeviceKeyPair {
  std::array<unsigned char, crypto_box_PUBLICKEYBYTES> pk{};
  std::array<unsigned char, crypto_box_SECRETKEYBYTES> sk{};
};

std::optional<DeviceKeyPair> load_device_keypair_from_paths(
    const std::vector<std::filesystem::path> &paths, std::string &error_out) {
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
      text.erase(std::remove_if(text.begin(), text.end(), [](char ch) {
                    return ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t';
                  }),
                 text.end());
      if (text.empty()) return std::nullopt;
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

std::optional<std::string> convert_der_private_key_to_pem(
    const std::vector<unsigned char> &der, std::string &error_out) {
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

std::optional<std::string> decrypt_private_key_pem(
    const boost::json::object &bundle_data,
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
          error_out = std::string("Failed to fingerprint device key: ") +
                      ex.what();
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

std::optional<std::vector<unsigned char>> extract_bundle_pfx_bytes(
    const boost::json::object &bundle_data) {
  if (auto *pfx_val = bundle_data.if_contains("bundle_pfx_b64")) {
    return decode_base64_to_bytes(*pfx_val);
  }
  if (auto *pkcs_val = bundle_data.if_contains("pkcs12_b64")) {
    return decode_base64_to_bytes(*pkcs_val);
  }
  return std::nullopt;
}

std::optional<boost::json::object> load_bundle_object(
    const std::filesystem::path &resource_root) {
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
    const std::filesystem::path &runtime_dir,
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    client_async::HttpClientManager *http_client,
    FetchOverrideFn fetch_override,
    ResourceFetchOverrideFn resource_fetch_override)
    : runtime_dir_(runtime_dir), config_provider_(config_provider),
      output_(output), http_client_(http_client),
      fetch_override_(std::move(fetch_override)),
      resource_fetch_override_(std::move(resource_fetch_override)) {
  if (!runtime_dir_.empty()) {
    try {
      std::filesystem::create_directories(state_dir());
#ifndef _WIN32
      std::filesystem::permissions(state_dir(), default_directory_perms(),
                                   std::filesystem::perm_options::replace);
#endif
    } catch (const std::exception &e) {
      output_.logger().warning()
          << "Failed to prepare runtime state dir: " << e.what()
          << std::endl;
    }
  }

  if (auto config = load_from_disk()) {
    cached_config_ = std::make_shared<dto::DeviceInstallConfigDto>(
        std::move(config.value()));
    local_version_ = cached_config_->version;
  }
}

void InstallConfigManager::clear_cache() {
  cached_config_.reset();
  local_version_.reset();
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
  using ReturnIO = monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>;
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

  auto perform_fetch = [this, expected_version,
                        expected_hash]() -> IO<dto::DeviceInstallConfigDto> {
    if (fetch_override_) {
      return fetch_override_(expected_version, expected_hash);
    }

    if (!http_client_) {
      return IO<dto::DeviceInstallConfigDto>::fail(
          make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                     "InstallConfigManager: no HTTP client available"));
    }

    auto token_opt = load_access_token();
    if (!token_opt || token_opt->empty()) {
      return IO<dto::DeviceInstallConfigDto>::fail(
          make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                     "Device access token unavailable"));
    }

    const auto &cfg = config_provider_.get();
    std::string url = fmt::format("{}/apiv1/devices/self/install-config",
                                  cfg.base_url);

    return http_io<monad::GetStringTag>(url)
        .map([token = *token_opt](auto ex) {
          namespace http = boost::beast::http;
          ex->request.set(http::field::authorization,
                          std::string("Bearer ") + token);
          return ex;
        })
        .then(http_request_io<monad::GetStringTag>(*http_client_))
        .then([](auto ex) -> IO<dto::DeviceInstallConfigDto> {
          if (!ex->response.has_value()) {
            return IO<dto::DeviceInstallConfigDto>::fail(
                make_error(my_errors::NETWORK::READ_ERROR,
                           "No response for install-config"));
          }

          int status = ex->response->result_int();
          if (status != 200) {
            auto err = make_error(
                my_errors::NETWORK::READ_ERROR,
                fmt::format("install-config fetch HTTP status {}", status));
            err.response_status = status;
            err.params["response_body_preview"] = ex->response->body();
            return IO<dto::DeviceInstallConfigDto>::fail(std::move(err));
          }

          auto result =
              ex->template parseJsonDataResponse<dto::DeviceInstallConfigDto>();
          if (result.is_err()) {
            return IO<dto::DeviceInstallConfigDto>::fail(result.error());
          }
          return IO<dto::DeviceInstallConfigDto>::pure(result.value());
        });
  };

  return perform_fetch()
      .then([this, expected_version,
             expected_hash](dto::DeviceInstallConfigDto config)
                -> ReturnIO {
        if (expected_version && config.version != *expected_version) {
          output_.logger().warning()
              << "Fetched install-config version " << config.version
              << " does not match expected " << *expected_version
              << std::endl;
        }
        if (expected_hash && !config.installs_hash.empty() &&
            config.installs_hash != *expected_hash) {
          output_.logger().warning()
              << "Fetched install-config hash mismatch" << std::endl;
        }

        return persist_config(config)
            .then([this]() -> ReturnIO {
              return ReturnIO::pure(cached_config_);
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
    output_.logger().error()
        << "Failed to parse cached install_config.json: " << e.what()
        << std::endl;
    return std::nullopt;
  }
}

monad::IO<void>
InstallConfigManager::persist_config(const dto::DeviceInstallConfigDto &config) {
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
    std::filesystem::permissions(
        config_file_path(),
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
    std::filesystem::permissions(
        version_file_path(),
        std::filesystem::perms::owner_read |
            std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);
#endif

    cached_config_ =
        std::make_shared<dto::DeviceInstallConfigDto>(config);
    local_version_ = config.version;

    return ReturnIO::pure();
  } catch (const std::exception &e) {
  return ReturnIO::fail(
    monad::make_error(my_errors::GENERAL::FILE_READ_WRITE, e.what()));
  }
}

std::optional<std::string> InstallConfigManager::load_access_token() const {
  const auto token_file = state_dir() / "access_token.txt";

  std::error_code ec;
  const auto mtime = std::filesystem::last_write_time(token_file, ec);
  if (!ec && cached_access_token_ && cached_access_token_mtime_ &&
      mtime == *cached_access_token_mtime_) {
    return cached_access_token_;
  }

  std::ifstream ifs(token_file, std::ios::binary);
  if (!ifs.is_open()) {
    cached_access_token_.reset();
    cached_access_token_mtime_.reset();
    return std::nullopt;
  }

  std::string token((std::istreambuf_iterator<char>(ifs)),
                    std::istreambuf_iterator<char>());
  auto first = token.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) {
    cached_access_token_.reset();
    cached_access_token_mtime_.reset();
    return std::nullopt;
  }
  auto last = token.find_last_not_of(" \t\r\n");
  if (last == std::string::npos || last < first) {
    cached_access_token_.reset();
    cached_access_token_mtime_.reset();
    return std::nullopt;
  }

  token = token.substr(first, last - first + 1);
  cached_access_token_ = token;
  if (!ec) {
    cached_access_token_mtime_ = mtime;
  } else {
    cached_access_token_mtime_.reset();
  }
  return cached_access_token_;
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

std::filesystem::path InstallConfigManager::resource_current_dir(
    const std::string &ob_type, std::int64_t ob_id) const {
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

std::optional<monad::Error> InstallConfigManager::ensure_resource_materialized_sync(
    const dto::InstallItem &item) {
  using monad::GetStringTag;
  using monad::http_io;
  using monad::http_request_io;
  using ExchangePtr = monad::ExchangePtrFor<GetStringTag>;
  using ResultType = monad::Result<ExchangePtr, monad::Error>;

  if (!item.ob_type || !item.ob_id) {
    return monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                             "Resource reference missing ob_type/ob_id");
  }

  auto current_dir = resource_current_dir(*item.ob_type, *item.ob_id);

  if (runtime_dir_.empty()) {
    return monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                             "Runtime directory is not configured");
  }

  bool all_present = true;
  if (item.from) {
    for (const auto &virtual_name : *item.from) {
      if (!virtual_name.empty()) {
        if (!std::filesystem::exists(current_dir / virtual_name)) {
          all_present = false;
          break;
        }
      }
    }
  }

  if (all_present) {
    return std::nullopt;
  }

  std::string body;
  if (resource_fetch_override_) {
    auto override_body = resource_fetch_override_(item);
    if (!override_body) {
  return monad::make_error(
      my_errors::GENERAL::INVALID_ARGUMENT,
      "Resource fetch override returned empty body");
    }
    body = std::move(*override_body);
  } else {
    if (!http_client_) {
      return monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                               "InstallConfigManager requires HTTP client");
    }

    auto token_opt = load_access_token();
    if (!token_opt || token_opt->empty()) {
      return monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                               "Device access token unavailable");
    }

    const auto &cfg = config_provider_.get();
    std::string url;
    if (*item.ob_type == "cert") {
      url = fmt::format("{}/apiv1/devices/self/certificates/{}/bundle?pack=download",
                        cfg.base_url, *item.ob_id);
    } else if (*item.ob_type == "ca") {
      url = fmt::format("{}/apiv1/devices/self/cas/{}/bundle?pack=download",
                        cfg.base_url, *item.ob_id);
    } else {
  return monad::make_error(
      my_errors::GENERAL::INVALID_ARGUMENT,
      fmt::format("Unsupported ob_type '{}'", *item.ob_type));
    }

    namespace http = boost::beast::http;

    constexpr int kMaxAttempts = 12;
    constexpr std::chrono::seconds kRetryDelay{3};

    std::optional<monad::Error> last_error;

    for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
      auto request_io = http_io<GetStringTag>(url)
                            .map([token = *token_opt](auto ex) {
                              ex->request.set(http::field::authorization,
                                              std::string("Bearer ") + token);
                              return ex;
                            })
                            .then(http_request_io<GetStringTag>(*http_client_));

      std::promise<ResultType> promise;
      auto future = promise.get_future();
      request_io.run([&promise](ResultType result) {
        promise.set_value(std::move(result));
      });

      auto io_result = future.get();
      if (io_result.is_err()) {
        return io_result.error();
      }

      auto exchange = io_result.value();
      if (!exchange->response.has_value()) {
        return monad::make_error(my_errors::NETWORK::READ_ERROR,
                                 "No response while fetching resource");
      }

      int status = exchange->response->result_int();
      body = exchange->response->body();

      if (status == 200) {
        last_error.reset();
        break;
      }

    auto err = monad::make_error(
      my_errors::NETWORK::READ_ERROR,
      fmt::format("Resource fetch HTTP {}", status));
      err.response_status = status;
      err.params["response_body_preview"] = body.substr(0, 512);

      if (status == 503) {
        last_error = err;

        std::string body_preview = body.substr(0, 512);
        output_.logger().info()
            << "Resource fetch 503 for URL '" << url
            << "' (attempt " << attempt << "/" << kMaxAttempts
            << ") response preview: " << body_preview << std::endl;
        output_.logger().info()
            << "Retrying after " << (kRetryDelay * 2).count()
            << " seconds for server availability" << std::endl;

        if (attempt == kMaxAttempts) {
          break;
        }

        std::this_thread::sleep_for(kRetryDelay * 2);
        continue;
      }

  return err;
    }

    if (last_error.has_value()) {
      return last_error;
    }
  }

  try {
    std::filesystem::create_directories(current_dir);
    auto raw_path = current_dir.parent_path() / "bundle_raw.json";
    {
      std::ofstream ofs(raw_path, std::ios::binary | std::ios::trunc);
      ofs << body;
    }

    std::unordered_map<std::string, std::string> text_outputs;
    std::unordered_map<std::string, std::vector<unsigned char>> binary_outputs;

    auto bundle_data = parse_bundle_data(body);

    if (item.from) {
      if (item.ob_type && *item.ob_type == "cert") {
        if (bundle_data) {
          std::string decrypt_error;
          auto private_key_pem =
              decrypt_private_key_pem(*bundle_data, runtime_dir_, state_dir(),
                                      decrypt_error);
          if (!private_key_pem) {
      return monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        fmt::format(
          "Failed to materialize decrypted private key for cert {}: {}",
          *item.ob_id, decrypt_error));
          }
          text_outputs["private.key"] = std::move(*private_key_pem);
          if (auto *pem = bundle_data->if_contains("certificate_pem")) {
            if (auto merged = join_pem_entries(*pem)) {
              text_outputs["certificate.pem"] = *merged;
            }
          }
          if (auto *chain = bundle_data->if_contains("chain_pem")) {
            if (auto merged = join_pem_entries(*chain)) {
              text_outputs["chain.pem"] = *merged;
            }
          }
          if (auto *fullchain = bundle_data->if_contains("fullchain_pem")) {
            if (auto merged = join_pem_entries(*fullchain)) {
              text_outputs["fullchain.pem"] = *merged;
            }
          }
          if (auto *cert_der = bundle_data->if_contains("certificate_der_b64")) {
            if (auto bytes = decode_base64_to_bytes(*cert_der)) {
              binary_outputs["certificate.der"] = std::move(*bytes);
            }
          }
          if (auto pfx = extract_bundle_pfx_bytes(*bundle_data)) {
            binary_outputs["bundle.pfx"] = std::move(*pfx);
          }
          text_outputs["meta.json"] = boost::json::serialize(*bundle_data);
        } else {
          text_outputs["private.key"] = body;
          text_outputs["meta.json"] = body;
        }
      } else if (item.ob_type && *item.ob_type == "ca") {
        if (bundle_data) {
          if (auto *pem = bundle_data->if_contains("ca_certificate_pem")) {
            text_outputs["ca.pem"] = boost::json::value_to<std::string>(*pem);
          }
          if (auto *der = bundle_data->if_contains("ca_certificate_der_b64")) {
            if (auto bytes = decode_base64_to_bytes(*der)) {
              binary_outputs["ca.der"] = std::move(*bytes);
            }
          }
          text_outputs["meta.json"] = boost::json::serialize(*bundle_data);
        } else {
          text_outputs["meta.json"] = body;
        }
      }

      for (const auto &virtual_name : *item.from) {
        if (virtual_name.empty()) {
          continue;
        }
        auto file_path = current_dir / virtual_name;
        if (auto binary_it = binary_outputs.find(virtual_name);
            binary_it != binary_outputs.end()) {
          std::ofstream ofs(file_path, std::ios::binary | std::ios::trunc);
          ofs.write(reinterpret_cast<const char *>(binary_it->second.data()),
                    static_cast<std::streamsize>(binary_it->second.size()));
        } else if (auto text_it = text_outputs.find(virtual_name);
                   text_it != text_outputs.end()) {
          std::ofstream ofs(file_path, std::ios::binary | std::ios::trunc);
          ofs << text_it->second;
        } else {
          std::ofstream ofs(file_path, std::ios::binary | std::ios::trunc);
          ofs << body;
        }
      }
    }

    output_.logger().debug()
        << "Fetched resource " << *item.ob_type << "/" << *item.ob_id
        << " (materials cached)" << std::endl;
  } catch (const std::exception &e) {
    return monad::make_error(my_errors::GENERAL::FILE_READ_WRITE, e.what());
  }

  return std::nullopt;
}

monad::IO<void> InstallConfigManager::apply_copy_actions(
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id) {
  install_actions::InstallActionContext context{
      runtime_dir_,
      output_,
      [this](const dto::InstallItem &item) {
        return ensure_resource_materialized_sync(item);
      }};

  return install_actions::apply_copy_actions(context, config, target_ob_type,
                                             target_ob_id);
}

monad::IO<void> InstallConfigManager::apply_import_ca_actions(
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id) {
  install_actions::InstallActionContext context{
      runtime_dir_,
      output_,
      [this](const dto::InstallItem &item) {
        return ensure_resource_materialized_sync(item);
      }};

  return install_actions::apply_import_ca_actions(context, config,
                                                  target_ob_type,
                                                  target_ob_id);
}

monad::IO<void> InstallConfigManager::apply_copy_actions_for_signal(
  const ::data::DeviceUpdateSignal &signal) {
  using ReturnIO = monad::IO<void>;

  if (signal.type == "install.updated") {
  auto typed = ::data::get_install_updated(signal);
    std::optional<std::int64_t> expected_version;
    std::optional<std::string> expected_hash;
    if (typed) {
      expected_version = typed->version;
      expected_hash = typed->installs_hash_b64;
    }

    return ensure_config_version(expected_version, expected_hash)
        .then([this](auto config_ptr) {
          using ReturnIO = monad::IO<void>;
          if (!config_provider_.get().auto_apply_config) {
            output_.logger().info()
                << "auto_apply_config disabled; staged install-config version "
                << config_ptr->version << " for manual approval." << std::endl;
            return ReturnIO::pure();
          }
          return apply_copy_actions(*config_ptr, std::nullopt, std::nullopt);
        });
  }

  if (signal.type == "cert.renewed") {
  if (auto typed = ::data::get_cert_renewed(signal)) {
      return ensure_cached_config().then([this, cert_id = typed->cert_id](auto config_ptr) {
        return apply_copy_actions(*config_ptr, std::string("cert"), cert_id);
      });
    }
  }

  if (signal.type == "cert.revoked") {
    // TODO: Implement removal / quarantine logic
    output_.logger().warning()
        << "cert.revoked handling not yet implemented" << std::endl;
    return ReturnIO::pure();
  }

  return ReturnIO::pure();
}

} // namespace certctrl
