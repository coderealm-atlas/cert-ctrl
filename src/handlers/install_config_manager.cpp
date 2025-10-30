#include "handlers/install_config_manager.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/function_adapters.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/system/error_code.hpp>
#include <boost/log/trivial.hpp>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <cstring>
#include <fmt/format.h>
#include <future>
#include <iostream>
#include <random>
#include <thread>
#include <unordered_map>
#include <array>
#include <sstream>
#include <string_view>
#include <vector>

#include <sodium.h>

#include "http_client_monad.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "base64.h"
#include "openssl/crypt_util.hpp"
#include "openssl/openssl_raii.hpp"
#include "util/secret_util.hpp"
#include "util/user_key_crypto.hpp"

namespace certctrl {

using monad::Error;

namespace {

constexpr const char kPfxPasswordEnvVar[] = "CERTCTRL_PFX_PASSWORD";

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

std::optional<std::vector<unsigned char>> decode_base64_string_raw(
    const std::string &value) {
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

std::optional<std::string> extract_private_key_from_detail(
    const boost::json::object &detail_obj, std::string &error_out) {
  auto get_string_field = [](const boost::json::object &obj,
                             std::string_view key)
      -> std::optional<std::string> {
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

  auto decode_der_field = [&](const boost::json::object &source,
                              std::string_view key)
      -> std::optional<std::string> {
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
  bundle_passwords_.clear();
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

  constexpr int kMaxAttempts = 4;
  constexpr std::chrono::milliseconds kBaseRetryDelay{200};

  auto attempt_ref = std::make_shared<std::function<ReturnIO(int)>>();

  *attempt_ref = [this, expected_version, expected_hash, perform_fetch,
                  attempt_ref, kMaxAttempts, kBaseRetryDelay](int attempt)
      -> ReturnIO {
    return perform_fetch()
        .then([this, expected_version, expected_hash, attempt, attempt_ref,
               kMaxAttempts, kBaseRetryDelay](
                  dto::DeviceInstallConfigDto config) -> ReturnIO {
          if (expected_version && config.version < *expected_version) {
            output_.logger().warning()
                << "Fetched install-config version " << config.version
                << " is older than expected " << *expected_version
                << std::endl;

            if (attempt + 1 < kMaxAttempts) {
              auto delay = kBaseRetryDelay * (attempt + 1);
              output_.logger().info()
                  << "Retrying install-config fetch (attempt "
                  << (attempt + 2) << "/" << kMaxAttempts
                  << ") after " << delay.count() << "ms" << std::endl;
              std::this_thread::sleep_for(delay);
              return (*attempt_ref)(attempt + 1);
            }

            auto err = make_error(
                my_errors::GENERAL::UNEXPECTED_RESULT,
                fmt::format(
                    "install-config fetch returned stale version {} (expected >= {})",
                    config.version, *expected_version));
            err.params["expected_version"] = std::to_string(*expected_version);
            err.params["observed_version"] = std::to_string(config.version);
            return ReturnIO::fail(std::move(err));
          }

          if (expected_version && config.version > *expected_version) {
            output_.logger().info()
                << "Fetched install-config version " << config.version
                << " (ahead of expected " << *expected_version << ")"
                << std::endl;
          }

          if (expected_hash && !config.installs_hash.empty() &&
              config.installs_hash != *expected_hash) {
            output_.logger().warning()
                << "Fetched install-config hash mismatch" << std::endl;
          }

          return persist_config(config).then([this]() -> ReturnIO {
            return ReturnIO::pure(cached_config_);
          });
        });
  };

  return (*attempt_ref)(0);
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

monad::IO<void> InstallConfigManager::ensure_resource_materialized(
    const dto::InstallItem &item) {
  auto result = ensure_resource_materialized_impl(item);
  if (result.has_value()) {
    return monad::IO<void>::fail(std::move(*result));
  }
  return monad::IO<void>::pure();
}

std::optional<monad::Error>
InstallConfigManager::ensure_resource_materialized_impl(
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

  BOOST_LOG_SEV(lg, trivial::trace)
    << "ensure_resource_materialized start ob_type=" << *item.ob_type
      << " ob_id=" << *item.ob_id;

  const std::string ob_type = *item.ob_type;
  const std::int64_t ob_id = *item.ob_id;
  const bool is_cert = (ob_type == "cert");

  auto current_dir = resource_current_dir(*item.ob_type, *item.ob_id);

  if (runtime_dir_.empty()) {
    return monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                             "Runtime directory is not configured");
  }

  bool all_present = true;
  bool bundle_requested = false;
  if (item.from) {
    for (const auto &virtual_name : *item.from) {
      if (!virtual_name.empty()) {
        if (virtual_name == "bundle.pfx") {
          bundle_requested = true;
        }
        if (!std::filesystem::exists(current_dir / virtual_name)) {
          all_present = false;
          break;
        }
      }
    }
  }

  DEBUG_PRINT("ensure_resource_materialized_impl check ob_type=" << ob_type
               << " ob_id=" << ob_id << " all_present=" << all_present
               << " bundle_requested=" << bundle_requested);

  if (all_present) {
    if (is_cert && bundle_requested && !lookup_bundle_password(ob_type, ob_id)) {
      all_present = false;
    }
  }

  if (all_present) {
    BOOST_LOG_SEV(lg, trivial::trace)
        << "ensure_resource_materialized_impl short-circuit ob_type="
        << ob_type << " ob_id=" << ob_id
        << " materials in place";
    BOOST_LOG_SEV(lg, trivial::trace)
        << "Resource already materialized ob_type=" << ob_type
        << " ob_id=" << ob_id;
    return std::nullopt;
  }

  auto parse_enveloped_object = [](const std::string &raw,
                                   const char *context,
                                   boost::json::object &out)
      -> std::optional<monad::Error> {
    boost::system::error_code ec;
    auto parsed = boost::json::parse(raw, ec);
    if (ec || !parsed.is_object()) {
      return monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT,
          fmt::format("{} response not a JSON object: {}", context, ec ? ec.message() : ""));
    }
    auto &obj = parsed.as_object();
    if (auto *data = obj.if_contains("data")) {
      if (data->is_object()) {
        out = data->as_object();
        return std::nullopt;
      }
    }
    return monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        fmt::format("{} response missing data object", context));
  };

  auto get_string_field = [](const boost::json::object &obj,
                             std::string_view key) -> std::optional<std::string> {
    if (auto *value = obj.if_contains(key)) {
      if (value->is_string()) {
        return value->as_string().c_str();
      }
    }
    return std::nullopt;
  };

  auto decode_base64_string = [](const std::string &encoded)
      -> std::optional<std::vector<unsigned char>> {
    try {
      std::string decoded = base64_decode(encoded);
      return std::vector<unsigned char>(decoded.begin(), decoded.end());
    } catch (...) {
      return std::nullopt;
    }
  };

  auto extract_pem = [](const boost::json::object &obj,
                        std::string_view key) -> std::optional<std::string> {
    if (auto *value = obj.if_contains(key)) {
      if (value->is_string()) {
        return value->as_string().c_str();
      }
      if (auto merged = join_pem_entries(*value)) {
        return merged;
      }
    }
    return std::nullopt;
  };

  auto fetch_http_body = [&](const std::string &url,
                             const std::string &token,
                             std::string &out_body) -> std::optional<monad::Error> {
    namespace http = boost::beast::http;

    constexpr int kMaxAttempts = 12;
    constexpr std::chrono::seconds kRetryBaseDelay{3};

    auto attempt_counter = std::make_shared<int>(0);

    auto fetch_once = http_io<GetStringTag>(url)
                          .map([&, token](auto ex) {
                            const int current_attempt = ++(*attempt_counter);
                            BOOST_LOG_SEV(lg, trivial::trace)
                                << "fetch_http_body attempt "
                                << current_attempt << '/' << kMaxAttempts
                                << " for url=" << url;
                            ex->request.set(http::field::authorization,
                                            std::string("Bearer ") + token);
                            return ex;
                          })
                          .then(http_request_io<GetStringTag>(*http_client_))
                          .then([&, url](ExchangePtr ex) -> monad::IO<std::string> {
                            if (!ex->response.has_value()) {
                              BOOST_LOG_SEV(lg, trivial::warning)
                                  << "fetch_http_body received empty response for url="
                                  << url;
                              return monad::IO<std::string>::fail(
                                  monad::make_error(
                                      my_errors::NETWORK::READ_ERROR,
                                      "No response while fetching resource"));
                            }

                            int status = ex->response->result_int();
                            std::string body = ex->response->body();

                            if (status == 200) {
                              DEBUG_PRINT("fetch_http_body success status=200 url="
                                           << url << " bytes=" << body.size());
                              BOOST_LOG_SEV(lg, trivial::trace)
                                  << "fetch_http_body succeeded for url=" << url
                                  << " (status=200, bytes=" << body.size() << ')';
                              return monad::IO<std::string>::pure(std::move(body));
                            }

                            DEBUG_PRINT("fetch_http_body failure status=" << status
                                         << " url=" << url
                                         << " preview=" << body.substr(0, 128));

              auto err = monad::make_error(
                my_errors::NETWORK::READ_ERROR,
                fmt::format("Resource fetch HTTP {}", status));
                            err.response_status = status;
                            err.params["response_body_preview"] = body.substr(0, 512);

                            if (status == 503) {
                              auto preview = body.substr(0, 512);
                              output_.logger().info()
                                  << "Resource fetch 503 for URL '" << url
                                  << "' (attempt " << *attempt_counter << "/"
                                  << kMaxAttempts << ") response preview: "
                                  << preview << std::endl;

                              const auto next_delay = kRetryBaseDelay *
                                                      (1 << std::max(0, *attempt_counter - 1));
                              if (*attempt_counter < kMaxAttempts) {
                                output_.logger().info()
                                    << "Retrying after " << next_delay.count()
                                    << " seconds for server availability" << std::endl;
                              } else {
                                BOOST_LOG_SEV(lg, trivial::warning)
                                    << "fetch_http_body exhausted retries for url=" << url
                                    << " last_status=503";
                              }
                            } else {
                              BOOST_LOG_SEV(lg, trivial::warning)
                                  << "fetch_http_body aborting on status=" << status
                                  << " for url=" << url;
                            }

                            BOOST_LOG_SEV(lg, trivial::error)
                                << "fetch_http_body error status=" << status
                                << " url=" << url << " what=" << err.what;
                            return monad::IO<std::string>::fail(std::move(err));
                          });

    boost::asio::io_context retry_ioc;
    retry_ioc.restart();

    auto should_retry = [attempt_counter, kMaxAttempts](const monad::Error &err) {
      return err.response_status == 503 && *attempt_counter < kMaxAttempts;
    };

    std::promise<monad::Result<std::string, monad::Error>> promise;
    auto future = promise.get_future();

    std::move(fetch_once)
        .retry_exponential_if(kMaxAttempts, kRetryBaseDelay, retry_ioc, should_retry)
        .run([&promise](monad::Result<std::string, monad::Error> result) {
          promise.set_value(std::move(result));
        });

    while (future.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
      auto processed = retry_ioc.poll_one();
      if (processed == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }

    retry_ioc.restart();
    retry_ioc.poll();

    auto result = future.get();
    if (result.is_ok()) {
      out_body = std::move(result.value());
      return std::nullopt;
    }

    DEBUG_PRINT("fetch_http_body final error status="
                 << result.error().response_status << " url=" << url);

    if (result.error().response_status != 503) {
      BOOST_LOG_SEV(lg, trivial::debug)
          << "fetch_http_body received status=" << result.error().response_status
          << " for url=" << url;
    }

    auto err = result.error();
    BOOST_LOG_SEV(lg, trivial::error)
        << "fetch_http_body giving up url=" << url
        << " status=" << err.response_status
        << " what=" << err.what;
    return err;
  };

  std::unordered_map<std::string, std::string> text_outputs;
  std::unordered_map<std::string, std::vector<unsigned char>> binary_outputs;

  std::string deploy_raw_json;
  std::string detail_raw_json;
  std::string ca_raw_json;
  boost::json::object deploy_obj;
  boost::json::object detail_obj;

  if (!item.ob_type) {
    return monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                             "Install item missing ob_type");
  }

  if (resource_fetch_override_ && *item.ob_type == "cert") {
    auto override_body = resource_fetch_override_(item);
    if (!override_body) {
      return monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          "Resource fetch override returned empty body");
    }

    boost::system::error_code ec;
    auto parsed = boost::json::parse(*override_body, ec);
    if (ec || !parsed.is_object()) {
      return monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                               "Override payload for cert is not an object");
    }
    auto &obj = parsed.as_object();
    if (auto *deploy = obj.if_contains("deploy")) {
      if (deploy->is_object()) {
        deploy_obj = deploy->as_object();
      }
    }
    if (auto *detail = obj.if_contains("detail")) {
      if (detail->is_object()) {
        detail_obj = detail->as_object();
      }
    }
    if (deploy_obj.empty() && obj.if_contains("data") && obj["data"].is_object()) {
      deploy_obj = obj["data"].as_object();
    }
    if (detail_obj.empty() && obj.if_contains("certificate") && obj["certificate"].is_object()) {
      detail_obj = obj["certificate"].as_object();
    }
    if (detail_obj.empty()) {
      return monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT,
          "Override payload missing certificate detail object");
    }
    deploy_raw_json = boost::json::serialize(boost::json::object{{"data", deploy_obj}});
    detail_raw_json = boost::json::serialize(boost::json::object{{"data", detail_obj}});
    if (deploy_obj.empty()) {
      boost::json::object placeholder;
      placeholder["note"] =
          "resource override missing deploy materials; generated locally";
      deploy_raw_json = boost::json::serialize(
          boost::json::object{{"data", placeholder}});
    }
  } else if (*item.ob_type == "cert") {
    if (!http_client_) {
      auto err = monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                                   "InstallConfigManager requires HTTP client");
      BOOST_LOG_SEV(lg, trivial::error)
          << "ensure_resource_materialized_impl cert fetch missing http_client ob_id="
          << *item.ob_id;
      return err;
    }

    auto token_opt = load_access_token();
    if (!token_opt || token_opt->empty()) {
      auto err = monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                                   "Device access token unavailable");
      BOOST_LOG_SEV(lg, trivial::error)
          << "ensure_resource_materialized_impl cert fetch missing token ob_id="
          << *item.ob_id;
      return err;
    }

    const auto &cfg = config_provider_.get();
    std::string detail_url = fmt::format(
        "{}/apiv1/devices/self/certificates/{}", cfg.base_url, *item.ob_id);
    std::string deploy_url = fmt::format(
        "{}/apiv1/devices/self/certificates/{}/deploy-materials",
        cfg.base_url, *item.ob_id);

    if (auto err = fetch_http_body(detail_url, *token_opt, detail_raw_json)) {
      BOOST_LOG_SEV(lg, trivial::error)
          << "ensure_resource_materialized_impl detail fetch failed cert ob_id="
          << *item.ob_id << " status=" << err->response_status
          << " what=" << err->what;
      return err;
    }

    bool deploy_available = true;
    if (auto err = fetch_http_body(deploy_url, *token_opt, deploy_raw_json)) {
      if (err->response_status == 404 || err->response_status == 204) {
        deploy_available = false;
        deploy_raw_json.clear();
        output_.logger().info()
            << "Deploy materials endpoint unavailable for cert "
            << *item.ob_id << " (status=" << err->response_status
            << "); falling back to certificate detail payload" << std::endl;
        boost::json::object placeholder;
        placeholder["note"] =
            "no deploy materials provided; generated locally by agent";
        deploy_raw_json =
            boost::json::serialize(boost::json::object{{"data", placeholder}});
      } else {
        BOOST_LOG_SEV(lg, trivial::error)
            << "ensure_resource_materialized_impl deploy fetch failed cert ob_id="
            << *item.ob_id << " status=" << err->response_status
            << " what=" << err->what;
        return err;
      }
    }

    if (auto err = parse_enveloped_object(detail_raw_json,
                                           "certificate detail", detail_obj)) {
      BOOST_LOG_SEV(lg, trivial::error)
          << "ensure_resource_materialized_impl parse detail failed cert ob_id="
          << *item.ob_id << " what=" << err->what;
      return err;
    }
    if (deploy_available) {
      if (auto err = parse_enveloped_object(
              deploy_raw_json, "deploy materials", deploy_obj)) {
        BOOST_LOG_SEV(lg, trivial::error)
            << "ensure_resource_materialized_impl parse deploy failed cert ob_id="
            << *item.ob_id << " what=" << err->what;
        return err;
      }
    }
  }

  std::string ca_body;
  boost::json::object ca_obj;
  if (*item.ob_type == "ca") {
    if (resource_fetch_override_) {
      auto override_body = resource_fetch_override_(item);
      if (!override_body) {
        auto err = monad::make_error(
            my_errors::GENERAL::INVALID_ARGUMENT,
            "Resource fetch override returned empty body");
        BOOST_LOG_SEV(lg, trivial::error)
            << "ensure_resource_materialized_impl CA override empty ob_id="
            << *item.ob_id;
        return err;
      }
      ca_body = std::move(*override_body);
    } else {
      if (!http_client_) {
        auto err = monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                                     "InstallConfigManager requires HTTP client");
        BOOST_LOG_SEV(lg, trivial::error)
            << "ensure_resource_materialized_impl CA fetch missing http_client ob_id="
            << *item.ob_id;
        return err;
      }

      auto token_opt = load_access_token();
      if (!token_opt || token_opt->empty()) {
        auto err = monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                                     "Device access token unavailable");
        BOOST_LOG_SEV(lg, trivial::error)
            << "ensure_resource_materialized_impl CA fetch missing token ob_id="
            << *item.ob_id;
        return err;
      }

      const auto &cfg = config_provider_.get();
      std::string url = fmt::format(
          "{}/apiv1/devices/self/cas/{}/bundle?pack=download", cfg.base_url,
          *item.ob_id);
      if (auto err = fetch_http_body(url, *token_opt, ca_body)) {
        DEBUG_PRINT("CA fetch error status=" << err->response_status
                     << " url=" << url);
        BOOST_LOG_SEV(lg, trivial::warning)
            << "Failed to fetch CA bundle ob_type=" << *item.ob_type
            << " ob_id=" << *item.ob_id
            << " status=" << err->response_status;
        BOOST_LOG_SEV(lg, trivial::error)
            << "ensure_resource_materialized_impl CA fetch failed ob_id="
            << *item.ob_id << " status=" << err->response_status
            << " what=" << err->what;
        return err;
      }

      DEBUG_PRINT("CA fetch bytes=" << ca_body.size() << " url=" << url);
    }

    auto bundle_data = parse_bundle_data(ca_body);
    if (!bundle_data) {
      DEBUG_PRINT("CA bundle parse failed ob_type=" << *item.ob_type
                   << " ob_id=" << *item.ob_id
                   << " preview=" << ca_body.substr(0, 128));
      BOOST_LOG_SEV(lg, trivial::warning)
          << "CA bundle missing expected data ob_type=" << *item.ob_type
          << " ob_id=" << *item.ob_id;
      auto err = monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT,
          "CA bundle response missing expected data");
      BOOST_LOG_SEV(lg, trivial::error)
          << "ensure_resource_materialized_impl CA bundle parse failure ob_id="
          << *item.ob_id;
      return err;
    }
    DEBUG_PRINT("CA bundle parsed keys=" << bundle_data->size()
                 << " ob_type=" << *item.ob_type << " ob_id=" << *item.ob_id);
    ca_obj = *bundle_data;
  }

  try {
    std::filesystem::create_directories(current_dir);

    if (item.from) {
      if (*item.ob_type == "cert") {
        std::string decrypt_error;
        std::optional<std::string> private_key_pem;
        if (!deploy_obj.empty()) {
          private_key_pem =
              decrypt_private_key_pem(deploy_obj, runtime_dir_, state_dir(),
                                      decrypt_error);
        }

        std::string fallback_error;
        if (!private_key_pem) {
          private_key_pem = extract_private_key_from_detail(detail_obj,
                                                            fallback_error);
        }

        if (!private_key_pem) {
          std::string message =
              fmt::format("Failed to materialize private key for cert {}",
                          *item.ob_id);
          if (!decrypt_error.empty()) {
            message += "; deploy materials: " + decrypt_error;
          }
          if (!fallback_error.empty()) {
            message += "; detail fallback: " + fallback_error;
          }
          return monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                                   std::move(message));
        }

        text_outputs["private.key"] = *private_key_pem;

        const boost::json::object *detail_view = &detail_obj;
        if (auto *cert_node = detail_obj.if_contains("certificate")) {
          if (cert_node->is_object()) {
            detail_view = &cert_node->as_object();
          }
        }

        std::optional<std::string> cert_source =
            extract_pem(*detail_view, "certificate_pem");
        if (!cert_source) {
          cert_source = extract_pem(*detail_view, "cert");
        }

        if (!cert_source || cert_source->empty()) {
          return monad::make_error(
              my_errors::GENERAL::UNEXPECTED_RESULT,
              fmt::format(
                  "Certificate detail missing PEM payload for cert {}",
                  *item.ob_id));
        }

        auto pem_blocks = split_pem_certificates(*cert_source);
        if (pem_blocks.empty()) {
          pem_blocks.emplace_back(*cert_source);
        }

        std::string leaf_pem = pem_blocks.front();
        std::string chain_pem = join_cert_blocks(pem_blocks, 1);

        if (auto chain_field = extract_pem(*detail_view, "chain_pem")) {
          if (!chain_field->empty()) {
            chain_pem = *chain_field;
          }
        }

        std::string fullchain_pem;
        if (auto fullchain_field = extract_pem(*detail_view, "fullchain_pem")) {
          fullchain_pem = *fullchain_field;
        }

        if (fullchain_pem.empty()) {
          fullchain_pem = leaf_pem;
          if (!fullchain_pem.empty() && fullchain_pem.back() != '\n') {
            fullchain_pem.push_back('\n');
          }
          if (!chain_pem.empty()) {
            fullchain_pem += chain_pem;
          }
        }

        if (chain_pem.empty()) {
          auto derived_chain_blocks = split_pem_certificates(fullchain_pem);
          if (derived_chain_blocks.size() > 1) {
            chain_pem = join_cert_blocks(derived_chain_blocks, 1);
          }
        }

        bool chain_required = false;
        if (item.from) {
          chain_required = std::find(item.from->begin(), item.from->end(),
                                     std::string("chain.pem")) !=
                           item.from->end();
        }
        if (chain_required && chain_pem.empty()) {
          chain_pem = leaf_pem;
        }

        text_outputs["certificate.pem"] = leaf_pem;
        if (!chain_pem.empty()) {
          text_outputs["chain.pem"] = chain_pem;
        }
        text_outputs["fullchain.pem"] = fullchain_pem;

    if (binary_outputs.find("certificate.der") ==
      binary_outputs.end()) {
          std::vector<unsigned char> der_bytes;
          if (cjj365::opensslutil::convert_pem_string_to_der(leaf_pem,
                                                             der_bytes)) {
            binary_outputs["certificate.der"] = std::move(der_bytes);
          }
        }

        if (binary_outputs.find("bundle.pfx") == binary_outputs.end()) {
          try {
            auto pkey =
                cjj365::opensslutil::load_private_key(*private_key_pem, false);
            if (!pkey) {
              return monad::make_error(
                  my_errors::GENERAL::UNEXPECTED_RESULT,
                  "Failed to load private key for PKCS#12 generation");
            }

            std::string pfx_chain = fullchain_pem;
            if (pfx_chain.empty()) {
              pfx_chain = leaf_pem;
            }

            std::string alias = "Certificate";
            if (auto name = detail_view->if_contains("domain_name")) {
              if (name->is_string() && !name->as_string().empty()) {
                alias = std::string(name->as_string().c_str());
              }
            } else if (auto name = detail_obj.if_contains("domain_name")) {
              if (name->is_string() && !name->as_string().empty()) {
                alias = std::string(name->as_string().c_str());
              }
            }

            std::string pfx_password;
            if (auto existing = lookup_bundle_password(ob_type, ob_id)) {
              pfx_password = *existing;
            } else {
              pfx_password = cjj365::cryptutil::generateApiSecret(40);
            }

            std::string pkcs12 = cjj365::opensslutil::create_pkcs12_string(
                pkey, pfx_chain, alias, pfx_password);
            binary_outputs["bundle.pfx"] =
                std::vector<unsigned char>(pkcs12.begin(), pkcs12.end());
            remember_bundle_password(ob_type, ob_id, pfx_password);
          } catch (const std::exception &ex) {
            return monad::make_error(
                my_errors::GENERAL::UNEXPECTED_RESULT,
                fmt::format("Failed to create PKCS#12 bundle: {}",
                            ex.what()));
          }
        }

    if (binary_outputs.find("certificate.der") ==
      binary_outputs.end()) {
          if (auto der_b64 =
                  get_string_field(*detail_view, "certificate_der_b64")) {
            if (auto bytes = decode_base64_string(*der_b64)) {
              binary_outputs["certificate.der"] = std::move(*bytes);
            }
          } else if (auto *der_val =
                         detail_view->if_contains("certificate_der_b64")) {
            if (auto bytes = decode_base64_to_bytes(*der_val)) {
              binary_outputs["certificate.der"] = std::move(*bytes);
            }
          }
        }

        if (binary_outputs.find("bundle.pfx") == binary_outputs.end()) {
          if (auto *pfx_val = detail_view->if_contains("bundle_pfx_b64")) {
            if (auto bytes = decode_base64_to_bytes(*pfx_val)) {
              binary_outputs["bundle.pfx"] = std::move(*bytes);
              forget_bundle_password(ob_type, ob_id);
            }
          } else if (auto *pfx_val = detail_view->if_contains("pkcs12_b64")) {
            if (auto bytes = decode_base64_to_bytes(*pfx_val)) {
              binary_outputs["bundle.pfx"] = std::move(*bytes);
              forget_bundle_password(ob_type, ob_id);
            }
          }
        }

        boost::json::object meta_root;
        meta_root["certificate"] = detail_obj;
        meta_root["deploy_materials"] = deploy_obj;
        text_outputs["meta.json"] = boost::json::serialize(meta_root);

        auto raw_path = current_dir.parent_path() / "bundle_raw.json";
        {
          std::ofstream ofs(raw_path, std::ios::binary | std::ios::trunc);
          ofs << deploy_raw_json;
        }

        auto detail_dump = current_dir.parent_path() / "certificate_detail.json";
        {
          std::ofstream ofs(detail_dump, std::ios::binary | std::ios::trunc);
          ofs << detail_raw_json;
        }
      } else if (*item.ob_type == "ca") {
        if (auto *pem = ca_obj.if_contains("ca_certificate_pem")) {
          text_outputs["ca.pem"] = boost::json::value_to<std::string>(*pem);
        }
        if (auto *der = ca_obj.if_contains("ca_certificate_der_b64")) {
          if (auto bytes = decode_base64_to_bytes(*der)) {
            binary_outputs["ca.der"] = std::move(*bytes);
          }
        }
        boost::json::object meta_root;
        meta_root["ca_bundle"] = ca_obj;
        text_outputs["meta.json"] = boost::json::serialize(meta_root);

        auto raw_path = current_dir.parent_path() / "bundle_raw.json";
        {
          std::ofstream ofs(raw_path, std::ios::binary | std::ios::trunc);
          ofs << ca_body;
        }
      } else {
        return monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                                 fmt::format("Unsupported ob_type '{}'",
                                             *item.ob_type));
      }

      std::vector<std::string> missing;
      for (const auto &virtual_name : *item.from) {
        if (virtual_name.empty()) {
          continue;
        }
        bool present = binary_outputs.count(virtual_name) ||
                        text_outputs.count(virtual_name);
        if (!present) {
          missing.push_back(virtual_name);
        }
      }
      if (!missing.empty()) {
        std::ostringstream oss;
        oss << "Missing deploy materials: ";
        for (std::size_t i = 0; i < missing.size(); ++i) {
          if (i != 0) {
            oss << ", ";
          }
          oss << missing[i];
        }
        return monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                                 oss.str());
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
        }
      }
    }

    output_.logger().debug()
        << "Fetched resource " << *item.ob_type << "/" << *item.ob_id
        << " (materials cached)" << std::endl;
  BOOST_LOG_SEV(lg, trivial::trace)
    << "ensure_resource_materialized complete ob_type=" << ob_type
        << " ob_id=" << ob_id;
  } catch (const std::exception &e) {
    BOOST_LOG_SEV(lg, trivial::error)
        << "Failed to write resource materials ob_type=" << ob_type
        << " ob_id=" << ob_id << " error=" << e.what();
    return monad::make_error(my_errors::GENERAL::FILE_READ_WRITE, e.what());
  }

  return std::nullopt;
}

monad::IO<void> InstallConfigManager::apply_copy_actions(
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id) {
  auto resource_materializer =
      std::make_shared<install_actions::FunctionResourceMaterializer>(
          [this](const dto::InstallItem &item) {
            return ensure_resource_materialized(item);
          });

  install_actions::CopyActionHandler copy_handler(
      runtime_dir_, output_, resource_materializer);

  // First perform copy actions
  return copy_handler
      .apply(config, target_ob_type, target_ob_id)
      .then([this, &config, &target_ob_type, target_ob_id]() {
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
        auto exec_resource_materializer =
            std::make_shared<install_actions::FunctionResourceMaterializer>(
                [this](const dto::InstallItem &item) {
                  return ensure_resource_materialized(item);
                });
        auto exec_env_resolver =
            std::make_shared<install_actions::FunctionExecEnvironmentResolver>(
                [this](const dto::InstallItem &item)
                    -> std::optional<std::unordered_map<std::string, std::string>> {
                  return resolve_exec_env_for_item(item);
                });

        install_actions::ExecActionHandler exec_handler(
            runtime_dir_, output_, exec_resource_materializer,
            exec_env_resolver);
        return exec_handler.apply(config, allowed_types);
      })
  .catch_then([this](monad::Error err) {
        BOOST_LOG_SEV(lg, trivial::error)
            << "apply_copy_actions encountered error code=" << err.code
            << " status=" << err.response_status
    << " what=" << err.what
    << " params=" << boost::json::serialize(err.params);
        return monad::IO<void>::fail(std::move(err));
      });
}

monad::IO<void> InstallConfigManager::apply_import_ca_actions(
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id) {
  auto resource_materializer =
      std::make_shared<install_actions::FunctionResourceMaterializer>(
          [this](const dto::InstallItem &item) {
            return ensure_resource_materialized(item);
          });

  install_actions::ImportCaActionHandler import_handler(
      runtime_dir_, output_, resource_materializer);

  BOOST_LOG_SEV(lg, trivial::trace)
    << "apply_import_ca_actions start target_ob_type="
    << (target_ob_type ? *target_ob_type : std::string("<none>"))
    << " target_ob_id="
    << (target_ob_id ? std::to_string(*target_ob_id) : "<none>");

  return import_handler
      .apply(config, target_ob_type, target_ob_id)
      .then([this, &config, &target_ob_type, target_ob_id]() {
        std::optional<std::vector<std::string>> allowed_types = std::nullopt;
        if (target_ob_type) {
          allowed_types = std::vector<std::string>{*target_ob_type};
        }
        auto exec_resource_materializer =
            std::make_shared<install_actions::FunctionResourceMaterializer>(
                [this](const dto::InstallItem &item) {
                  return ensure_resource_materialized(item);
                });
        auto exec_env_resolver =
            std::make_shared<install_actions::FunctionExecEnvironmentResolver>(
                [this](const dto::InstallItem &item)
                    -> std::optional<std::unordered_map<std::string, std::string>> {
                  return resolve_exec_env_for_item(item);
                });

        install_actions::ExecActionHandler exec_handler(
            runtime_dir_, output_, exec_resource_materializer,
            exec_env_resolver);
        return exec_handler.apply(config, allowed_types);
      })
  .catch_then([this](monad::Error err) {
        BOOST_LOG_SEV(lg, trivial::error)
            << "apply_import_ca_actions encountered error code=" << err.code
            << " status=" << err.response_status
    << " what=" << err.what
    << " params=" << boost::json::serialize(err.params);
        return monad::IO<void>::fail(std::move(err));
      });
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
            output_.logger().info()
                << "To apply staged changes (including any cmd/cmd_argv updates), run: cert-ctrl install-config apply" << std::endl;
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

std::optional<std::unordered_map<std::string, std::string>>
InstallConfigManager::resolve_exec_env_for_item(
    const dto::InstallItem &item) {
  if (!item.ob_type || !item.ob_id) {
    return std::nullopt;
  }
  if (*item.ob_type != "cert") {
    return std::nullopt;
  }

  auto password = lookup_bundle_password(*item.ob_type, *item.ob_id);
  if (!password || password->empty()) {
    return std::nullopt;
  }

  std::unordered_map<std::string, std::string> env;
  env.emplace(kPfxPasswordEnvVar, *password);
  return env;
}

std::optional<std::string> InstallConfigManager::lookup_bundle_password(
    const std::string &ob_type, std::int64_t ob_id) const {
  auto type_it = bundle_passwords_.find(ob_type);
  if (type_it == bundle_passwords_.end()) {
    return std::nullopt;
  }
  auto id_it = type_it->second.find(ob_id);
  if (id_it == type_it->second.end()) {
    return std::nullopt;
  }
  return id_it->second;
}

void InstallConfigManager::remember_bundle_password(
    const std::string &ob_type, std::int64_t ob_id,
    const std::string &password) {
  bundle_passwords_[ob_type][ob_id] = password;
}

void InstallConfigManager::forget_bundle_password(
    const std::string &ob_type, std::int64_t ob_id) {
  auto type_it = bundle_passwords_.find(ob_type);
  if (type_it == bundle_passwords_.end()) {
    return;
  }
  type_it->second.erase(ob_id);
  if (type_it->second.empty()) {
    bundle_passwords_.erase(type_it);
  }
}

} // namespace certctrl
