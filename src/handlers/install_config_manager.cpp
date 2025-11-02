#include "handlers/install_config_manager.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/function_adapters.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "handlers/install_actions/install_resource_materializer.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/log/trivial.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <fmt/format.h>
#include <fstream>
#include <future>
#include <iostream>
#include <random>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sodium.h>

#include "base64.h"
#include "http_client_monad.hpp"
#include "my_error_codes.hpp"
#include "openssl/crypt_util.hpp"
#include "openssl/openssl_raii.hpp"
#include "result_monad.hpp"
#include "util/secret_util.hpp"
#include "util/user_key_crypto.hpp"

namespace certctrl {

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
  std::transform(
      lower.begin(), lower.end(), lower.begin(),
      [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return lower;
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
    install_actions::IAccessTokenLoader &access_token_loader)
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
      access_token_loader_(access_token_loader) {
  if (!runtime_dir_.empty()) {
    try {
      std::filesystem::create_directories(state_dir());
#ifndef _WIN32
      std::filesystem::permissions(state_dir(), default_directory_perms(),
                                   std::filesystem::perm_options::replace);
#endif
    } catch (const std::exception &e) {
      output_.logger().warning()
          << "Failed to prepare runtime state dir: " << e.what() << std::endl;
    }
  }

  if (auto config = load_from_disk()) {
    cached_config_ = std::make_shared<dto::DeviceInstallConfigDto>(
        std::move(config.value()));
    local_version_ = cached_config_->version;
  }
}

InstallConfigManager::~InstallConfigManager() {}

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

// void InstallConfigManager::configure_resource_materializer(
//     const install_actions::IResourceMaterializer::Ptr &materializer) {
//   if (!materializer) {
//     return;
//   }

//   auto concrete =
//       std::dynamic_pointer_cast<install_actions::InstallResourceMaterializer>(
//           materializer);
//   if (!concrete) {
//     return;
//   }

//   install_actions::InstallResourceMaterializer::RuntimeConfig runtime_cfg{
//       runtime_dir_,
//       [this]() { return load_access_token(); },
//       resource_fetch_override_,
//       [this](const std::string &type, std::int64_t id) {
//         return lookup_bundle_password(type, id);
//       },
//       [this](const std::string &type, std::int64_t id,
//              const std::string &password) {
//         remember_bundle_password(type, id, password);
//       },
//       [this](const std::string &type, std::int64_t id) {
//         forget_bundle_password(type, id);
//       }};

//   concrete->customize(std::move(runtime_cfg));
// }

// install_actions::IResourceMaterializer::Ptr
// InstallConfigManager::make_resource_materializer() {
//   install_actions::IResourceMaterializer::Ptr materializer;
//   if (resource_materializer_factory_) {
//     materializer = resource_materializer_factory_();
//   }

//   if (!materializer) {
//     materializer =
//         std::make_shared<install_actions::InstallResourceMaterializer>(
//             config_provider_, output_, http_client_);
//   }

//   configure_resource_materializer(materializer);
//   return materializer;
// }

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

  return config_fetcher_
      .fetch_install_config(access_token_loader_.load_token(), expected_version,
                            expected_hash)
      .then([this](dto::DeviceInstallConfigDto config) -> ReturnIO {
        return persist_config(std::move(config)).then([this]() -> ReturnIO {
          if (!cached_config_) {
            output_.logger().error()
                << "refresh_from_remote completed without cached_config_" << std::endl;
          }
          return ReturnIO::pure(cached_config_);
        });
      });

  // auto perform_fetch = [this, expected_version,
  //                       expected_hash]() -> IO<dto::DeviceInstallConfigDto> {
  //   // if (fetch_override_) {
  //   //   return fetch_override_(expected_version, expected_hash);
  //   // }

  //   auto token_opt = load_access_token();
  //   if (!token_opt || token_opt->empty()) {
  //     return IO<dto::DeviceInstallConfigDto>::fail(
  //         make_error(my_errors::GENERAL::INVALID_ARGUMENT,
  //                    "Device access token unavailable"));
  //   }

  //   const auto &cfg = config_provider_.get();
  //   std::string url =
  //       fmt::format("{}/apiv1/devices/self/install-config", cfg.base_url);

  //   return http_io<monad::GetStringTag>(url)
  //       .map([token = *token_opt](auto ex) {
  //         namespace http = boost::beast::http;
  //         ex->request.set(http::field::authorization,
  //                         std::string("Bearer ") + token);
  //         return ex;
  //       })
  //       .then(http_request_io<monad::GetStringTag>(http_client_))
  //       .then([](auto ex) -> IO<dto::DeviceInstallConfigDto> {
  //         if (!ex->response.has_value()) {
  //           return IO<dto::DeviceInstallConfigDto>::fail(
  //               make_error(my_errors::NETWORK::READ_ERROR,
  //                          "No response for install-config"));
  //         }

  //         int status = ex->response->result_int();
  //         if (status != 200) {
  //           auto err = make_error(
  //               my_errors::NETWORK::READ_ERROR,
  //               fmt::format("install-config fetch HTTP status {}", status));
  //           err.response_status = status;
  //           err.params["response_body_preview"] = ex->response->body();
  //           return IO<dto::DeviceInstallConfigDto>::fail(std::move(err));
  //         }

  //         auto result =
  //             ex->template
  //             parseJsonDataResponse<dto::DeviceInstallConfigDto>();
  //         if (result.is_err()) {
  //           return IO<dto::DeviceInstallConfigDto>::fail(result.error());
  //         }
  //         return IO<dto::DeviceInstallConfigDto>::pure(result.value());
  //       });
  // };

  // constexpr int kMaxAttempts = 4;
  // constexpr std::chrono::milliseconds kBaseRetryDelay{200};

  // auto retry_count = std::make_shared<int>(0);
  // auto next_delay =
  //     std::make_shared<std::chrono::milliseconds>(kBaseRetryDelay);

  // auto validated_fetch =
  //     perform_fetch().then([this, expected_version,
  //                           expected_hash](dto::DeviceInstallConfigDto
  //                           config)
  //                              -> monad::IO<dto::DeviceInstallConfigDto> {
  //       if (expected_version && config.version < *expected_version) {
  //         output_.logger().warning()
  //             << "Fetched install-config version " << config.version
  //             << " is older than expected " << *expected_version <<
  //             std::endl;

  //         auto err = make_error(
  //             my_errors::GENERAL::UNEXPECTED_RESULT,
  //             fmt::format("install-config fetch returned stale version {} "
  //                         "(expected >= {})",
  //                         config.version, *expected_version));
  //         err.params["expected_version"] = std::to_string(*expected_version);
  //         err.params["observed_version"] = std::to_string(config.version);
  //         err.params["retry_reason"] = "stale_version";
  //         return
  //         monad::IO<dto::DeviceInstallConfigDto>::fail(std::move(err));
  //       }

  //       if (expected_version && config.version > *expected_version) {
  //         output_.logger().info() << "Fetched install-config version "
  //                                 << config.version << " (ahead of expected "
  //                                 << *expected_version << ")" << std::endl;
  //       }

  //       if (expected_hash && !config.installs_hash.empty() &&
  //           config.installs_hash != *expected_hash) {
  //         output_.logger().warning()
  //             << "Fetched install-config hash mismatch" << std::endl;
  //       }

  //       return
  //       monad::IO<dto::DeviceInstallConfigDto>::pure(std::move(config));
  //     });

  // auto should_retry = [this, retry_count, next_delay,
  //                      kMaxAttempts](const monad::Error &err) -> bool {
  //   auto *reason = err.params.if_contains("retry_reason");
  //   if (!reason || !reason->is_string() ||
  //       reason->as_string() != "stale_version") {
  //     return false;
  //   }

  //   const int current_attempt = *retry_count;
  //   const bool can_retry = (current_attempt + 1) < kMaxAttempts;
  //   if (can_retry) {
  //     auto delay = *next_delay;
  //     output_.logger().info()
  //         << "Retrying install-config fetch (attempt " << (current_attempt +
  //         2)
  //         << "/" << kMaxAttempts << ") after " << delay.count() << "ms"
  //         << std::endl;
  //     *next_delay = *next_delay * 2;
  //   } else {
  //     output_.logger().warning()
  //         << "install-config fetch exhausted retries for stale version"
  //         << std::endl;
  //   }

  //   ++(*retry_count);
  //   return can_retry;
  // };

  // return std::move(validated_fetch)
  //     .retry_exponential_if(kMaxAttempts, kBaseRetryDelay, io_context_,
  //                           should_retry)
  //     .then([this](dto::DeviceInstallConfigDto config) -> ReturnIO {
  //       return persist_config(std::move(config)).then([this]() -> ReturnIO {
  //         return ReturnIO::pure(cached_config_);
  //       });
  //     });
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
  output_.logger().info() << "persist_config cached_config_="
              << static_cast<const void *>(cached_config_.get())
              << " version=" << cached_config_->version
              << std::endl;
    local_version_ = config.version;

    return ReturnIO::pure();
  } catch (const std::exception &e) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::FILE_READ_WRITE, e.what()));
  }
}

// std::optional<std::string> InstallConfigManager::load_access_token() const {
//   const auto token_file = state_dir() / "access_token.txt";

//   std::error_code ec;
//   const auto mtime = std::filesystem::last_write_time(token_file, ec);
//   if (!ec && cached_access_token_ && cached_access_token_mtime_ &&
//       mtime == *cached_access_token_mtime_) {
//     return cached_access_token_;
//   }

//   std::ifstream ifs(token_file, std::ios::binary);
//   if (!ifs.is_open()) {
//     cached_access_token_.reset();
//     cached_access_token_mtime_.reset();
//     return std::nullopt;
//   }

//   std::string token((std::istreambuf_iterator<char>(ifs)),
//                     std::istreambuf_iterator<char>());
//   auto first = token.find_first_not_of(" \t\r\n");
//   if (first == std::string::npos) {
//     cached_access_token_.reset();
//     cached_access_token_mtime_.reset();
//     return std::nullopt;
//   }
//   auto last = token.find_last_not_of(" \t\r\n");
//   if (last == std::string::npos || last < first) {
//     cached_access_token_.reset();
//     cached_access_token_mtime_.reset();
//     return std::nullopt;
//   }

//   token = token.substr(first, last - first + 1);
//   cached_access_token_ = token;
//   if (!ec) {
//     cached_access_token_mtime_ = mtime;
//   } else {
//     cached_access_token_mtime_.reset();
//   }
//   return cached_access_token_;
// }

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
  // if (customized_)
  //   copy_handler->customize(runtime_dir_, resource_materializer_factory_);

  // First perform copy actions
  return copy_handler->apply(config, target_ob_type, target_ob_id)
      .then([this, copy_handler, &config, &target_ob_type, target_ob_id]() {
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
        // if (customized_)
        //   exec_handler->customize(runtime_dir_,
        //   resource_materializer_factory_,
        //                           exec_env_resolver_factory_);
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
      .then([this, import_handler, &config, &target_ob_type, target_ob_id]() {
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
                << "To apply staged changes (including any cmd/cmd_argv "
                   "updates), run: cert-ctrl install-config apply"
                << std::endl;
            return ReturnIO::pure();
          }
          return apply_copy_actions(*config_ptr, std::nullopt, std::nullopt);
        });
  }

  if (signal.type == "cert.renewed") {
    if (auto typed = ::data::get_cert_renewed(signal)) {
      return ensure_cached_config().then([this, cert_id = typed->cert_id](
                                             auto config_ptr) {
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
InstallConfigManager::resolve_exec_env_for_item(const dto::InstallItem &item) {
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

std::optional<std::string>
InstallConfigManager::lookup_bundle_password(const std::string &ob_type,
                                             std::int64_t ob_id) const {
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

void InstallConfigManager::forget_bundle_password(const std::string &ob_type,
                                                  std::int64_t ob_id) {
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
