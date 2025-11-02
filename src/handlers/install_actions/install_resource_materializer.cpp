#include "handlers/install_actions/install_resource_materializer.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/system/error_code.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fmt/format.h>

#include "base64.h"
#include "http_client_monad.hpp"
#include "my_error_codes.hpp"
#include "openssl/crypt_util.hpp"
#include "openssl/openssl_raii.hpp"
#include "resource_fetcher.hpp"
#include "result_monad.hpp"
#include "util/secret_util.hpp"
#include "util/user_key_crypto.hpp"

namespace certctrl::install_actions {

using monad::Error;
using monad::Result;

namespace {

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
    if (!entry.is_string()) {
      continue;
    }
    if (!first) {
      oss << '\n';
    }
    oss << entry.as_string();
    first = false;
  }
  auto result = oss.str();
  if (result.empty()) {
    return std::nullopt;
  }
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
      if (text.empty()) {
        return std::nullopt;
      }
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

InstallResourceMaterializer::InstallResourceMaterializer(
    cjj365::IoContextManager &io_context_manager,       //
    certctrl::ICertctrlConfigProvider &config_provider, //
    customio::ConsoleOutput &output,                    //
    IResourceFetcher &resource_fetcher,                 //
    client_async::HttpClientManager &http_client,       //
    install_actions::IAccessTokenLoader &access_token_loader)
    : config_provider_(config_provider), output_(output),
      resource_fetcher_(resource_fetcher), http_client_(http_client),
      io_context_(io_context_manager.ioc()),
      runtime_dir_(config_provider.get().runtime_dir),
      access_token_loader_(access_token_loader) {}

InstallResourceMaterializer::~InstallResourceMaterializer() {}

// void InstallResourceMaterializer::customize(RuntimeConfig config) {
//   update_runtime_dir(std::move(config.runtime_dir));
//   update_access_token_loader(std::move(config.access_token_loader));
//   update_resource_fetch_override(std::move(config.resource_fetch_override));
//   update_bundle_hooks(std::move(config.bundle_lookup),
//                       std::move(config.bundle_remember),
//                       std::move(config.bundle_forget));
// }

// void InstallResourceMaterializer::update_runtime_dir(
//     std::filesystem::path runtime_dir) {
//   runtime_dir_ = std::move(runtime_dir);
// }

// void InstallResourceMaterializer::update_resource_fetch_override(
//     ResourceFetchOverrideFn fn) {
//   resource_fetch_override_ = std::move(fn);
// }

// void InstallResourceMaterializer::update_access_token_loader(
//     AccessTokenLoader loader) {
//   access_token_loader_ = std::move(loader);
// }

// void InstallResourceMaterializer::update_bundle_hooks(
//     BundlePasswordLookup lookup, BundlePasswordRemember remember,
//     BundlePasswordForget forget) {
//   bundle_lookup_ = std::move(lookup);
//   bundle_remember_ = std::move(remember);
//   bundle_forget_ = std::move(forget);
// }

monad::IO<void>
InstallResourceMaterializer::ensure_materialized(const dto::InstallItem &item) {
  return ensure_resource_materialized_impl(item);
}

std::filesystem::path InstallResourceMaterializer::state_dir() const {
  return runtime_dir_ / "state";
}

std::filesystem::path
InstallResourceMaterializer::resource_current_dir(const std::string &ob_type,
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

// std::optional<std::string>
// InstallResourceMaterializer::load_access_token() const {
//   if (!access_token_loader_) {
//     return std::nullopt;
//   }
//   return access_token_loader_();
// }

std::optional<std::string>
InstallResourceMaterializer::lookup_bundle_password(const std::string &ob_type,
                                                    std::int64_t ob_id) const {
  if (!bundle_lookup_) {
    return std::nullopt;
  }
  return bundle_lookup_(ob_type, ob_id);
}

void InstallResourceMaterializer::remember_bundle_password(
    const std::string &ob_type, std::int64_t ob_id,
    const std::string &password) {
  if (bundle_remember_) {
    bundle_remember_(ob_type, ob_id, password);
  }
}

void InstallResourceMaterializer::forget_bundle_password(
    const std::string &ob_type, std::int64_t ob_id) {
  if (bundle_forget_) {
    bundle_forget_(ob_type, ob_id);
  }
}

monad::IO<void> InstallResourceMaterializer::ensure_resource_materialized_impl(
    const dto::InstallItem &item) {
  using namespace std::chrono_literals;

  if (!item.ob_type || !item.ob_id) {
    return monad::IO<void>::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Resource reference missing ob_type/ob_id"));
  }

  auto state = std::make_shared<MaterializationData>();
  state->item = std::make_shared<dto::InstallItem>(item);
  state->ob_type = *item.ob_type;
  state->ob_id = *item.ob_id;
  state->is_cert = (state->ob_type == "cert");
  state->is_ca = (state->ob_type == "ca");
  state->current_dir = resource_current_dir(state->ob_type, state->ob_id);

  if (runtime_dir_.empty()) {
    return monad::IO<void>::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Runtime directory is not configured"));
  }

  bool all_present = true;
  bool bundle_requested = false;
  if (item.from) {
    for (const auto &virtual_name : *item.from) {
      if (!virtual_name.empty()) {
        if (virtual_name == "bundle.pfx") {
          bundle_requested = true;
        }
        if (!std::filesystem::exists(state->current_dir / virtual_name)) {
          all_present = false;
          break;
        }
      }
    }
  }

  if (all_present) {
    if (state->is_cert && bundle_requested &&
        !lookup_bundle_password(state->ob_type, state->ob_id)) {
      all_present = false;
    }
  }

  if (all_present) {
    return monad::IO<void>::pure();
  }

  // auto parse_enveloped_object =
  //     [](const std::string &raw, const char *context,
  //        boost::json::object &out) -> std::optional<monad::Error> {
  //   boost::system::error_code ec;
  //   auto parsed = boost::json::parse(raw, ec);
  //   if (ec || !parsed.is_object()) {
  //     return monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
  //                              fmt::format("{} response not a JSON object:
  //                              {}",
  //                                          context, ec ? ec.message() : ""));
  //   }
  //   auto &obj = parsed.as_object();
  //   if (auto *data = obj.if_contains("data")) {
  //     if (data->is_object()) {
  //       out = data->as_object();
  //       return std::nullopt;
  //     }
  //   }
  //   return monad::make_error(
  //       my_errors::GENERAL::UNEXPECTED_RESULT,
  //       fmt::format("{} response missing data object", context));
  // };

  auto get_string_field =
      [](const boost::json::object &obj,
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

  auto self = shared_from_this();
  // monad::IO<void> pipeline = monad::IO<void>::pure();

  // if (state->is_cert) {
  //   if (resource_fetch_override_) {
  //     auto override_body = resource_fetch_override_(item);
  //     if (!override_body) {
  //       return monad::IO<void>::fail(
  //           monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
  //                             "Resource fetch override returned empty
  //                             body"));
  //     }

  //     boost::system::error_code ec;
  //     auto parsed = boost::json::parse(*override_body, ec);
  //     if (ec || !parsed.is_object()) {
  //       return monad::IO<void>::fail(
  //           monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
  //                             "Override payload for cert is not an object"));
  //     }
  //     auto &obj = parsed.as_object();
  //     if (auto *deploy = obj.if_contains("deploy")) {
  //       if (deploy->is_object()) {
  //         state->deploy_obj = deploy->as_object();
  //         state->deploy_available = true;
  //       }
  //     }
  //     if (auto *detail = obj.if_contains("detail")) {
  //       if (detail->is_object()) {
  //         state->detail_obj = detail->as_object();
  //         state->detail_parsed = true;
  //       }
  //     }
  //     if (state->deploy_obj.empty() && obj.if_contains("data") &&
  //         obj["data"].is_object()) {
  //       state->deploy_obj = obj["data"].as_object();
  //       state->deploy_available = true;
  //     }
  //     if (state->detail_obj.empty() && obj.if_contains("certificate") &&
  //         obj["certificate"].is_object()) {
  //       state->detail_obj = obj["certificate"].as_object();
  //       state->detail_parsed = true;
  //     }
  //     if (state->detail_obj.empty()) {
  //       return monad::IO<void>::fail(monad::make_error(
  //           my_errors::GENERAL::UNEXPECTED_RESULT,
  //           "Override payload missing certificate detail object"));
  //     }

  //     state->detail_raw_json = boost::json::serialize(
  //         boost::json::object{{"data", state->detail_obj}});
  //     if (!state->deploy_obj.empty()) {
  //       state->deploy_raw_json = boost::json::serialize(
  //           boost::json::object{{"data", state->deploy_obj}});
  //     } else {
  //       boost::json::object placeholder;
  //       placeholder["note"] =
  //           "resource override missing deploy materials; generated locally";
  //       state->deploy_raw_json =
  //           boost::json::serialize(boost::json::object{{"data",
  //           placeholder}});
  //     }
  //     state->deploy_available = !state->deploy_obj.empty();
  //   } else {
  //     auto token_opt = load_access_token();
  //     if (!token_opt || token_opt->empty()) {
  //       auto err = monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
  //                                    "Device access token unavailable");
  //       BOOST_LOG_SEV(lg, trivial::error)
  //           << "ensure_resource_materialized_impl cert fetch missing token "
  //              "ob_id="
  //           << state->ob_id;
  //       return monad::IO<void>::fail(std::move(err));
  //     }

  //     const auto &cfg = config_provider_.get();
  //     std::string detail_url = fmt::format(
  //         "{}/apiv1/devices/self/certificates/{}", cfg.base_url,
  //         state->ob_id);
  //     std::string deploy_url =
  //         fmt::format("{}/apiv1/devices/self/certificates/{}/deploy-materials",
  //                     cfg.base_url, state->ob_id);
  //     auto token = *token_opt;

  //     pipeline = pipeline.then([self, state, detail_url, deploy_url, token,
  //                               parse_enveloped_object]() {
  //       return self->fetch_http_body(detail_url, token, "certificate detail")
  //           .map([state](std::string body) {
  //             state->detail_raw_json = std::move(body);
  //           })
  //           .then([self, state, deploy_url, token, parse_enveloped_object]()
  //           {
  //             return self
  //                 ->fetch_http_body(deploy_url, token, "deploy materials")
  //                 .map([state](std::string body) {
  //                   state->deploy_raw_json = std::move(body);
  //                   state->deploy_available = true;
  //                 })
  //                 .catch_then([state, self](monad::Error err) {
  //                   if (err.response_status == 404 ||
  //                       err.response_status == 204) {
  //                     state->deploy_available = false;
  //                     boost::json::object placeholder;
  //                     placeholder["note"] = "no deploy materials provided; "
  //                                           "generated locally by agent";
  //                     state->deploy_raw_json = boost::json::serialize(
  //                         boost::json::object{{"data", placeholder}});
  //                     self->output_.logger().info()
  //                         << "Deploy materials endpoint unavailable for cert
  //                         "
  //                         << state->ob_id << " (status=" <<
  //                         err.response_status
  //                         << "); falling back to certificate detail payload"
  //                         << std::endl;
  //                     return monad::IO<void>::pure();
  //                   }
  //                   return monad::IO<void>::fail(std::move(err));
  //                 })
  //                 .then([state, parse_enveloped_object]() {
  //                   auto detail_err = parse_enveloped_object(
  //                       state->detail_raw_json, "certificate detail",
  //                       state->detail_obj);
  //                   if (detail_err) {
  //                     return monad::IO<void>::fail(std::move(*detail_err));
  //                   }
  //                   state->detail_parsed = true;

  //                   if (!state->deploy_raw_json.empty()) {
  //                     boost::json::object deploy_obj;
  //                     auto deploy_err = parse_enveloped_object(
  //                         state->deploy_raw_json, "deploy materials",
  //                         deploy_obj);
  //                     if (deploy_err) {
  //                       return monad::IO<void>::fail(std::move(*deploy_err));
  //                     }
  //                     state->deploy_obj = std::move(deploy_obj);
  //                   }
  //                   return monad::IO<void>::pure();
  //                 });
  //           });
  //     });
  //   }
  // }

  // if (state->is_ca) {
  //   if (resource_fetch_override_) {
  //     auto override_body = resource_fetch_override_(item);
  //     if (!override_body) {
  //       auto err =
  //           monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
  //                             "Resource fetch override returned empty body");
  //       BOOST_LOG_SEV(lg, trivial::error)
  //           << "ensure_resource_materialized_impl CA override empty ob_id="
  //           << state->ob_id;
  //       return monad::IO<void>::fail(std::move(err));
  //     }
  //     state->ca_body = std::move(*override_body);
  //     auto bundle_data = parse_bundle_data(state->ca_body);
  //     if (!bundle_data) {
  //       auto err =
  //           monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
  //                             "CA bundle response missing expected data");
  //       BOOST_LOG_SEV(lg, trivial::error)
  //           << "ensure_resource_materialized_impl CA bundle parse failure "
  //              "ob_id="
  //           << state->ob_id;
  //       return monad::IO<void>::fail(std::move(err));
  //     }
  //     state->ca_obj = std::move(*bundle_data);
  //     state->ca_parsed = true;
  //   } else {
  //     auto token_opt = load_access_token();
  //     if (!token_opt || token_opt->empty()) {
  //       auto err = monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
  //                                    "Device access token unavailable");
  //       BOOST_LOG_SEV(lg, trivial::error)
  //           << "ensure_resource_materialized_impl CA fetch missing token
  //           ob_id="
  //           << state->ob_id;
  //       return monad::IO<void>::fail(std::move(err));
  //     }

  //     const auto &cfg = config_provider_.get();
  //     std::string url =
  //         fmt::format("{}/apiv1/devices/self/cas/{}/bundle?pack=download",
  //                     cfg.base_url, state->ob_id);
  //     auto token = *token_opt;

  //     pipeline = pipeline.then([self, state, url, token]() {
  //       return self->fetch_http_body(url, token, "ca bundle")
  //           .map(
  //               [state](std::string body) { state->ca_body = std::move(body);
  //               })
  //           .then([state]() {
  //             auto bundle_data = parse_bundle_data(state->ca_body);
  //             if (!bundle_data) {
  //               auto err = monad::make_error(
  //                   my_errors::GENERAL::UNEXPECTED_RESULT,
  //                   "CA bundle response missing expected data");
  //               return monad::IO<void>::fail(std::move(err));
  //             }
  //             state->ca_obj = std::move(*bundle_data);
  //             state->ca_parsed = true;
  //             return monad::IO<void>::pure();
  //           });
  //     });
  //   }
  // }
  auto pipeline = resource_fetcher_.fetch(access_token_loader_.load_token(), state);

  pipeline = pipeline.then([self, state, get_string_field, extract_pem,
                            decode_base64_string]() {
    try {
      std::filesystem::create_directories(state->current_dir);

      const auto &install_item = *state->item;

      if (install_item.from) {
        if (state->is_cert) {
          std::string decrypt_error;
          std::optional<std::string> private_key_pem;
          if (!state->deploy_obj.empty()) {
            private_key_pem =
                decrypt_private_key_pem(state->deploy_obj, self->runtime_dir_,
                                        self->state_dir(), decrypt_error);
          }

          std::string fallback_error;
          if (!private_key_pem) {
            private_key_pem = extract_private_key_from_detail(state->detail_obj,
                                                              fallback_error);
          }

          if (!private_key_pem) {
            std::string message = fmt::format(
                "Failed to materialize private key for cert {}", state->ob_id);
            if (!decrypt_error.empty()) {
              message += "; deploy materials: " + decrypt_error;
            }
            if (!fallback_error.empty()) {
              message += "; detail fallback: " + fallback_error;
            }
            return monad::IO<void>::fail(monad::make_error(
                my_errors::GENERAL::UNEXPECTED_RESULT, std::move(message)));
          }

          std::unordered_map<std::string, std::string> text_outputs;
          std::unordered_map<std::string, std::vector<unsigned char>>
              binary_outputs;

          text_outputs["private.key"] = *private_key_pem;

          const boost::json::object *detail_view = &state->detail_obj;
          if (auto *cert_node = state->detail_obj.if_contains("certificate")) {
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
            return monad::IO<void>::fail(monad::make_error(
                my_errors::GENERAL::UNEXPECTED_RESULT,
                fmt::format(
                    "Certificate detail missing PEM payload for cert {}",
                    state->ob_id)));
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
          if (auto fullchain_field =
                  extract_pem(*detail_view, "fullchain_pem")) {
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
          if (install_item.from) {
            chain_required =
                std::find(install_item.from->begin(), install_item.from->end(),
                          std::string("chain.pem")) != install_item.from->end();
          }
          if (chain_required && chain_pem.empty()) {
            chain_pem = leaf_pem;
          }

          text_outputs["certificate.pem"] = leaf_pem;
          if (!chain_pem.empty()) {
            text_outputs["chain.pem"] = chain_pem;
          }
          text_outputs["fullchain.pem"] = fullchain_pem;

          if (binary_outputs.find("certificate.der") == binary_outputs.end()) {
            std::vector<unsigned char> der_bytes;
            if (cjj365::opensslutil::convert_pem_string_to_der(leaf_pem,
                                                               der_bytes)) {
              binary_outputs["certificate.der"] = std::move(der_bytes);
            }
          }

          if (binary_outputs.find("bundle.pfx") == binary_outputs.end()) {
            try {
              auto pkey = cjj365::opensslutil::load_private_key(
                  *private_key_pem, false);
              if (!pkey) {
                return monad::IO<void>::fail(monad::make_error(
                    my_errors::GENERAL::UNEXPECTED_RESULT,
                    "Failed to load private key for PKCS#12 generation"));
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
              } else if (auto name =
                             state->detail_obj.if_contains("domain_name")) {
                if (name->is_string() && !name->as_string().empty()) {
                  alias = std::string(name->as_string().c_str());
                }
              }

              std::string pfx_password;
              if (auto existing = self->lookup_bundle_password(state->ob_type,
                                                               state->ob_id)) {
                pfx_password = *existing;
              } else {
                pfx_password = cjj365::cryptutil::generateApiSecret(40);
              }

              std::string pkcs12 = cjj365::opensslutil::create_pkcs12_string(
                  pkey, pfx_chain, alias, pfx_password);
              binary_outputs["bundle.pfx"] =
                  std::vector<unsigned char>(pkcs12.begin(), pkcs12.end());
              self->remember_bundle_password(state->ob_type, state->ob_id,
                                             pfx_password);
            } catch (const std::exception &ex) {
              return monad::IO<void>::fail(monad::make_error(
                  my_errors::GENERAL::UNEXPECTED_RESULT,
                  fmt::format("Failed to create PKCS#12 bundle: {}",
                              ex.what())));
            }
          }

          if (binary_outputs.find("certificate.der") == binary_outputs.end()) {
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
                self->forget_bundle_password(state->ob_type, state->ob_id);
              }
            } else if (auto *pfx_val = detail_view->if_contains("pkcs12_b64")) {
              if (auto bytes = decode_base64_to_bytes(*pfx_val)) {
                binary_outputs["bundle.pfx"] = std::move(*bytes);
                self->forget_bundle_password(state->ob_type, state->ob_id);
              }
            }
          }

          boost::json::object meta_root;
          meta_root["certificate"] = state->detail_obj;
          meta_root["deploy_materials"] = state->deploy_obj;
          text_outputs["meta.json"] = boost::json::serialize(meta_root);

          auto raw_path = state->current_dir.parent_path() / "bundle_raw.json";
          {
            std::ofstream ofs(raw_path, std::ios::binary | std::ios::trunc);
            ofs << state->deploy_raw_json;
          }

          auto detail_dump =
              state->current_dir.parent_path() / "certificate_detail.json";
          {
            std::ofstream ofs(detail_dump, std::ios::binary | std::ios::trunc);
            ofs << state->detail_raw_json;
          }

          std::vector<std::string> missing;
          for (const auto &virtual_name : *install_item.from) {
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
            return monad::IO<void>::fail(monad::make_error(
                my_errors::GENERAL::UNEXPECTED_RESULT, oss.str()));
          }

          for (const auto &virtual_name : *install_item.from) {
            if (virtual_name.empty()) {
              continue;
            }
            auto file_path = state->current_dir / virtual_name;
            if (auto binary_it = binary_outputs.find(virtual_name);
                binary_it != binary_outputs.end()) {
              std::ofstream ofs(file_path, std::ios::binary | std::ios::trunc);
              ofs.write(
                  reinterpret_cast<const char *>(binary_it->second.data()),
                  static_cast<std::streamsize>(binary_it->second.size()));
            } else if (auto text_it = text_outputs.find(virtual_name);
                       text_it != text_outputs.end()) {
              std::ofstream ofs(file_path, std::ios::binary | std::ios::trunc);
              ofs << text_it->second;
            }
          }

          self->output_.logger().debug()
              << "Fetched resource " << state->ob_type << "/" << state->ob_id
              << " (materials cached)" << std::endl;
          BOOST_LOG_SEV(self->lg, trivial::trace)
              << "ensure_resource_materialized complete ob_type="
              << state->ob_type << " ob_id=" << state->ob_id;
        } else if (state->is_ca) {
          std::unordered_map<std::string, std::string> text_outputs;
          std::unordered_map<std::string, std::vector<unsigned char>>
              binary_outputs;

          if (auto *pem = state->ca_obj.if_contains("ca_certificate_pem")) {
            text_outputs["ca.pem"] = boost::json::value_to<std::string>(*pem);
          }
          if (auto *der = state->ca_obj.if_contains("ca_certificate_der_b64")) {
            if (auto bytes = decode_base64_to_bytes(*der)) {
              binary_outputs["ca.der"] = std::move(*bytes);
            }
          }
          boost::json::object meta_root;
          meta_root["ca_bundle"] = state->ca_obj;
          text_outputs["meta.json"] = boost::json::serialize(meta_root);

          auto raw_path = state->current_dir.parent_path() / "bundle_raw.json";
          {
            std::ofstream ofs(raw_path, std::ios::binary | std::ios::trunc);
            ofs << state->ca_body;
          }

          for (const auto &virtual_name : *install_item.from) {
            if (virtual_name.empty()) {
              continue;
            }
            auto file_path = state->current_dir / virtual_name;
            if (auto binary_it = binary_outputs.find(virtual_name);
                binary_it != binary_outputs.end()) {
              std::ofstream ofs(file_path, std::ios::binary | std::ios::trunc);
              ofs.write(
                  reinterpret_cast<const char *>(binary_it->second.data()),
                  static_cast<std::streamsize>(binary_it->second.size()));
            } else if (auto text_it = text_outputs.find(virtual_name);
                       text_it != text_outputs.end()) {
              std::ofstream ofs(file_path, std::ios::binary | std::ios::trunc);
              ofs << text_it->second;
            }
          }

          self->output_.logger().debug()
              << "Fetched resource " << state->ob_type << "/" << state->ob_id
              << " (materials cached)" << std::endl;
          BOOST_LOG_SEV(self->lg, trivial::trace)
              << "ensure_resource_materialized complete ob_type="
              << state->ob_type << " ob_id=" << state->ob_id;
        } else {
          return monad::IO<void>::fail(monad::make_error(
              my_errors::GENERAL::INVALID_ARGUMENT,
              fmt::format("Unsupported ob_type '{}'", state->ob_type)));
        }
      }
    } catch (const std::exception &e) {
      BOOST_LOG_SEV(self->lg, trivial::error)
          << "Failed to write resource materials ob_type=" << state->ob_type
          << " ob_id=" << state->ob_id << " error=" << e.what();
      return monad::IO<void>::fail(
          monad::make_error(my_errors::GENERAL::FILE_READ_WRITE, e.what()));
    }

    return monad::IO<void>::pure();
  });

  return pipeline;
}

// boost::asio::io_context &InstallResourceMaterializer::ensure_io_context() {
//   if (!io_context_) {
//     owned_io_context_ = std::make_unique<boost::asio::io_context>();
//     owned_io_work_guard_ = std::make_unique<boost::asio::executor_work_guard<
//         boost::asio::io_context::executor_type>>(
//         boost::asio::make_work_guard(*owned_io_context_));
//     io_context_ = owned_io_context_.get();
//     owned_io_thread_ = std::thread([ctx = io_context_]() {
//       if (!ctx) {
//         return;
//       }
//       ctx->run();
//     });
//   }
//   return *io_context_;
// }

monad::IO<std::string>
InstallResourceMaterializer::fetch_http_body(const std::string &url,
                                             const std::string &token,
                                             const char *context_label) {
  using monad::GetStringTag;
  using monad::http_io;
  using monad::http_request_io;
  using ExchangePtr = monad::ExchangePtrFor<GetStringTag>;

  namespace http = boost::beast::http;

  constexpr int kMaxAttempts = 12;
  constexpr std::chrono::seconds kRetryBaseDelay{3};

  auto attempt_counter = std::make_shared<int>(0);

  auto fetch_once =
      http_io<GetStringTag>(url)
          .map([this, attempt_counter, token, url, context_label](auto ex) {
            const int current_attempt = ++(*attempt_counter);
            BOOST_LOG_SEV(lg, trivial::trace)
                << "fetch_http_body attempt " << current_attempt << '/'
                << kMaxAttempts << " for url=" << url
                << " context=" << context_label;
            ex->request.set(http::field::authorization,
                            std::string("Bearer ") + token);
            return ex;
          })
          .then(http_request_io<GetStringTag>(http_client_))
          .then([this, url, context_label,
                 attempt_counter](ExchangePtr ex) -> monad::IO<std::string> {
            if (!ex->response.has_value()) {
              BOOST_LOG_SEV(lg, trivial::warning)
                  << "fetch_http_body received empty response for url=" << url
                  << " context=" << context_label;
              return monad::IO<std::string>::fail(
                  monad::make_error(my_errors::NETWORK::READ_ERROR,
                                    "No response while fetching resource"));
            }

            int status = ex->response->result_int();
            std::string body = ex->response->body();

            if (status == 200) {
              BOOST_LOG_SEV(lg, trivial::trace)
                  << "fetch_http_body succeeded for url=" << url
                  << " context=" << context_label
                  << " (status=200, bytes=" << body.size() << ')';
              return monad::IO<std::string>::pure(std::move(body));
            }

            auto err = monad::make_error(
                my_errors::NETWORK::READ_ERROR,
                fmt::format("Resource fetch HTTP {}", status));
            err.response_status = status;
            err.params["response_body_preview"] = body.substr(0, 512);

            if (status == 503) {
              BOOST_LOG_SEV(lg, trivial::warning)
                  << "fetch_http_body retry for url=" << url
                  << " context=" << context_label
                  << " attempt=" << *attempt_counter;
            } else {
              BOOST_LOG_SEV(lg, trivial::warning)
                  << "fetch_http_body aborting status=" << status
                  << " url=" << url << " context=" << context_label;
            }

            return monad::IO<std::string>::fail(std::move(err));
          });

  auto should_retry = [attempt_counter](const monad::Error &err) {
    return err.response_status == 503 && *attempt_counter < kMaxAttempts;
  };

  return std::move(fetch_once)
      .retry_exponential_if(kMaxAttempts, kRetryBaseDelay, io_context_,
                            should_retry);
}

} // namespace certctrl::install_actions
