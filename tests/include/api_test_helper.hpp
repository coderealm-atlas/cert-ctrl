#pragma once

#include <boost/json.hpp>
#include <array>
#include <cctype>
#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "http_client_manager.hpp"
#include "http_client_monad.hpp"
#include "login_helper.hpp"
#include "base64.h"

// High-level test helpers for creating and managing API resources
// Uses the real API endpoints per HTTP_API_REFERENCE.md

namespace testutil {
namespace json = boost::json;
namespace http = boost::beast::http;

// ============================================================================
// Self-CA helpers
// ============================================================================

struct SelfCAInfo {
  int64_t id{};
  std::string name;
  std::string cert;
};

// Create self-CA - needed for self-signed certificates
// Per HTTP_API_REFERENCE.md example: POST /apiv1/users/:user_id/cas
inline monad::IO<SelfCAInfo> create_self_ca_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    const std::string &name = "test-ca",
    const std::string &common_name = "Test Root CA",
    const std::string &org = "Test Org",
    const std::string &country = "CN") {
  
  using CAInfoIO = monad::IO<SelfCAInfo>;
  
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + "/cas";
  
  return http_io<monad::PostJsonTag>(url)
      .map([=](auto ex) {
        json::object body{
            {"name", name},
            {"algorithm", "ECDSA"},
            {"key_size", 256},
            {"curve_name", "prime256v1"},
            {"country", country},
            {"organization", org},
            {"organizational_unit", ""},
            {"common_name", common_name},
            {"state", ""},
            {"locality", ""},
            {"valid_days", 3650},
            {"max_path_length", 0},
            {"key_usage", "keyCertSign,cRLSign"}
        };
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::PostJsonTag>(mgr))
      .then([](auto ex) {
        log_http_response("create_self_ca_io", ex);
        return CAInfoIO::from_result(
            ex->template parseJsonDataResponse<json::object>()
                .map([](json::object obj) {
                  SelfCAInfo ca;
                  ca.id = obj.at("id").as_int64();
                  ca.name = obj.at("name").as_string().c_str();
                  if (obj.contains("ca_certificate_pem") && !obj.at("ca_certificate_pem").is_null()) {
                    ca.cert = obj.at("ca_certificate_pem").as_string().c_str();
                  }
                  return ca;
                })
        );
      });
}

inline monad::IO<void> delete_self_ca_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    int64_t ca_id) {
  
  using VoidIO = monad::IO<void>;
  
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + 
                    "/cas/" + std::to_string(ca_id);
  
  return http_io<monad::DeleteTag>(url)
      .map([cookie](auto ex) {
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::DeleteTag>(mgr))
      .then([](auto ex) {
        log_http_response("delete_self_ca_io", ex);
        if (ex->response->result() == http::status::ok || 
            ex->response->result() == http::status::no_content) {
          return VoidIO::from_result(monad::MyVoidResult::Ok());
        }
        return VoidIO::from_result(monad::MyVoidResult::Err(
            monad::Error{static_cast<int>(ex->response->result()), 
                        "Failed to delete self-CA"}));
      });
}

// ============================================================================
// ACME Account helpers
// ============================================================================

struct AcmeAccountInfo {
  int64_t id{};
  int64_t user_id{};
  std::string name;
  std::string email;
  std::string provider;
  int64_t ca_id{};
};

// Create ACME account - this is step 1 for certificate workflow
// If ca_id > 0, creates account linked to self-CA for immediate issuance
inline monad::IO<AcmeAccountInfo> create_acme_account_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    const std::string &name = "test-acct",
    const std::string &email = "test@example.com",
    const std::string &provider = "letsencrypt",
    int64_t ca_id = 0) {
  
  using AcctIO = monad::IO<AcmeAccountInfo>;
  
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + "/acme-accounts";
  
  return http_io<monad::PostJsonTag>(url)
      .map([=](auto ex) {
        std::string provider_val = provider;
        if (ca_id > 0) {
          // When linking to a user-owned CA, use the SELF_CA provider by default
          provider_val = "SELF_CA";
        }
        json::object body{
            {"name", name},
            {"email", email},
            {"provider", provider_val}
        };
        // Only include ca-specific fields when linking to a self-CA
        if (ca_id > 0) {
          body["ca_id"] = ca_id;
          body["cert_valid_seconds"] = 315360000;
          body["leaf_key_algorithm"] = "ECDSA";
          body["leaf_ec_curve"] = "prime256v1";
        }
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::PostJsonTag>(mgr))
      .then([](auto ex) {
        log_http_response("create_acme_account_io", ex);
        return AcctIO::from_result(
            ex->template parseJsonDataResponse<json::object>()
                .map([](json::object obj) {
                  AcmeAccountInfo acct;
                  acct.id = obj.at("id").as_int64();
                  if (obj.contains("user_id")) {
                    acct.user_id = obj.at("user_id").as_int64();
                  }
                  acct.name = obj.at("name").as_string().c_str();
                  acct.email = obj.at("email").as_string().c_str();
                  acct.provider = obj.at("provider").as_string().c_str();
                  if (obj.contains("ca_id") && !obj.at("ca_id").is_null()) {
                    acct.ca_id = obj.at("ca_id").as_int64();
                  }
                  return acct;
                })
        );
      });
}

inline monad::IO<void> delete_acme_account_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    int64_t acct_id) {
  
  using VoidIO = monad::IO<void>;
  
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + 
                    "/acme-accounts/" + std::to_string(acct_id);
  
  return http_io<monad::DeleteTag>(url)
      .map([cookie](auto ex) {
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::DeleteTag>(mgr))
      .then([](auto ex) {
        log_http_response("delete_acme_account_io", ex);
        if (ex->response->result() == http::status::ok || 
            ex->response->result() == http::status::no_content) {
          return VoidIO::from_result(monad::MyVoidResult::Ok());
        }
        return VoidIO::from_result(monad::MyVoidResult::Err(
            monad::Error{static_cast<int>(ex->response->result()), 
                        "Failed to delete ACME account"}));
      });
}

// ============================================================================
// Certificate helpers
// ============================================================================

struct CertInfo {
  int64_t id{};
  int64_t user_id{};
  std::string domain_name;
  std::vector<std::string> sans;
  bool verified{};
  std::string serial_number;
};

// Create certificate record - step 2: Create the certificate entry
// Per HTTP_API_REFERENCE.md: POST /apiv1/users/:user_id/certificates (not under acme-accounts)
inline monad::IO<CertInfo> create_cert_record_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    int64_t acct_id,
    const std::string &domain_name,
    const std::vector<std::string> &sans = {}) {
  
  using CertIO = monad::IO<CertInfo>;
  
  // POST /apiv1/users/:user_id/certificates (body includes acct_id)
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + "/certificates";
  
  return http_io<monad::PostJsonTag>(url)
      .map([=](auto ex) {
        json::array sans_array;
        for (const auto &san : sans) {
          sans_array.push_back(json::value(san));
        }
        
        json::object body{
            {"domain_name", domain_name},
            {"sans", sans_array},
            {"acct_id", acct_id},
            {"action", "create"},
            {"organization", "Test Org"},
            {"organizational_unit", "IT"},
            {"country", "US"},
            {"state", "CA"},
            {"locality", "San Jose"}
        };
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::PostJsonTag>(mgr))
      .then([](auto ex) {
        log_http_response("create_cert_record_io", ex);
        return CertIO::from_result(
            ex->template parseJsonDataResponse<json::object>()
                .map([](json::object obj) {
                  CertInfo cert;
                  cert.id = obj.at("id").as_int64();
                  if (obj.contains("user_id")) {
                    cert.user_id = obj.at("user_id").as_int64();
                  }
                  cert.domain_name = obj.at("domain_name").as_string().c_str();
                  cert.verified = obj.contains("verified") ? 
                                  obj.at("verified").as_bool() : false;
                  if (obj.contains("serial_number")) {
                    cert.serial_number = obj.at("serial_number").as_string().c_str();
                  }
                  if (obj.contains("sans") && obj.at("sans").is_array()) {
                    for (const auto &san : obj.at("sans").as_array()) {
                      cert.sans.push_back(san.as_string().c_str());
                    }
                  }
                  return cert;
                })
        );
      });
}

// Issue certificate - step 3: Actually issue/sign the certificate
inline monad::IO<CertInfo> issue_cert_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    int64_t cert_id,
    int validity_seconds = 7776000) {
  
  using CertIO = monad::IO<CertInfo>;
  
  // POST /apiv1/users/:user_id/certificates/:certificate_id/issues
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + 
                    "/certificates/" + std::to_string(cert_id) + "/issues";
  
  return http_io<monad::PostJsonTag>(url)
      .map([=](auto ex) {
        json::object body{{"validity_seconds", validity_seconds}};
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::PostJsonTag>(mgr))
      .then([](auto ex) -> CertIO {
        log_http_response("issue_cert_io", ex);
        // For self-CA, returns 200 with data immediately
        // For public ACME, returns 204 (async processing)
        if (ex->response->result() == http::status::no_content) {
          // Async issuance - return empty cert (processing async)
          return CertIO::from_result(
              monad::MyResult<CertInfo>::Ok(CertInfo{}));
        }
        return CertIO::from_result(
            ex->template parseJsonDataResponse<json::object>()
                .map([](json::object obj) {
                  CertInfo cert;
                  cert.id = obj.at("id").as_int64();
                  if (obj.contains("user_id")) {
                    cert.user_id = obj.at("user_id").as_int64();
                  }
                  cert.domain_name = obj.at("domain_name").as_string().c_str();
                  cert.verified = obj.contains("verified") ? 
                                  obj.at("verified").as_bool() : false;
                  if (obj.contains("serial_number")) {
                    cert.serial_number = obj.at("serial_number").as_string().c_str();
                  }
                  if (obj.contains("sans") && obj.at("sans").is_array()) {
                    for (const auto &san : obj.at("sans").as_array()) {
                      cert.sans.push_back(san.as_string().c_str());
                    }
                  }
                  return cert;
                })
        );
      });
}

inline monad::IO<void> delete_cert_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    int64_t cert_id) {
  
  using VoidIO = monad::IO<void>;
  
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + 
                    "/certificates/" + std::to_string(cert_id);
  
  return http_io<monad::DeleteTag>(url)
      .map([cookie](auto ex) {
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::DeleteTag>(mgr))
      .then([](auto ex) {
        log_http_response("delete_cert_io", ex);
        if (ex->response->result() == http::status::ok || 
            ex->response->result() == http::status::no_content) {
          return VoidIO::from_result(monad::MyVoidResult::Ok());
        }
        return VoidIO::from_result(monad::MyVoidResult::Err(
            monad::Error{static_cast<int>(ex->response->result()), 
                        "Failed to delete certificate"}));
      });
}

// ============================================================================
// Device helpers
// ============================================================================

struct DeviceInfo {
  int64_t id{};
  int64_t user_id{};
  std::string name;
  std::string fingerprint;
};

// ============================================================================
// API key helpers
// ============================================================================

struct ApiKeyCreateOptions {
  std::string name{"device-apikey"};
  std::string permission_obtype{"ForDeviceAuthenticate"};
  std::string permission_obid{"*"};
  std::vector<std::string> actions{"authenticate", "validate", "revoke"};
  int64_t expires_in_seconds{2592000};
};

struct ApiKeyInfo {
  int64_t id{};
  std::string name;
  std::string token;
  std::vector<std::string> actions;
  std::string permission_obtype;
  std::string permission_obid;
  int64_t expires_in_seconds{0};
};

inline std::string trim_copy(std::string value) {
  auto is_ws = [](unsigned char ch) { return static_cast<bool>(std::isspace(ch)); };
  while (!value.empty() && is_ws(static_cast<unsigned char>(value.back()))) {
    value.pop_back();
  }
  size_t start = 0;
  while (start < value.size() && is_ws(static_cast<unsigned char>(value[start]))) {
    ++start;
  }
  if (start > 0) {
    value.erase(0, start);
  }
  return value;
}

inline std::vector<std::string> split_actions_csv(const std::string &csv) {
  std::vector<std::string> actions;
  std::stringstream ss(csv);
  std::string item;
  while (std::getline(ss, item, ',')) {
    auto trimmed = trim_copy(item);
    if (!trimmed.empty()) {
      actions.push_back(std::move(trimmed));
    }
  }
  return actions;
}

inline ApiKeyCreateOptions default_api_key_options() {
  ApiKeyCreateOptions opts;

  if (auto env_name = read_trimmed_env("API_KEY_NAME")) {
    opts.name = *env_name;
  }
  if (auto env_obtype = read_trimmed_env("API_KEY_PERMISSION_OBTYPE")) {
    opts.permission_obtype = *env_obtype;
  }
  if (auto env_obid = read_trimmed_env("API_KEY_PERMISSION_OBID")) {
    opts.permission_obid = *env_obid;
  }
  if (auto env_actions = read_trimmed_env("API_KEY_ACTIONS")) {
    auto parsed = split_actions_csv(*env_actions);
    if (!parsed.empty()) {
      opts.actions = std::move(parsed);
    }
  }
  if (auto env_expires = read_trimmed_env("API_KEY_EXPIRES_SECONDS")) {
    try {
      opts.expires_in_seconds = std::stoll(*env_expires);
    } catch (...) {
      // ignore invalid overrides
    }
  }

  if (opts.name.empty()) {
    opts.name = "device-apikey";
  }
  if (opts.actions.empty()) {
    opts.actions = {"authenticate", "validate", "revoke"};
  }
  if (opts.expires_in_seconds <= 0) {
    opts.expires_in_seconds = 2592000;
  }

  return opts;
}

inline monad::IO<ApiKeyInfo> create_api_key_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    ApiKeyCreateOptions options = default_api_key_options()) {

  using ApiKeyIO = monad::IO<ApiKeyInfo>;

  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + "/apikeys";

  return http_io<monad::PostJsonTag>(url)
      .map([=](auto ex) mutable {
        json::array actions_array;
        for (const auto &action : options.actions) {
          actions_array.push_back(json::value(action));
        }

        json::object permission{{"obtype", options.permission_obtype},
                                {"obid", options.permission_obid},
                                {"actions", std::move(actions_array)}};
        json::array permissions;
        permissions.push_back(permission);

        json::object body{{"name", options.name},
                          {"permissions", std::move(permissions)},
                          {"expires_in_seconds", options.expires_in_seconds}};

        std::cout << "[create_api_key_io] POST " << url
                  << " body=" << json::serialize(body) << std::endl;
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::PostJsonTag>(mgr))
      .then([options](auto ex) mutable {
        log_http_response("create_api_key_io", ex);
        return ApiKeyIO::from_result(
            ex->template parseJsonDataResponse<json::object>()
                .map([options = std::move(options)](json::object obj) {
                  ApiKeyInfo info;
                  info.actions = options.actions;
                  info.permission_obtype = options.permission_obtype;
                  info.permission_obid = options.permission_obid;
                  info.expires_in_seconds = options.expires_in_seconds;

                  if (auto *id_val = obj.if_contains("id"); id_val && id_val->is_int64()) {
                    info.id = id_val->as_int64();
                  }
                  if (auto *name_val = obj.if_contains("name"); name_val && name_val->is_string()) {
                    info.name = std::string(name_val->as_string().c_str());
                  } else {
                    info.name = options.name;
                  }
                  if (auto *token_val = obj.if_contains("token"); token_val && token_val->is_string()) {
                    info.token = std::string(token_val->as_string().c_str());
                  }
                  if (auto *expires_val = obj.if_contains("expires_in_seconds");
                      expires_val && expires_val->is_int64()) {
                    info.expires_in_seconds = expires_val->as_int64();
                  }
                  if (info.token.empty()) {
                    throw std::runtime_error("API key response missing token");
                  }
                  return info;
                }));
      });
}

inline monad::IO<void> delete_api_key_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    int64_t api_key_id) {

  using VoidIO = monad::IO<void>;

  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) +
                    "/apikeys/" + std::to_string(api_key_id);

  return http_io<monad::DeleteTag>(url)
      .map([cookie](auto ex) {
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::DeleteTag>(mgr))
      .then([](auto ex) {
        log_http_response("delete_api_key_io", ex);
        const auto status = ex->response->result();
        if (status == http::status::ok || status == http::status::no_content) {
          return VoidIO::from_result(monad::MyVoidResult::Ok());
        }
        return VoidIO::from_result(monad::MyVoidResult::Err(
            monad::Error{static_cast<int>(status), "Failed to delete API key"}));
      });
}

// ============================================================================
// API key device registration helpers
// ============================================================================

struct DeviceRegistrationRequest {
  std::string device_public_id;
  std::string device_public_key_b64;
  std::string platform;
  std::string model;
  std::string app_version;
  std::string name;
  std::string ip;
  std::string user_agent;
};

struct DeviceRegistrationResult {
  std::optional<int64_t> device_id;
  std::string device_public_id;
  std::string device_name;
  std::string access_token;
  std::optional<std::string> refresh_token;
  json::object raw_payload;
};

inline std::string random_uuid_v4() {
  std::array<unsigned char, 16> bytes{};
  std::random_device rd;
  for (auto &b : bytes) {
    b = static_cast<unsigned char>(rd());
  }
  bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0F) | 0x40);
  bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3F) | 0x80);

  constexpr char hex[] = "0123456789abcdef";
  std::string uuid(36, '-');
  size_t out = 0;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      ++out;
    }
    uuid[out++] = hex[(bytes[i] >> 4) & 0x0F];
    uuid[out++] = hex[bytes[i] & 0x0F];
  }
  return uuid;
}

inline std::string random_device_key_b64(size_t size = 32) {
  std::vector<unsigned char> bytes(size);
  std::random_device rd;
  for (auto &b : bytes) {
    b = static_cast<unsigned char>(rd());
  }
  return base64_encode(bytes.data(), bytes.size());
}

inline std::string detect_default_platform() {
#if defined(_WIN32)
  return "windows";
#elif defined(__APPLE__)
  return "darwin";
#elif defined(__linux__)
  return "linux";
#else
  return "unknown";
#endif
}

inline std::string detect_default_model() {
#if defined(_WIN32)
  return "x86_64";
#elif defined(__APPLE__)
  return "arm64";
#elif defined(__linux__)
  return "x86_64";
#else
  return "generic";
#endif
}

inline DeviceRegistrationRequest make_device_registration_request(
    std::string name_prefix = "API Key Device") {
  auto env_prefix = read_trimmed_env("DEVICE_NAME_PREFIX");
  if (env_prefix && !env_prefix->empty()) {
    name_prefix = *env_prefix;
  }

  auto now = std::chrono::system_clock::now().time_since_epoch();
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now).count();

  DeviceRegistrationRequest req;
  req.device_public_id = random_uuid_v4();
  req.device_public_key_b64 = random_device_key_b64();

  auto platform = read_trimmed_env("DEVICE_PLATFORM_OVERRIDE");
  req.platform = platform && !platform->empty() ? *platform : detect_default_platform();

  auto model = read_trimmed_env("DEVICE_MODEL_OVERRIDE");
  req.model = model && !model->empty() ? *model : detect_default_model();

  auto app_version = read_trimmed_env("DEVICE_APP_VERSION");
  req.app_version = app_version && !app_version->empty() ? *app_version : "1.0.0";

  req.name = name_prefix + " " + std::to_string(seconds);

  auto ip_override = read_trimmed_env("DEVICE_IP_OVERRIDE");
  req.ip = ip_override && !ip_override->empty() ? *ip_override : "127.0.0.1";

  auto user_agent = read_trimmed_env("DEVICE_USER_AGENT");
  req.user_agent = user_agent && !user_agent->empty() ? *user_agent : "ApiKeyDeviceClient/1.0";

  return req;
}

inline monad::IO<DeviceRegistrationResult> register_device_with_apikey_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    int64_t user_id,
    const std::string &api_key_token,
    const DeviceRegistrationRequest &request) {

  using DeviceIO = monad::IO<DeviceRegistrationResult>;

  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + "/devices";

  auto request_ptr = std::make_shared<DeviceRegistrationRequest>(request);

  return http_io<monad::PostJsonTag>(url)
      .map([request_ptr, api_key_token, url](auto ex) {
        const auto &req = *request_ptr;
        json::object body{{"device_public_id", req.device_public_id},
                          {"dev_pk", req.device_public_key_b64},
                          {"platform", req.platform},
                          {"model", req.model},
                          {"app_version", req.app_version},
                          {"name", req.name},
                          {"ip", req.ip},
                          {"user_agent", req.user_agent}};

        std::cout << "[register_device_with_apikey_io] POST " << url
                  << " body=" << json::serialize(body) << std::endl;
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::authorization, "Bearer " + api_key_token);
        return ex;
      })
      .then(http_request_io<monad::PostJsonTag>(mgr))
      .then([request_ptr](auto ex) {
        log_http_response("register_device_with_apikey_io", ex);
        auto data_result = ex->template parseJsonDataResponse<json::object>();
        if (data_result.is_err()) {
          return DeviceIO::from_result(
              monad::MyResult<DeviceRegistrationResult>::Err(data_result.error()));
        }

        const auto &req = *request_ptr;
        const auto &obj = data_result.value();

        DeviceRegistrationResult result;
        result.device_public_id = req.device_public_id;
        result.device_name = req.name;
        result.raw_payload = obj;

        auto extract_device = [&]() {
          if (auto *device = obj.if_contains("device"); device && device->is_object()) {
            const auto &dev_obj = device->as_object();
            if (auto *id_val = dev_obj.if_contains("id"); id_val && id_val->is_int64()) {
              result.device_id = id_val->as_int64();
            }
            if (auto *public_id = dev_obj.if_contains("device_public_id");
                public_id && public_id->is_string()) {
              result.device_public_id = std::string(public_id->as_string().c_str());
            }
            if (auto *name_val = dev_obj.if_contains("name"); name_val && name_val->is_string()) {
              result.device_name = std::string(name_val->as_string().c_str());
            }
          }
        };

        extract_device();

        auto extract_session = [&]() -> monad::MyResult<void> {
          const auto try_session = [&](const json::object &session_obj) -> monad::MyResult<void> {
            if (auto *access = session_obj.if_contains("access_token"); access && access->is_string()) {
              result.access_token = std::string(access->as_string().c_str());
            }
            if (auto *refresh = session_obj.if_contains("refresh_token"); refresh && refresh->is_string()) {
              result.refresh_token = std::string(refresh->as_string().c_str());
            }
            return monad::MyResult<void>::Ok();
          };

          if (auto *session = obj.if_contains("session"); session && session->is_object()) {
            return try_session(session->as_object());
          }
          if (auto *tokens = obj.if_contains("tokens"); tokens && tokens->is_object()) {
            return try_session(tokens->as_object());
          }
          if (auto *access = obj.if_contains("access_token"); access && access->is_string()) {
            result.access_token = std::string(access->as_string().c_str());
            if (auto *refresh = obj.if_contains("refresh_token"); refresh && refresh->is_string()) {
              result.refresh_token = std::string(refresh->as_string().c_str());
            }
            return monad::MyResult<void>::Ok();
          }
          return monad::MyResult<void>::Err(
              monad::Error{500, "Device registration response missing session tokens"});
        };

        auto session_result = extract_session();
        if (session_result.is_err()) {
          return DeviceIO::from_result(
              monad::MyResult<DeviceRegistrationResult>::Err(session_result.error()));
        }

        if (result.access_token.empty()) {
          return DeviceIO::from_result(
              monad::MyResult<DeviceRegistrationResult>::Err(
                  monad::Error{500, "Device registration response missing access token"}));
        }

        return DeviceIO::from_result(
            monad::MyResult<DeviceRegistrationResult>::Ok(std::move(result)));
      });
}

inline monad::IO<json::array> list_devices_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id) {
  
  using DeviceListIO = monad::IO<json::array>;
  
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + "/devices";
  
  return http_io<monad::GetStringTag>(url)
      .map([cookie](auto ex) {
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::GetStringTag>(mgr))
      .then([](auto ex) {
        log_http_response("list_devices_io", ex);
        return DeviceListIO::from_result(
            ex->template parseJsonDataResponse<json::array>()
        );
      });
}

inline monad::IO<void> delete_device_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    int64_t device_id) {
  
  using VoidIO = monad::IO<void>;
  
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + 
                    "/devices/" + std::to_string(device_id);
  
  return http_io<monad::DeleteTag>(url)
      .map([cookie](auto ex) {
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::DeleteTag>(mgr))
      .then([](auto ex) {
        log_http_response("delete_device_io", ex);
        if (ex->response->result() == http::status::ok || 
            ex->response->result() == http::status::no_content) {
          return VoidIO::from_result(monad::MyVoidResult::Ok());
        }
        return VoidIO::from_result(monad::MyVoidResult::Err(
            monad::Error{static_cast<int>(ex->response->result()), 
                        "Failed to delete device"}));
      });
}

// ============================================================================
// Device certificate assignment helpers
// ============================================================================

// Associate CA with device - required before assigning certs issued by that CA
// Per HTTP_API_REFERENCE.md: POST /apiv1/users/:user_id/devices/:device_id/cas
inline monad::IO<void> associate_ca_with_device_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    int64_t device_id,
    int64_t ca_id) {
  
  using VoidIO = monad::IO<void>;
  
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + 
                    "/devices/" + std::to_string(device_id) + "/cas";
  
  return http_io<monad::PostJsonTag>(url)
      .map([=](auto ex) {
        json::object body{{"ca_id", ca_id}};
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::PostJsonTag>(mgr))
      .then([](auto ex) {
        log_http_response("associate_ca_with_device_io", ex);
        const auto status = ex->response->result();
        if (status == http::status::ok || 
            status == http::status::no_content) {
          return VoidIO::from_result(monad::MyVoidResult::Ok());
        }
        return VoidIO::from_result(monad::MyVoidResult::Err(
            monad::Error{static_cast<int>(status), 
                        "Failed to associate CA with device"}));
      });
}

inline monad::IO<void> assign_cert_to_device_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &cookie,
    int64_t user_id,
    int64_t device_id,
    int64_t cert_id) {
  
  using VoidIO = monad::IO<void>;
  
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) + 
                    "/devices/" + std::to_string(device_id) + "/certificates";
  
  return http_io<monad::PostJsonTag>(url)
      .map([=](auto ex) {
        // Per HTTP_API_REFERENCE.md: body field is "cert_id", not "certificate_id"
        json::object body{{"cert_id", cert_id}};
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::PostJsonTag>(mgr))
      .then([](auto ex) {
        log_http_response("assign_cert_to_device_io", ex);
        if (ex->response->result() == http::status::ok || 
            ex->response->result() == http::status::created ||
            ex->response->result() == http::status::no_content) {
          return VoidIO::from_result(monad::MyVoidResult::Ok());
        }
        
        // Print response body to help diagnose server-side errors
        std::string body_str{ex->response->body().begin(), ex->response->body().end()};
        std::cout << "Certificate assignment failed with status " 
                  << static_cast<int>(ex->response->result()) 
                  << ", response body: " << body_str << std::endl;
        
        // Try to extract error message from JSON response
        std::string error_msg = "Failed to assign certificate to device";
        try {
          if (!body_str.empty()) {
            auto json_val = json::parse(body_str);
            if (json_val.is_object() && json_val.as_object().contains("error")) {
              auto error_obj = json_val.as_object().at("error").as_object();
              if (error_obj.contains("what")) {
                error_msg = std::string(error_obj.at("what").as_string());
              }
            }
          }
        } catch (...) {
          // If parsing fails, use default error message
        }
        
        return VoidIO::from_result(monad::MyVoidResult::Err(
            monad::Error{static_cast<int>(ex->response->result()), error_msg}));
      });
}

// ============================================================================
// Combined test fixture setup
// ============================================================================

struct TestResources {
  int64_t user_id{};
  std::string session_cookie;
  std::optional<AcmeAccountInfo> acme_account;
  std::optional<CertInfo> cert;
  std::optional<DeviceInfo> device;
  std::string device_access_token;
  std::string device_refresh_token;
};

} // namespace testutil
