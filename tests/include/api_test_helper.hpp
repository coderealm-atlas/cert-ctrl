#pragma once

#include <boost/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "http_client_manager.hpp"
#include "http_client_monad.hpp"
#include "login_helper.hpp"

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
        json::object body{
            {"name", name},
            {"email", email},
            {"provider", provider}
        };
        // Only include ca_id if it's > 0 (for self-CA)
        if (ca_id > 0) {
          body["ca_id"] = ca_id;
        }
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<monad::PostJsonTag>(mgr))
      .then([](auto ex) {
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
        if (ex->response->result() == http::status::ok || 
            ex->response->result() == http::status::no_content) {
          return VoidIO::from_result(monad::MyVoidResult::Ok());
        }
        return VoidIO::from_result(monad::MyVoidResult::Err(
            monad::Error{static_cast<int>(ex->response->result()), 
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
