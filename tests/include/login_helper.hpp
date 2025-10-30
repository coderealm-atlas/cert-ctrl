#pragma once

#include <boost/json.hpp>
#include <cctype>
#include <iostream>
#include <optional>
#include <string>
#include <type_traits>

#include "api_response_result.hpp"
#include "data/data_shape.hpp"
#include "data/device_auth_types.hpp"
#include "http_client_manager.hpp"
#include "http_client_monad.hpp"

// High level monadic helpers for login & device workflow against real server.
// They build on the generic http_io / http_request_io primitives and keep the
// fluent functional style inside tests.
//
// The helpers intentionally avoid hiding the monadic pipeline; they just
// provide small reusable functions that append .map / .then chains.

namespace testutil {
namespace json = boost::json;
namespace http = boost::beast::http;
using monad::GetStringTag;
using monad::http_io;         // bring into scope
using monad::http_request_io; // bring into scope
using monad::PostJsonTag;
using LoginResponse = apihandler::ApiDataResponse<data::LoginSuccess>;
using LoginResponseResult = apihandler::ApiResponseResult<data::LoginSuccess>;
using loginSuccessResult = monad::MyResult<data::LoginSuccess>;
using LoginSuccessIO = monad::IO<data::LoginSuccess>;

inline std::string make_body_preview(const std::string &body,
                                     std::size_t max_len = 512) {
  if (body.size() <= max_len) {
    return body;
  }
  std::string preview = body.substr(0, max_len);
  preview.append("...");
  return preview;
}

template <typename ExchangePtr>
inline void log_http_response(const char *tag, const ExchangePtr &ex) {
  if (!ex) {
    std::cout << "[" << tag << "] exchange unavailable" << std::endl;
    return;
  }
  if (ex->response.has_value()) {
    const auto &res = *ex->response;
    using BodyType = std::decay_t<decltype(res.body())>;
    std::string preview;
    if constexpr (std::is_same_v<BodyType, std::string>) {
      preview = make_body_preview(res.body());
    } else {
      preview = "<non-string-body>";
    }
    std::cout << "[" << tag << "] status=" << res.result_int()
              << " body_preview=" << preview << std::endl;
  } else {
    std::cout << "[" << tag << "] no HTTP response received" << std::endl;
  }
}

inline std::optional<std::string> read_trimmed_env(const char *key) {
  if (const char *envv = std::getenv(key); envv && *envv) {
    std::string value(envv);
    auto is_ws = [](unsigned char ch) {
      return static_cast<bool>(std::isspace(ch));
    };
    while (!value.empty() && is_ws(static_cast<unsigned char>(value.back()))) {
      value.pop_back();
    }
    size_t start = 0;
    while (start < value.size() &&
           is_ws(static_cast<unsigned char>(value[start]))) {
      ++start;
    }
    if (start > 0) {
      value.erase(0, start);
    }
    return value;
  }
  return std::nullopt;
}

inline std::string login_email() {
  auto value = read_trimmed_env("CERT_CTRL_TEST_EMAIL");
  if (value && !value->empty()) {
    return *value;
  }
  throw std::runtime_error("CERT_CTRL_TEST_EMAIL env var not set");
}

inline std::string login_password() {
  auto value = read_trimmed_env("CERT_CTRL_TEST_PASSWORD");
  if (value && !value->empty()) {
    return *value;
  }
  throw std::runtime_error("CERT_CTRL_TEST_PASSWORD env var not set");
}

inline std::string url_base() {
  auto value = read_trimmed_env("CERT_CTRL_TEST_URL_BASE");
  if (value && !value->empty()) {
    return *value;
  }
  return std::string("https://test-api.cjj365.cc"); // 8080 default
}

// inline std::string first_cookie_pair(
//     const monad::HttpExchangePtr<http::request<http::string_body>,
//                                  http::response<http::string_body>> &ex) {
//   if (!ex->response)
//     return {};
//   for (auto it = ex->response->find(http::field::set_cookie);
//        it != ex->response->end(); ++it) {
//     std::string raw = std::string(it->value());
//     auto pos = raw.find(';');
//     if (pos != std::string::npos)
//       raw = raw.substr(0, pos);
//     if (!raw.empty())
//       return raw;
//   }
//   return {};
// }

inline LoginSuccessIO login_io(client_async::HttpClientManager &mgr,
                               const std::string &base_url,
                               const std::string &email,
                               const std::string &password) {
  // Contract per docs: POST /auth { action: login, email, password }
  std::string login_url =
      base_url + "/auth/general"; // unified multi-action endpoint
  return http_io<PostJsonTag>(login_url)
      .map([email, password, login_url](auto ex) {
        json::object body{
            {"action", "login"}, {"email", email}, {"password", password}};
        std::cout << "[login_io] POST " << login_url
                  << " body=" << json::serialize(body) << std::endl;
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::accept, "application/json");
        return ex;
      })
      .then(http_request_io<PostJsonTag>(mgr))
      .then([&](auto ex) {
        log_http_response("login_io", ex);
        // Get the cookie value and construct the full cookie string
        auto cookie_value = ex->getResponseCookie().value_or("");
        auto auth_cookie = cookie_value.empty() ? std::string{} 
                                                : "cjj365=" + cookie_value;
        auto r =
            ex->template parseJsonResponseResult<LoginResponseResult>().map(
                [auth_cookie](auto api_resp) {
                  auto login_success =
                      std::get<data::LoginSuccess>(api_resp.data);
                  login_success.session_cookie = auth_cookie;
                  return login_success;
                });
        return LoginSuccessIO::from_result(std::move(r));
      });
}

inline monad::IO<data::deviceauth::StartResp>
device_start_io(client_async::HttpClientManager &mgr,
                const std::string &base_url, const std::string &cookie) {
  using StartRespResult = monad::MyResult<data::deviceauth::StartResp>;
  using StartRespIO = monad::IO<data::deviceauth::StartResp>;

  std::string url = base_url + "/auth/device";
  return http_io<PostJsonTag>(url)
      .map([cookie](auto ex) {
        ex->setRequestJsonBody(
            json::object{{"action", "device_start"},
                         {"scopes", json::array{json::value("openid"),
                                                json::value("profile")}}});
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(mgr))
      .then([](auto ex) {
        return StartRespIO::from_result(
    ex->template parseJsonDataResponse<data::deviceauth::StartResp>());
      });
}

inline monad::IO<data::deviceauth::PollResp>
device_poll_io(client_async::HttpClientManager &mgr,
               const std::string &base_url, const std::string &device_code,
               std::optional<int64_t> device_id = std::nullopt) {
  using PollRespResult = monad::MyResult<data::deviceauth::PollResp>;
  using PollRespIO = monad::IO<data::deviceauth::PollResp>;

  std::string url = base_url + "/auth/device";
  return http_io<PostJsonTag>(url)
      .map([device_code, device_id](auto ex) {
        json::object body{{"action", "device_poll"},
                          {"device_code", device_code}};
        if (device_id.has_value()) {
          body.emplace("device_id", *device_id);
        }
        ex->setRequestJsonBody(std::move(body));
        return ex;
      })
      .then(http_request_io<PostJsonTag>(mgr))
      .then([](auto ex) {
        return PollRespIO::from_result(
            ex->template parseJsonDataResponse<data::deviceauth::PollResp>()
        );
      });
}

inline monad::IO<data::deviceauth::VerifyResp>
device_verify_io(client_async::HttpClientManager &mgr,
                 const std::string &base_url, const std::string &cookie,
                 const std::string &user_code, bool approve = true) {
  using VerifyRespIO = monad::IO<data::deviceauth::VerifyResp>;

  std::string url = base_url + "/auth/device";
  return http_io<PostJsonTag>(url)
      .map([cookie, user_code, approve](auto ex) {
        json::object body{{"action", "device_verify"},
                          {"user_code", user_code},
                          {"approve", approve}};
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(mgr))
      .then([](auto ex) {
        return VerifyRespIO::from_result(
            ex->template parseJsonDataResponse<data::deviceauth::VerifyResp>()
        );
      });
}

// Register device with fingerprint
inline monad::IO<json::object> device_register_io(
    client_async::HttpClientManager &mgr,
    const std::string &base_url,
    const std::string &access_token,
    int64_t timestamp) {
  using RegisterIO = monad::IO<json::object>;

  std::string url = base_url + "/auth/device";
  return http_io<PostJsonTag>(url)
      .map([access_token, timestamp](auto ex) {
        ex->setRequestJsonBody(json::object{
            {"action", "device_register"},
            {"platform", "linux"},
            {"model", "test_x86_64"},
            {"app_version", "1.0.0-test"},
            {"device_name", "Test Device " + std::to_string(timestamp)},
            {"fp_version", 1}
        });
        ex->request.set(http::field::authorization, "Bearer " + access_token);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(mgr))
      .then([](auto ex) {
        return RegisterIO::from_result(
            ex->template parseJsonDataResponse<json::object>()
        );
      });
}

// Query user devices to verify registration
inline monad::IO<json::array> list_user_devices_io(
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

} // namespace testutil
