#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/json.hpp>
#include <cctype>
#include <iostream>
#include <optional>
#include <string>
#include <type_traits>

#include "api_response_result.hpp"
#include "data/data_shape.hpp"
#include "data/device_auth_types.hpp"
#include "http_client_awaitable.hpp"
#include "http_client_manager.hpp"

// High-level coroutine helpers for login and device workflows against a real
// server.

namespace testutil {
namespace json = boost::json;
namespace http = boost::beast::http;
using LoginResponse = apihandler::ApiDataResponse<data::LoginSuccess>;
using LoginResponseResult = apihandler::ApiResponseResult<data::LoginSuccess>;
using loginSuccessResult = monad::MyResult<data::LoginSuccess>;
using LoginSuccessAwaitable = boost::asio::awaitable<loginSuccessResult>;

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
  return std::string("https://api.cjj365.cc");
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

inline LoginSuccessAwaitable
login_awaitable(client_async::HttpClientManager &mgr,
                const std::string &base_url, const std::string &email,
                const std::string &password) {
  // Contract per docs: POST /auth { action: login, email, password }
  std::string login_url =
      base_url + "/auth/general"; // unified multi-action endpoint
  auto exchange_result =
      certctrl::async_support::make_http_exchange<monad::PostJsonTag>(
          login_url);
  if (exchange_result.is_err()) {
    co_return loginSuccessResult::Err(std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  json::object body{
      {"action", "login"}, {"email", email}, {"password", password}};
  std::cout << "[login_awaitable] POST " << login_url
            << " body=" << json::serialize(body) << std::endl;
  exchange->setRequestJsonBody(std::move(body));
  exchange->request.set(http::field::accept, "application/json");

  auto request_result =
      co_await certctrl::async_support::http_exchange_awaitable<
          monad::PostJsonTag>(mgr, std::move(exchange));
  if (request_result.is_err()) {
    co_return loginSuccessResult::Err(std::move(request_result).error());
  }
  exchange = std::move(request_result).value();
  log_http_response("login_awaitable", exchange);
  auto cookie_value = exchange->getResponseCookie().value_or("");
  auto auth_cookie =
      cookie_value.empty() ? std::string{} : "cjj365=" + cookie_value;
  co_return exchange->template parseJsonResponseResult<LoginResponseResult>()
      .map([auth_cookie](auto api_resp) {
        auto login_success = std::get<data::LoginSuccess>(api_resp.data);
        login_success.session_cookie = auth_cookie;
        return login_success;
      });
}

inline boost::asio::awaitable<monad::MyResult<data::deviceauth::StartResp>>
device_start_awaitable(client_async::HttpClientManager &mgr,
                       const std::string &base_url, const std::string &cookie) {
  using Result = monad::MyResult<data::deviceauth::StartResp>;

  std::string url = base_url + "/auth/device";
  auto exchange_result =
      certctrl::async_support::make_http_exchange<monad::PostJsonTag>(url);
  if (exchange_result.is_err()) {
    co_return Result::Err(std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  exchange->setRequestJsonBody(json::object{
      {"action", "device_start"},
      {"scopes", json::array{json::value("openid"), json::value("profile")}}});
  exchange->request.set(http::field::cookie, cookie);
  auto request_result =
      co_await certctrl::async_support::http_exchange_awaitable<
          monad::PostJsonTag>(mgr, std::move(exchange));
  if (request_result.is_err()) {
    co_return Result::Err(std::move(request_result).error());
  }
  co_return std::move(request_result)
      .value()
      ->template parseJsonDataResponse<data::deviceauth::StartResp>();
}

inline boost::asio::awaitable<monad::MyResult<data::deviceauth::PollResp>>
device_poll_awaitable(client_async::HttpClientManager &mgr,
                      const std::string &base_url,
                      const std::string &device_code,
                      std::optional<int64_t> device_id = std::nullopt) {
  using Result = monad::MyResult<data::deviceauth::PollResp>;

  std::string url = base_url + "/auth/device";
  auto exchange_result =
      certctrl::async_support::make_http_exchange<monad::PostJsonTag>(url);
  if (exchange_result.is_err()) {
    co_return Result::Err(std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  json::object body{{"action", "device_poll"}, {"device_code", device_code}};
  if (device_id.has_value()) {
    body.emplace("device_id", *device_id);
  }
  exchange->setRequestJsonBody(std::move(body));
  auto request_result =
      co_await certctrl::async_support::http_exchange_awaitable<
          monad::PostJsonTag>(mgr, std::move(exchange));
  if (request_result.is_err()) {
    co_return Result::Err(std::move(request_result).error());
  }
  co_return std::move(request_result)
      .value()
      ->template parseJsonDataResponse<data::deviceauth::PollResp>();
}

inline boost::asio::awaitable<monad::MyResult<data::deviceauth::VerifyResp>>
device_verify_awaitable(client_async::HttpClientManager &mgr,
                        const std::string &base_url, const std::string &cookie,
                        const std::string &user_code, bool approve = true) {
  using Result = monad::MyResult<data::deviceauth::VerifyResp>;

  std::string url = base_url + "/auth/device";
  auto exchange_result =
      certctrl::async_support::make_http_exchange<monad::PostJsonTag>(url);
  if (exchange_result.is_err()) {
    co_return Result::Err(std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  exchange->setRequestJsonBody(json::object{{"action", "device_verify"},
                                            {"user_code", user_code},
                                            {"approve", approve}});
  exchange->request.set(http::field::cookie, cookie);
  auto request_result =
      co_await certctrl::async_support::http_exchange_awaitable<
          monad::PostJsonTag>(mgr, std::move(exchange));
  if (request_result.is_err()) {
    co_return Result::Err(std::move(request_result).error());
  }
  co_return std::move(request_result)
      .value()
      ->template parseJsonDataResponse<data::deviceauth::VerifyResp>();
}

// Register device with fingerprint
inline boost::asio::awaitable<monad::MyResult<json::object>>
device_register_awaitable(client_async::HttpClientManager &mgr,
                          const std::string &base_url,
                          const std::string &access_token, int64_t timestamp) {
  using Result = monad::MyResult<json::object>;

  std::string url = base_url + "/auth/device";
  auto exchange_result =
      certctrl::async_support::make_http_exchange<monad::PostJsonTag>(url);
  if (exchange_result.is_err()) {
    co_return Result::Err(std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  exchange->setRequestJsonBody(
      json::object{{"action", "device_register"},
                   {"platform", "linux"},
                   {"model", "test_x86_64"},
                   {"app_version", "1.0.0-test"},
                   {"device_name", "Test Device " + std::to_string(timestamp)},
                   {"fp_version", 1}});
  exchange->request.set(http::field::authorization, "Bearer " + access_token);
  auto request_result =
      co_await certctrl::async_support::http_exchange_awaitable<
          monad::PostJsonTag>(mgr, std::move(exchange));
  if (request_result.is_err()) {
    co_return Result::Err(std::move(request_result).error());
  }
  co_return std::move(request_result)
      .value()
      ->template parseJsonDataResponse<json::object>();
}

// Query user devices to verify registration
inline boost::asio::awaitable<monad::MyResult<json::array>>
list_user_devices_awaitable(client_async::HttpClientManager &mgr,
                            const std::string &base_url,
                            const std::string &cookie, int64_t user_id) {
  using Result = monad::MyResult<json::array>;

  std::string url =
      base_url + "/apiv1/users/" + std::to_string(user_id) + "/devices";
  auto exchange_result =
      certctrl::async_support::make_http_exchange<monad::GetStringTag>(url);
  if (exchange_result.is_err()) {
    co_return Result::Err(std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  exchange->request.set(http::field::cookie, cookie);
  auto request_result =
      co_await certctrl::async_support::http_exchange_awaitable<
          monad::GetStringTag>(mgr, std::move(exchange));
  if (request_result.is_err()) {
    co_return Result::Err(std::move(request_result).error());
  }
  co_return std::move(request_result)
      .value()
      ->template parseJsonDataResponse<json::array>();
}

} // namespace testutil
