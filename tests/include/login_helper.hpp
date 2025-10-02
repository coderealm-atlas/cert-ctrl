#pragma once

#include <boost/json.hpp>
#include <cctype>
#include <optional>
#include <string>

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

inline std::string first_cookie_pair(
    const monad::HttpExchangePtr<http::request<http::string_body>,
                                 http::response<http::string_body>> &ex) {
  if (!ex->response)
    return {};
  for (auto it = ex->response->find(http::field::set_cookie);
       it != ex->response->end(); ++it) {
    std::string raw = std::string(it->value());
    auto pos = raw.find(';');
    if (pos != std::string::npos)
      raw = raw.substr(0, pos);
    if (!raw.empty())
      return raw;
  }
  return {};
}

inline LoginSuccessIO login_io(client_async::HttpClientManager &mgr,
                               const std::string &base_url,
                               const std::string &email,
                               const std::string &password) {
  // Contract per docs: POST /auth { action: login, email, password }
  std::string login_url =
      base_url + "/auth/general"; // unified multi-action endpoint
  return http_io<PostJsonTag>(login_url)
      .map([email, password](auto ex) {
        json::object body{
            {"action", "login"}, {"email", email}, {"password", password}};
        ex->setRequestJsonBody(std::move(body));
        ex->request.set(http::field::accept, "application/json");
        return ex;
      })
      .then(http_request_io<PostJsonTag>(mgr))
      .then([&](auto ex) {
        auto auth_cookie = ex->getResponseCookie().value_or("");
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
      .map([&](auto ex) {
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
            ex->template parseJsonResponse<data::deviceauth::StartResp>());
      });
}

inline monad::IO<data::deviceauth::PollResp>
device_poll_io(client_async::HttpClientManager &mgr,
               const std::string &base_url, const std::string &device_code) {
  using PollRespResult = monad::MyResult<data::deviceauth::PollResp>;
  using PollRespIO = monad::IO<data::deviceauth::PollResp>;

  std::string url = base_url + "/auth/device";
  return http_io<PostJsonTag>(url)
      .map([&](auto ex) {
        ex->setRequestJsonBody(json::object{{"action", "device_poll"},
                                            {"device_code", device_code}});
        return ex;
      })
      .then(http_request_io<PostJsonTag>(mgr))
      .then([](auto ex) {
        return PollRespIO::from_result(
            ex->template parseJsonResponse<data::deviceauth::PollResp>()
        );
      });
}

} // namespace testutil
