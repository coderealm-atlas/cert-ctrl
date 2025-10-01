#pragma once

#include <boost/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "api_response_result.hpp"
#include "common_macros.hpp"
#include "data/data_shape.hpp"
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

constexpr const char *LOGIN_EMAIL = "jianglibo@hotmail.com";
constexpr const char *LOGIN_PASSWORD = "StrongPass1!";

inline std::string login_email() {
  const char *envv = std::getenv("CERT_CTRL_TEST_EMAIL");
  if (envv && *envv)
    return std::string(envv);
  return std::string(LOGIN_EMAIL);
}

inline std::string login_password() {
  const char *envv = std::getenv("CERT_CTRL_TEST_PASSWORD");
  if (envv && *envv)
    return std::string(envv);
  return std::string(LOGIN_PASSWORD);
}

inline std::string url_base() {
  const char *envv = std::getenv("CERT_CTRL_TEST_URL_BASE");
  if (envv && *envv)
    return std::string(envv);
  return std::string("http://localhost:8080"); // 8080 default
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
  DEBUG_PRINT("login_url: " << login_url);
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

struct DeviceStartData {
  std::string device_code;
  json::value body;
};

inline std::string extract_device_code(const json::value &v) {
  if (!v.is_object())
    return {};
  auto &o = v.as_object();
  if (auto dc = o.if_contains("device_code"); dc && dc->is_string())
    return std::string(dc->as_string());
  if (auto data = o.if_contains("data"); data && data->is_object()) {
    if (auto dc2 = data->as_object().if_contains("device_code");
        dc2 && dc2->is_string())
      return std::string(dc2->as_string());
  }
  return {};
}

inline monad::IO<DeviceStartData>
device_start_io(client_async::HttpClientManager &mgr,
                const std::string &base_url, const std::string &cookie) {
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
        auto jr = ex->getJsonResponse();
        if (jr.is_err())
          return monad::IO<DeviceStartData>::fail(jr.error());
        auto dc = extract_device_code(jr.value());
        if (dc.empty())
          return monad::IO<DeviceStartData>::fail(
              monad::Error{400, "missing device_code"});
        return monad::IO<DeviceStartData>::pure(
            DeviceStartData{dc, jr.value()});
      });
}

struct DevicePollData {
  std::string status;
  std::string access_token;
  std::string refresh_token;
  json::value body;
};

inline DevicePollData parse_poll(const json::value &v) {
  DevicePollData out;
  out.body = v;
  if (v.is_object()) {
    auto &o = v.as_object();
    auto extract = [&](auto &obj) {
      if (auto s = obj.if_contains("status"); s && s->is_string())
        out.status = std::string(s->as_string());
      if (auto at = obj.if_contains("access_token"); at && at->is_string())
        out.access_token = std::string(at->as_string());
      if (auto rt = obj.if_contains("refresh_token"); rt && rt->is_string())
        out.refresh_token = std::string(rt->as_string());
    };
    extract(o);
    if (auto data = o.if_contains("data"); data && data->is_object())
      extract(data->as_object());
  }
  return out;
}

inline monad::IO<DevicePollData>
device_poll_io(client_async::HttpClientManager &mgr,
               const std::string &base_url, const std::string &device_code) {
  std::string url = base_url + "/auth/device";
  return http_io<PostJsonTag>(url)
      .map([&](auto ex) {
        ex->setRequestJsonBody(json::object{{"action", "device_poll"},
                                            {"device_code", device_code}});
        return ex;
      })
      .then(http_request_io<PostJsonTag>(mgr))
      .then([](auto ex) {
        auto jr = ex->getJsonResponse();
        if (jr.is_err())
          return monad::IO<DevicePollData>::fail(jr.error());
        auto parsed = parse_poll(jr.value());
        if (parsed.status.empty())
          return monad::IO<DevicePollData>::fail(
              monad::Error{400, "missing status"});
        return monad::IO<DevicePollData>::pure(std::move(parsed));
      });
}

} // namespace testutil
