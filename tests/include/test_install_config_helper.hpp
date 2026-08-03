#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/json.hpp>
#include <string>

#include "http_client_awaitable.hpp"
#include "http_client_manager.hpp"

namespace testutil {
namespace json = boost::json;
namespace http = boost::beast::http;

inline boost::asio::awaitable<monad::MyResult<void>>
create_install_config_awaitable(client_async::HttpClientManager &mgr,
                                const std::string &base_url,
                                const std::string &cookie, int64_t user_id,
                                int64_t device_id, const json::array &installs,
                                const std::string &change_note = {}) {
  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) +
                    "/devices/" + std::to_string(device_id) + "/install-config";

  json::object body{{"installs", installs}};
  if (!change_note.empty()) {
    body.emplace("change_note", change_note);
  }

  auto exchange_result =
      certctrl::async_support::make_http_exchange<monad::PostJsonTag>(url);
  if (exchange_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  exchange->request.method(http::verb::put);
  exchange->setRequestJsonBody(body);
  exchange->request.set(http::field::cookie, cookie);

  auto request_result =
      co_await certctrl::async_support::http_exchange_awaitable<
          monad::PostJsonTag>(mgr, std::move(exchange));
  if (request_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(request_result).error());
  }
  exchange = std::move(request_result).value();
  if (exchange->response->result() == http::status::ok ||
      exchange->response->result() == http::status::created ||
      exchange->response->result() == http::status::no_content) {
    co_return monad::MyResult<void>::Ok();
  }
  std::string response_body(exchange->response->body().begin(),
                            exchange->response->body().end());
  co_return monad::MyResult<void>::Err(
      monad::Error{static_cast<int>(exchange->response->result()),
                   std::move(response_body)});
}

} // namespace testutil
