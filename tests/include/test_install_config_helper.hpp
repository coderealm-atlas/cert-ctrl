#pragma once

#include <boost/json.hpp>
#include <string>

#include "http_client_manager.hpp"
#include "http_client_monad.hpp"

namespace testutil {
namespace json = boost::json;
namespace http = boost::beast::http;

inline monad::IO<void> create_install_config_io(
  client_async::HttpClientManager &mgr,
  const std::string &base_url,
  const std::string &cookie,
  int64_t user_id,
  int64_t device_id,
  const json::array &installs,
  const std::string &change_note = {}) {
  using VoidIO = monad::IO<void>;

  std::string url = base_url + "/apiv1/users/" + std::to_string(user_id) +
                    "/devices/" + std::to_string(device_id) +
                    "/install-config";

  json::object body{{"installs", installs}};
  if (!change_note.empty()) {
    body.emplace("change_note", change_note);
  }

  return monad::http_io<monad::PostJsonTag>(url)
      .map([=](auto ex) {
        ex->request.method(http::verb::put);
        ex->setRequestJsonBody(body);
        ex->request.set(http::field::cookie, cookie);
        return ex;
      })
      .then(monad::http_request_io<monad::PostJsonTag>(mgr))
      .then([](auto ex) {
        if (ex->response->result() == http::status::ok ||
            ex->response->result() == http::status::created ||
            ex->response->result() == http::status::no_content) {
          return VoidIO::pure();
        }
        std::string body(ex->response->body().begin(), ex->response->body().end());
        return VoidIO::fail(monad::Error{static_cast<int>(ex->response->result()), body});
      });
}

} // namespace testutil
