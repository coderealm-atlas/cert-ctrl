#include "handlers/login_handler.hpp"
#include "http_client_monad.hpp"
#include <format>
#include "handlers/device_auth_types.hpp"

namespace json = boost::json;

namespace certctrl {

using VoidPureIO = monad::IO<void>;

VoidPureIO LoginHandler::start() {
  using namespace monad;
  using httphandler::deviceauth::StartResp;
  std::string device_auth_url =
      std::format("{}/auth/device", certctrl_config_provider_.get().base_url);

  http_io<PostJsonTag>(device_auth_url)
      .map([](auto ex) {
        json::value body{{"action", "device_start"},
                         {"scopes", json::array{"openid", "profile", "email"}},
                         {"interval", 5},
                         {"expires_in", 900}};
        ex->setRequestJsonBody(std::move(body));
        return ex;
      })
      .then(http_request_io<PostJsonTag>(http_client_))
      .then([](auto ex) {
        return monad::IO<StartResp>::from_result(
          ex->template parseJsonResponse<StartResp>()
        );
      })
      .run([&](monad::MyResult<StartResp> &&result) {
        // response_body_r = std::move(result);
        // notifier.notify();
      });
  return VoidPureIO::pure();
}
} // namespace certctrl