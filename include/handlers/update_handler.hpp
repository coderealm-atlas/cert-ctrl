#pragma once

#include <memory>
#include <string>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/agent_update_checker.hpp"
#include "handlers/i_handler.hpp"
#include "http_client_manager.hpp"

namespace certctrl {

class UpdateHandler : public IHandler,
                      public std::enable_shared_from_this<UpdateHandler> {
private:
  customio::ConsoleOutput &output_;

  std::string detect_platform();

public:
  UpdateHandler(certctrl::ICertctrlConfigProvider &config_provider,
                customio::ConsoleOutput &output,
                client_async::HttpClientManager &http_client,
                certctrl::CliCtx &cli_ctx,
                std::shared_ptr<AgentUpdateChecker> update_checker);

  std::string command() const override;
  boost::asio::awaitable<monad::MyResult<void>> start_awaitable() override;
};

} // namespace certctrl
