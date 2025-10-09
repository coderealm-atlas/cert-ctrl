#pragma once

#include <memory>
#include <string>

#include <boost/url/url.hpp>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/agent_update_check.hpp"
#include "http_client_manager.hpp"
#include "http_client_monad.hpp"
#include "io_monad.hpp"

namespace certctrl {

class AgentUpdateChecker {
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;

public:
  AgentUpdateChecker(certctrl::ICertctrlConfigProvider &config_provider,
                     customio::ConsoleOutput &output,
                     client_async::HttpClientManager &http_client);

  monad::IO<void> run_once(const std::string &current_version);

private:
  static std::string detect_platform();
  static std::string detect_architecture();
};

} // namespace certctrl
