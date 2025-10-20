#pragma once

#include <memory>
#include <string>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/i_handler.hpp"
#include "handlers/install_config_manager.hpp"
#include "io_monad.hpp"

namespace cjj365 {
class ConfigSources;
}

namespace client_async {
class HttpClientManager;
}

namespace certctrl {

class InstallConfigApplyHandler : public IHandler {
private:
  certctrl::CliCtx &cli_ctx_;
  customio::ConsoleOutput &output_;
  cjj365::ConfigSources &config_sources_;
  client_async::HttpClientManager &http_client_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  std::shared_ptr<InstallConfigManager> install_config_manager_;

public:
  InstallConfigApplyHandler(cjj365::ConfigSources &config_sources,
                            certctrl::CliCtx &cli_ctx,
                            customio::ConsoleOutput &output,
                            client_async::HttpClientManager &http_client,
                            certctrl::ICertctrlConfigProvider &config_provider);

  std::string command() const override;
  monad::IO<void> start() override;
};

} // namespace certctrl
