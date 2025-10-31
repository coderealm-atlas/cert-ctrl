#pragma once

#include <memory>
#include <string>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/i_handler.hpp"
#include "handlers/install_workflow/install_workflow_runner.hpp"
#include "io_monad.hpp"

namespace cjj365 {
class ConfigSources;
}

namespace client_async {
class HttpClientManager;
}

namespace certctrl {

class InstallConfigApplyHandler : public IHandler, 
                                 public std::enable_shared_from_this<
                                     InstallConfigApplyHandler> {
private:
  certctrl::CliCtx &cli_ctx_;
  customio::ConsoleOutput &output_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  std::unique_ptr<InstallWorkflowRunner> workflow_runner_;

public:
  InstallConfigApplyHandler(cjj365::ConfigSources &config_sources,
                            certctrl::CliCtx &cli_ctx,
                            customio::ConsoleOutput &output,
                            client_async::HttpClientManager &http_client,
                            certctrl::ICertctrlConfigProvider &config_provider,
                            std::unique_ptr<InstallWorkflowRunner> workflow_runner);

  std::string command() const override;
  monad::IO<void> start() override;
};

} // namespace certctrl
