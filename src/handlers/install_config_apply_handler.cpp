#include "handlers/install_config_apply_handler.hpp"

#include <filesystem>

#include "customio/console_output.hpp"
#include "simple_data.hpp"

namespace certctrl {

InstallConfigApplyHandler::InstallConfigApplyHandler(
    cjj365::ConfigSources &config_sources,              //
    certctrl::CliCtx &cli_ctx,                          //
    customio::ConsoleOutput &output,                    //
    client_async::HttpClientManager &http_client,       //
    certctrl::ICertctrlConfigProvider &config_provider, //
    std::unique_ptr<InstallWorkflowRunner> workflow_runner)
    : cli_ctx_(cli_ctx), output_(output), config_provider_(config_provider),
      workflow_runner_(std::move(workflow_runner)) {
  (void)config_sources;
  (void)http_client;
}

std::string InstallConfigApplyHandler::command() const { return "install"; }

boost::asio::awaitable<monad::MyResult<void>>
InstallConfigApplyHandler::start_awaitable() {
  if (cli_ctx_.positionals.size() < 2 || cli_ctx_.positionals[1] != "apply") {
    output_.logger().error()
        << "Usage: cert-ctrl install-config apply" << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  if (config_provider_.get().auto_apply_config) {
    output_.logger().warning()
        << "auto_apply_config is enabled; install.updated signals are applied"
        << " automatically." << std::endl
        << "Disable it via 'cert-ctrl conf set auto_apply_config false' if you"
        << " prefer manual promotion." << std::endl;
  }

  InstallWorkflowRunner::Options options{};
  if (cli_ctx_.positionals.size() > 2) {
    // Future: parse target filters from CLI (not yet implemented).
  }

  co_return co_await workflow_runner_->start_awaitable(options);
}

} // namespace certctrl
