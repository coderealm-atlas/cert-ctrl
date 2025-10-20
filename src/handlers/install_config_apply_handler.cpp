#include "handlers/install_config_apply_handler.hpp"

#include <filesystem>

#include "customio/console_output.hpp"
#include "simple_data.hpp"

namespace certctrl {

InstallConfigApplyHandler::InstallConfigApplyHandler(
    cjj365::ConfigSources &config_sources, certctrl::CliCtx &cli_ctx,
    customio::ConsoleOutput &output,
    client_async::HttpClientManager &http_client,
    certctrl::ICertctrlConfigProvider &config_provider)
    : cli_ctx_(cli_ctx), output_(output), config_sources_(config_sources),
      http_client_(http_client), config_provider_(config_provider) {
  auto runtime_dir = config_sources_.paths_.empty()
                          ? std::filesystem::path{}
                          : config_sources_.paths_.back();
  install_config_manager_ = std::make_shared<InstallConfigManager>(
      runtime_dir, config_provider_, output_, &http_client_);
}

std::string InstallConfigApplyHandler::command() const { return "install"; }

monad::IO<void> InstallConfigApplyHandler::start() {
  using ReturnIO = monad::IO<void>;

  if (cli_ctx_.positionals.size() < 2 || cli_ctx_.positionals[1] != "apply") {
    output_.logger().error()
        << "Usage: cert-ctrl install apply" << std::endl;
    return ReturnIO::pure();
  }

  if (config_provider_.get().auto_apply_config) {
    output_.logger().warning()
        << "auto_apply_config is enabled; install.updated signals are applied"
        << " automatically." << std::endl
        << "Disable it via 'cert-ctrl conf set auto_apply_config false' if you"
        << " prefer manual promotion." << std::endl;
  }

  auto config_ptr = install_config_manager_->cached_config_snapshot();
  if (!config_ptr) {
    output_.logger().warning()
        << "No staged install configuration found on disk." << std::endl
        << "Fetch one first (e.g. via updates polling) before running apply."
        << std::endl;
    return ReturnIO::pure();
  }

  auto version = config_ptr->version;
  output_.logger().info()
      << "Applying staged install-config version " << version << std::endl;

  return install_config_manager_->apply_copy_actions(*config_ptr, std::nullopt,
                                                     std::nullopt)
      .then([this, version]() {
        output_.logger().info()
            << "Installed configuration version " << version
            << " successfully." << std::endl;
        return monad::IO<void>::pure();
      });
}

} // namespace certctrl
