#include "handlers/install_workflow/install_workflow_runner.hpp"

namespace certctrl {

InstallWorkflowRunner::InstallWorkflowRunner(
    std::unique_ptr<InstallConfigManager> manager,
    customio::ConsoleOutput &output)
    : manager_(std::move(manager)), output_(output) {}

boost::asio::awaitable<monad::MyResult<void>>
InstallWorkflowRunner::start_awaitable(const Options &options) {
  output_.logger().info() << "Fetching latest install-config before apply"
                          << std::endl;

  auto config_result =
      co_await manager_->ensure_config_version(std::nullopt, std::nullopt);
  if (config_result.is_err()) {
    co_return monad::MyResult<void>::Err(config_result.error());
  }
  auto config = std::move(config_result).value();
  if (!config) {
    output_.logger().warning()
        << "install-config fetch returned no payload" << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  const auto version = config->version;
  output_.logger().info() << "Applying install-config version " << version
                          << std::endl;

  auto rearm_result = co_await manager_->rearm_local_install_update_window();
  if (rearm_result.is_err()) {
    co_return rearm_result;
  }
  auto approval_result =
      co_await manager_->approve_and_persist_after_update_script(*config);
  if (approval_result.is_err()) {
    co_return approval_result;
  }
  auto copy_result = co_await manager_->apply_copy_actions(
      *config, options.target_ob_type, options.target_ob_id);
  if (copy_result.is_err()) {
    co_return copy_result;
  }
  auto import_result = co_await manager_->apply_import_ca_actions(
      *config, options.target_ob_type, options.target_ob_id);
  if (import_result.is_err()) {
    co_return import_result;
  }

  output_.logger().info() << "Installed configuration version " << version
                          << " successfully." << std::endl;
  co_return monad::MyResult<void>::Ok();
}

} // namespace certctrl
