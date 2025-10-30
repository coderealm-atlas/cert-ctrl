#include "handlers/install_workflow/install_workflow_runner.hpp"

#include "customio/console_output.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "handlers/install_config_manager.hpp"

namespace certctrl {

InstallWorkflowRunner::InstallWorkflowRunner(
  std::shared_ptr<InstallConfigManager> manager,
  customio::ConsoleOutput &output)
  : manager_(std::move(manager)), output_(output) {}

monad::IO<void> InstallWorkflowRunner::start(const Options &options) {
  using ReturnIO = monad::IO<void>;
  auto self = shared_from_this();

  return ReturnIO::pure().then([self, options]() -> ReturnIO {
  auto config_ptr = self->manager_->cached_config_snapshot();
    if (!config_ptr) {
      self->output_.logger().warning()
          << "No staged install configuration found on disk." << std::endl
          << "Fetch one first (e.g. via updates polling) before running apply."
          << std::endl;
      return ReturnIO::pure();
    }

    auto version = config_ptr->version;
    self->output_.logger().info()
        << "Applying staged install-config version " << version << std::endl;

  return self->manager_
    ->apply_copy_actions(*config_ptr, options.target_ob_type,
             options.target_ob_id)
        .then([self, version]() {
          self->output_.logger().info()
              << "Installed configuration version " << version
              << " successfully." << std::endl;
          return monad::IO<void>::pure();
        });
  });
}

} // namespace certctrl
