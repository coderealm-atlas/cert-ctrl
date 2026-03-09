#include "handlers/install_workflow/install_workflow_runner.hpp"

#include "customio/console_output.hpp"
#include "handlers/install_config_manager.hpp"

namespace certctrl {

InstallWorkflowRunner::InstallWorkflowRunner(
    std::unique_ptr<InstallConfigManager> manager,
    customio::ConsoleOutput &output)
    : manager_(std::move(manager)), output_(output) {}

monad::IO<void> InstallWorkflowRunner::start(const Options &options) {
  using ReturnIO = monad::IO<void>;

  return ReturnIO::pure().then([this, options]() -> ReturnIO {
    output_.logger().info()
        << "Fetching latest install-config before apply" << std::endl;

    return manager_
        ->ensure_config_version(std::nullopt, std::nullopt)
        .then([this, options](std::shared_ptr<const dto::DeviceInstallConfigDto>
                                  config_ptr) {
          if (!config_ptr) {
            output_.logger().warning()
                << "install-config fetch returned no payload" << std::endl;
            return ReturnIO::pure();
          }

          auto version = config_ptr->version;
          output_.logger().info()
              << "Applying install-config version " << version << std::endl;

          return manager_
              ->rearm_local_install_update_window()
              .then([this, config_ptr]() {
                return manager_->approve_after_update_script_hash(*config_ptr);
              })
              .then([this, config_ptr, options]() {
                return manager_->apply_copy_actions(*config_ptr,
                                                    options.target_ob_type,
                                                    options.target_ob_id);
              })
              .then([this, config_ptr, options]() {
                return manager_->apply_import_ca_actions(*config_ptr,
                                                         options.target_ob_type,
                                                         options.target_ob_id);
              })
              .then([this, version]() {
                output_.logger().info()
                    << "Installed configuration version " << version
                    << " successfully." << std::endl;
                return monad::IO<void>::pure();
              });
        });
  });
}

} // namespace certctrl
