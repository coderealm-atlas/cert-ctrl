#pragma once

#include "handlers/install_config_manager.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "customio/console_output.hpp"
#include <boost/json.hpp>

namespace certctrl {
namespace signal_handlers {

/**
 * Handler for "install.updated" signals.
 * Fetches and applies updated installation configuration.
 */
class InstallUpdatedHandler : public ISignalHandler {
private:
    std::shared_ptr<InstallConfigManager> config_manager_;
    customio::ConsoleOutput& output_hub_;
    
public:
    InstallUpdatedHandler(
        std::shared_ptr<InstallConfigManager> config_manager,
        customio::ConsoleOutput& output_hub)
        : config_manager_(std::move(config_manager))
        , output_hub_(output_hub) {}
    
    std::string signal_type() const override {
        return "install.updated";
    }
    
    monad::IO<void> handle(const ::data::DeviceUpdateSignal& signal) override {
        output_hub_.logger().info()
            << "Processing install.updated: "
            << boost::json::serialize(signal.ref) << std::endl;
        return config_manager_->apply_copy_actions_for_signal(signal);
    }
    
    bool should_process(const ::data::DeviceUpdateSignal& signal) const override {
        auto typed = ::data::get_install_updated(signal);
        if (typed) {
            auto local = config_manager_->local_version();
            if (local && typed->version <= *local) {
                return false;
            }
        }
        return true;
    }
};

} // namespace signal_handlers
} // namespace certctrl
