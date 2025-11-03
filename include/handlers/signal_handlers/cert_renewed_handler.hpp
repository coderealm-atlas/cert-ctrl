#pragma once

#include "handlers/install_config_manager.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "customio/console_output.hpp"
#include <boost/json.hpp>

namespace certctrl {
namespace signal_handlers {

/**
 * Handler for "cert.renewed" signals.
 * Fetches and installs renewed certificates.
 */
class CertRenewedHandler : public ISignalHandler {
private:
    std::shared_ptr<InstallConfigManager> config_manager_;
    customio::ConsoleOutput& output_hub_;
    
public:
    CertRenewedHandler(
        std::shared_ptr<InstallConfigManager> config_manager,
        customio::ConsoleOutput& output_hub)
        : config_manager_(std::move(config_manager))
        , output_hub_(output_hub) {}
    
    std::string signal_type() const override {
        return "cert.renewed";
    }
    
    monad::IO<void> handle(const ::data::DeviceUpdateSignal& signal) override {
        if (!config_manager_) {
            output_hub_.logger().warning()
                << "CertRenewedHandler missing InstallConfigManager; skipping signal"
                << std::endl;
            return monad::IO<void>::pure();
        }
        output_hub_.logger().info()
            << "Processing cert.renewed: "
            << boost::json::serialize(signal.ref) << std::endl;
        
        return config_manager_->apply_copy_actions_for_signal(signal);
    }
};

} // namespace signal_handlers
} // namespace certctrl
