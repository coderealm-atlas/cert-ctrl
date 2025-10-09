#pragma once

#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "customio/console_output.hpp"
#include <filesystem>

namespace certctrl {
namespace signal_handlers {

/**
 * Handler for "install.updated" signals.
 * Placeholder implementation that logs signals.
 */
class InstallUpdatedHandler : public ISignalHandler {
private:
    customio::ConsoleOutput& output_hub_;
    
public:
    explicit InstallUpdatedHandler(customio::ConsoleOutput& output_hub)
        : output_hub_(output_hub) {}
    
    std::string signal_type() const override {
        return "install.updated";
    }
    
    monad::IO<void> handle(const ::data::DeviceUpdateSignal& signal) override {
        output_hub_.logger().info()
            << "Processing install.updated signal: "
            << "ts_ms=" << signal.ts_ms
            << " ref=" << boost::json::serialize(signal.ref)
            << std::endl;
        
        // TODO: Implement actual install config fetch and application
        return monad::IO<void>::pure();
    }
    
    bool should_process(const ::data::DeviceUpdateSignal& signal) const override {
        return true; // Process all for now
    }
};

} // namespace signal_handlers
} // namespace certctrl
