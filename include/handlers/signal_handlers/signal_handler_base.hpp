#pragma once

#include "data/data_shape.hpp"
#include "io_monad.hpp"
#include <string>

namespace certctrl {
namespace signal_handlers {

/**
 * Base interface for all signal handlers.
 * Each handler processes a specific signal type (e.g., "install.updated").
 */
class ISignalHandler {
public:
    virtual ~ISignalHandler() = default;
    
    /**
     * Return the signal type this handler processes.
     * Must match the "type" field in DeviceUpdateSignal.
     */
    virtual std::string signal_type() const = 0;
    
    /**
     * Process the signal synchronously.
     * Errors are caught by the dispatcher and logged.
     * @param signal The signal to process
     * @return IO<void> monad representing the processing operation
     */
    virtual monad::IO<void> handle(const data::DeviceUpdateSignal& signal) = 0;
    
    /**
     * Check if this signal should be processed.
     * Allows handlers to skip stale or already-applied signals.
     * @param signal The signal to check
     * @return true if the signal should be processed
     */
    virtual bool should_process(const data::DeviceUpdateSignal& signal) const {
        return true; // Default: process all signals
    }
};

} // namespace signal_handlers
} // namespace certctrl
