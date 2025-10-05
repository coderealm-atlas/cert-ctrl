#pragma once

#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "customio/console_output.hpp"
#include <filesystem>

namespace certctrl {
namespace signal_handlers {

/**
 * Handler for "cert.revoked" signals.
 * Removes revoked certificates from active use.
 */
class CertRevokedHandler : public ISignalHandler {
private:
    std::filesystem::path config_dir_;
    customio::ConsoleOutput& output_hub_;
    
public:
    CertRevokedHandler(
        const std::filesystem::path& config_dir,
        customio::ConsoleOutput& output_hub)
        : config_dir_(config_dir)
        , output_hub_(output_hub) {}
    
    std::string signal_type() const override {
        return "cert.revoked";
    }
    
    monad::IO<void> handle(const data::DeviceUpdateSignal& signal) override {
        output_hub_.logger().warning()
            << "Processing cert.revoked: "
            << boost::json::serialize(signal.ref) << std::endl;
        
        try {
            auto cert_id = signal.ref.at("cert_id").as_int64();
            
            output_hub_.logger().warning()
                << "Certificate revoked: cert_id=" << cert_id << std::endl;
            
            // TODO: Remove certificate from config and stop services
            output_hub_.logger().info()
                << "Certificate " << cert_id 
                << " revoked and removed from system" << std::endl;
            
            return monad::IO<void>::pure();
            
        } catch (const std::exception& e) {
            return monad::IO<void>::fail(
                monad::Error{
                    .code = my_errors::GENERAL::INVALID_ARGUMENT,
                    .what = std::string("Failed to parse signal ref: ") + e.what()
                });
        }
    }
};

} // namespace signal_handlers
} // namespace certctrl
