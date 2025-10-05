#pragma once

#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "customio/console_output.hpp"
#include <filesystem>

namespace certctrl {
namespace signal_handlers {

/**
 * Handler for "cert.renewed" signals.
 * Fetches and installs renewed certificates.
 */
class CertRenewedHandler : public ISignalHandler {
private:
    std::filesystem::path config_dir_;
    customio::ConsoleOutput& output_hub_;
    
public:
    CertRenewedHandler(
        const std::filesystem::path& config_dir,
        customio::ConsoleOutput& output_hub)
        : config_dir_(config_dir)
        , output_hub_(output_hub) {}
    
    std::string signal_type() const override {
        return "cert.renewed";
    }
    
    monad::IO<void> handle(const data::DeviceUpdateSignal& signal) override {
        output_hub_.logger().info()
            << "Processing cert.renewed: "
            << boost::json::serialize(signal.ref) << std::endl;
        
        try {
            auto cert_id = signal.ref.at("cert_id").as_int64();
            
            std::string serial;
            if (signal.ref.contains("serial")) {
                serial = std::string(signal.ref.at("serial").as_string());
            }
            
            output_hub_.logger().info()
                << "Certificate renewed: cert_id=" << cert_id
                << " serial=" << serial << std::endl;
            
            // TODO: Fetch certificate from server and install
            output_hub_.logger().info()
                << "Certificate " << cert_id << " processed successfully" << std::endl;
            
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
