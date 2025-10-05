#pragma once

#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "customio/console_output.hpp"
#include <filesystem>
#include <fstream>

namespace certctrl {
namespace signal_handlers {

/**
 * Handler for "install.updated" signals.
 * Fetches and applies updated installation configuration.
 */
class InstallUpdatedHandler : public ISignalHandler {
private:
    std::filesystem::path config_dir_;
    customio::ConsoleOutput& output_hub_;
    int64_t local_version_{0};
    
public:
    InstallUpdatedHandler(
        const std::filesystem::path& config_dir,
        customio::ConsoleOutput& output_hub)
        : config_dir_(config_dir)
        , output_hub_(output_hub) {
        load_local_version();
    }
    
    std::string signal_type() const override {
        return "install.updated";
    }
    
    monad::IO<void> handle(const data::DeviceUpdateSignal& signal) override {
        output_hub_.logger().info()
            << "Processing install.updated: "
            << boost::json::serialize(signal.ref) << std::endl;
        
        try {
            // Extract reference data
            auto config_id = signal.ref.at("config_id").as_int64();
            auto version = signal.ref.at("version").as_int64();
            
            output_hub_.logger().info()
                << "Install config update: config_id=" << config_id
                << " version=" << version
                << " local_version=" << local_version_ << std::endl;
            
            // TODO: Fetch full install config from server and apply
            // For now, just update local version
            save_local_version(version);
            local_version_ = version;
            
            output_hub_.logger().info()
                << "Install config version " << version
                << " applied successfully" << std::endl;
            
            return monad::IO<void>::pure();
            
        } catch (const std::exception& e) {
            return monad::IO<void>::fail(
                monad::Error{
                    .code = my_errors::GENERAL::INVALID_ARGUMENT,
                    .what = std::string("Failed to parse signal ref: ") + e.what()
                });
        }
    }
    
    bool should_process(const data::DeviceUpdateSignal& signal) const override {
        // Check if version is newer than local
        try {
            if (signal.ref.contains("version")) {
                int64_t remote_version = signal.ref.at("version").as_int64();
                return remote_version > local_version_;
            }
        } catch (const std::exception&) {
            // Error checking version
        }
        
        return true; // Process if no version info or error
    }
    
private:
    void load_local_version() {
        auto version_file = config_dir_ / "state" / "install_version.txt";
        if (!std::filesystem::exists(version_file)) {
            local_version_ = 0;
            return;
        }
        
        try {
            std::ifstream ifs(version_file);
            ifs >> local_version_;
        } catch (const std::exception&) {
            local_version_ = 0;
        }
    }
    
    void save_local_version(int64_t version) {
        auto version_file = config_dir_ / "state" / "install_version.txt";
        auto temp_file = config_dir_ / "state" / ".install_version.txt.tmp";
        
        try {
            // Ensure state directory exists
            std::filesystem::create_directories(config_dir_ / "state");
            
            std::ofstream ofs(temp_file);
            ofs << version;
            ofs.close();
            
            std::filesystem::rename(temp_file, version_file);
            std::filesystem::permissions(version_file,
                std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write);
        } catch (const std::exception& e) {
            output_hub_.logger().error()
                << "Failed to save local version: " << e.what() << std::endl;
        }
    }
};

} // namespace signal_handlers
} // namespace certctrl
