#pragma once

#include "signal_handlers/signal_handler_base.hpp"
#include "data/data_shape.hpp"
#include "util/my_logging.hpp"
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <boost/json.hpp>

namespace certctrl {

/**
 * Signal dispatcher that routes update signals to appropriate handlers.
 * Handles deduplication by persisting processed signal IDs.
 */
class SignalDispatcher {
private:
    std::unordered_map<std::string, 
                       std::shared_ptr<signal_handlers::ISignalHandler>> handlers_;
    std::filesystem::path state_dir_;
    std::unordered_set<std::string> processed_signals_;
    src::severity_logger<trivial::severity_level> lg_;
    
public:
    explicit SignalDispatcher(const std::filesystem::path& config_dir) 
        : state_dir_(config_dir / "state") {
        // Ensure state directory exists
        std::filesystem::create_directories(state_dir_);
        load_processed_signals();
    }
    
    /**
     * Register a signal handler.
     * @param handler Shared pointer to the handler
     */
    void register_handler(std::shared_ptr<signal_handlers::ISignalHandler> handler) {
        handlers_[handler->signal_type()] = handler;
        BOOST_LOG_SEV(lg_, trivial::info)
            << "Registered handler for: " << handler->signal_type();
    }
    
    /**
     * Dispatch signal to appropriate handler.
     * Handles deduplication, unknown types, and error recovery.
     * @param signal The signal to dispatch
     * @return IO<void> monad that logs errors and continues
     */
    monad::IO<void> dispatch(const ::data::DeviceUpdateSignal& signal) {
        // Generate unique signal ID for deduplication
        std::string signal_id = make_signal_id(signal);
        
        // Check if already processed
        if (is_processed(signal_id)) {
            BOOST_LOG_SEV(lg_, trivial::debug)
                << "Signal already processed: " << signal_id;
            return monad::IO<void>::pure();
        }
        
        // Find handler
        auto it = handlers_.find(signal.type);
        if (it == handlers_.end()) {
            // Unknown signal type - log and ignore (forward compatibility)
            BOOST_LOG_SEV(lg_, trivial::warning)
                << "Unknown signal type: " << signal.type << " (ignored)";
            return monad::IO<void>::pure();
        }
        
        // Check if handler wants to process this signal
        if (!it->second->should_process(signal)) {
            BOOST_LOG_SEV(lg_, trivial::debug)
                << "Handler skipped signal: " << signal.type;
            mark_as_processed(signal_id); // Still mark as processed to avoid retries
            return monad::IO<void>::pure();
        }
        
        // Execute handler
        return it->second->handle(signal)
            .then([this, signal_id, type = signal.type]() {
                // Mark as successfully processed
                mark_as_processed(signal_id);
                BOOST_LOG_SEV(lg_, trivial::info)
                    << "Signal processed successfully: " << type;
                return monad::IO<void>::pure();
            })
            .catch_then([this, signal_id, type = signal.type](monad::Error e) {
                // Log error and continue (don't block polling)
                BOOST_LOG_SEV(lg_, trivial::error)
                    << "Signal handler failed: type=" << type
                    << " error=" << e.what;
                // Don't mark as processed - might retry later if cursor resets
                return monad::IO<void>::pure();
            });
    }
    
    /**
     * Get count of registered handlers.
     */
    size_t handler_count() const {
        return handlers_.size();
    }
    
    /**
     * Get count of processed signals in memory.
     */
    size_t processed_count() const {
        return processed_signals_.size();
    }
    
private:
    /**
     * Generate unique signal ID from type and timestamp.
     */
    std::string make_signal_id(const ::data::DeviceUpdateSignal& signal) const {
        // Use type + timestamp as unique ID
        return signal.type + ":" + std::to_string(signal.ts_ms);
    }
    
    /**
     * Check if signal has already been processed.
     */
    bool is_processed(const std::string& signal_id) const {
        return processed_signals_.find(signal_id) != processed_signals_.end();
    }
    
    /**
     * Mark signal as processed and persist to disk.
     */
    void mark_as_processed(const std::string& signal_id) {
        processed_signals_.insert(signal_id);
        save_processed_signals();
    }
    
    /**
     * Load processed signals from disk on startup.
     */
    void load_processed_signals() {
        auto file = state_dir_ / "processed_signals.json";
        if (!std::filesystem::exists(file)) {
            BOOST_LOG_SEV(lg_, trivial::debug)
                << "No processed signals file found (first run)";
            return;
        }
        
        try {
            std::ifstream ifs(file);
            std::string content((std::istreambuf_iterator<char>(ifs)),
                               std::istreambuf_iterator<char>());
            
            auto jv = boost::json::parse(content);
            auto& arr = jv.as_array();
            
            for (const auto& item : arr) {
                processed_signals_.insert(std::string(item.as_string()));
            }
            
            BOOST_LOG_SEV(lg_, trivial::info)
                << "Loaded " << processed_signals_.size() 
                << " processed signals from disk";
        } catch (const std::exception& e) {
            BOOST_LOG_SEV(lg_, trivial::error)
                << "Failed to load processed signals: " << e.what();
        }
    }
    
    /**
     * Save processed signals to disk atomically.
     * Keeps only recent signals (last 1000 or last 7 days).
     */
    void save_processed_signals() {
        auto file = state_dir_ / "processed_signals.json";
        auto temp_file = state_dir_ / ".processed_signals.json.tmp";
        
        try {
            boost::json::array arr;
            
            // Keep only recent signals (last 1000 or last 7 days)
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            
            std::vector<std::pair<int64_t, std::string>> signals_with_ts;
            
            for (const auto& sig_id : processed_signals_) {
                // Parse timestamp from signal_id (format: "type:timestamp_ms")
                auto pos = sig_id.find(':');
                if (pos != std::string::npos) {
                    try {
                        int64_t ts_ms = std::stoll(sig_id.substr(pos + 1));
                        // Keep signals from last 7 days
                        if (now_ms - ts_ms < 7 * 24 * 3600 * 1000LL) {
                            signals_with_ts.push_back({ts_ms, sig_id});
                        }
                    } catch (const std::exception&) {
                        // Invalid timestamp, skip
                        continue;
                    }
                }
            }
            
            // Sort by timestamp descending
            std::sort(signals_with_ts.begin(), signals_with_ts.end(),
                     [](const auto& a, const auto& b) { return a.first > b.first; });
            
            // Limit to last 1000 signals
            size_t limit = std::min(signals_with_ts.size(), size_t(1000));
            for (size_t i = 0; i < limit; ++i) {
                arr.push_back(boost::json::value(signals_with_ts[i].second));
            }
            
            // Write atomically
            {
                std::ofstream ofs(temp_file);
                ofs << boost::json::serialize(arr);
            }
            
            std::filesystem::rename(temp_file, file);
            std::filesystem::permissions(file, 
                std::filesystem::perms::owner_read | 
                std::filesystem::perms::owner_write);
                
        } catch (const std::exception& e) {
            BOOST_LOG_SEV(lg_, trivial::error)
                << "Failed to save processed signals: " << e.what();
        }
    }
};

} // namespace certctrl
