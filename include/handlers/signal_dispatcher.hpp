#pragma once

#include "data/data_shape.hpp"
#include "signal_handlers/signal_handler_base.hpp"
#include "state/device_state_store.hpp"
#include "util/my_logging.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
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
    certctrl::IDeviceStateStore *state_store_{nullptr};
    std::unordered_set<std::string> processed_signals_;
    src::severity_logger<trivial::severity_level> lg_;
    
public:
    explicit SignalDispatcher(const std::filesystem::path& config_dir,
                              certctrl::IDeviceStateStore *state_store = nullptr)
        : state_dir_(config_dir / "state"), state_store_(state_store) {
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
        BOOST_LOG_SEV(lg_, trivial::trace)
            << "Registered handler for: " << handler->signal_type();
    }
    
    /**
     * Dispatch signal to appropriate handler.
     * Handles deduplication, unknown types, and error recovery.
     * @param signal The signal to dispatch
        * @return IO<void> monad. Unknown signal types are treated as successful
        *         (forward compatibility). Real handler failures are propagated as
        *         errors so callers can decide whether to ack/advance cursors.
     */
    monad::IO<void> dispatch(const ::data::DeviceUpdateSignal& signal) {
        // Generate unique signal ID for deduplication
        std::string signal_id = make_signal_id(signal);
        
        // Check if already processed
        if (is_processed(signal_id)) {
            BOOST_LOG_SEV(lg_, trivial::trace)
                << "Signal already processed: " << signal_id;
            return monad::IO<void>::pure();
        }
        
        // Find handler
        auto it = handlers_.find(signal.type);
        if (it == handlers_.end()) {
            // Unknown signal type - log and ignore (forward compatibility)
            BOOST_LOG_SEV(lg_, trivial::warning)
                << "Unknown signal type: " << signal.type << " (ignored)";
            // Treat as successfully processed for delivery progress.
            mark_as_processed(signal_id);
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
            .catch_then([this, type = signal.type](monad::Error e) {
                // Don't mark as processed - allow retry/redelivery.
                BOOST_LOG_SEV(lg_, trivial::error)
                    << "Signal handler failed: type=" << type
                    << " error=" << e.what;
                return monad::IO<void>::fail(std::move(e));
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
        if (state_store_) {
            if (auto stored = state_store_->get_processed_signals_json()) {
                if (!stored->empty() && hydrate_from_serialized(*stored)) {
                    BOOST_LOG_SEV(lg_, trivial::info)
                        << "Loaded " << processed_signals_.size()
                        << " processed signals from SQLite";
                    remove_legacy_processed_signals_file();
                    return;
                }
            }
        }

        if (load_from_legacy_file()) {
            BOOST_LOG_SEV(lg_, trivial::info)
                << "Loaded " << processed_signals_.size()
                << " processed signals from disk";
            migrate_file_payload_to_store();
        }
    }

    /**
     * Save processed signals to persistent storage.
     * Keeps only recent signals (last 1000 or last 7 days).
     */
    void save_processed_signals() {
        try {
            auto serialized = serialize_processed_signals();
            persist_processed_signals(serialized);
        } catch (const std::exception &e) {
            BOOST_LOG_SEV(lg_, trivial::error)
                << "Failed to save processed signals: " << e.what();
        }
    }

    bool hydrate_from_serialized(const std::string &payload) {
        try {
            auto jv = boost::json::parse(payload);
            const auto &arr = jv.as_array();
            processed_signals_.clear();
            for (const auto &item : arr) {
                processed_signals_.insert(std::string(item.as_string()));
            }
            return true;
        } catch (const std::exception &e) {
            BOOST_LOG_SEV(lg_, trivial::error)
                << "Failed to parse processed signals payload: " << e.what();
            return false;
        }
    }

    bool load_from_legacy_file() {
        auto file = state_dir_ / "processed_signals.json";
        if (!std::filesystem::exists(file)) {
            BOOST_LOG_SEV(lg_, trivial::debug)
                << "No processed signals file found (first run)";
            return false;
        }

        try {
            std::ifstream ifs(file);
            std::string content((std::istreambuf_iterator<char>(ifs)),
                                std::istreambuf_iterator<char>());
            return hydrate_from_serialized(content);
        } catch (const std::exception &e) {
            BOOST_LOG_SEV(lg_, trivial::error)
                << "Failed to load processed signals: " << e.what();
            return false;
        }
    }

    std::string serialize_processed_signals() const {
        boost::json::array arr;
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

        std::vector<std::pair<int64_t, std::string>> signals_with_ts;
        signals_with_ts.reserve(processed_signals_.size());

        for (const auto &sig_id : processed_signals_) {
            auto pos = sig_id.find(':');
            if (pos == std::string::npos) {
                continue;
            }
            try {
                int64_t ts_ms = std::stoll(sig_id.substr(pos + 1));
                if (now_ms - ts_ms < 7 * 24 * 3600 * 1000LL) {
                    signals_with_ts.emplace_back(ts_ms, sig_id);
                }
            } catch (const std::exception &) {
                continue;
            }
        }

        std::sort(signals_with_ts.begin(), signals_with_ts.end(),
                  [](const auto &a, const auto &b) { return a.first > b.first; });

        size_t limit = std::min(signals_with_ts.size(), size_t(1000));
        for (size_t i = 0; i < limit; ++i) {
            arr.push_back(boost::json::value(signals_with_ts[i].second));
        }

        return boost::json::serialize(arr);
    }

    void persist_processed_signals(const std::string &payload) {
        bool saved = false;
        if (state_store_) {
            const std::optional<std::string> serialized(payload);
            if (auto err = state_store_->save_processed_signals_json(serialized)) {
                BOOST_LOG_SEV(lg_, trivial::error)
                    << "Failed to write processed signals to SQLite: " << *err;
            } else {
                saved = true;
                remove_legacy_processed_signals_file();
            }
        }

        if (!saved) {
            save_processed_signals_to_file(payload);
        }
    }

    void migrate_file_payload_to_store() {
        if (!state_store_) {
            return;
        }

        const auto payload = serialize_processed_signals();
        const std::optional<std::string> serialized(payload);
        if (auto err = state_store_->save_processed_signals_json(serialized)) {
            BOOST_LOG_SEV(lg_, trivial::warning)
                << "Failed to migrate processed signals to SQLite: " << *err;
            return;
        }
        remove_legacy_processed_signals_file();
    }

    void save_processed_signals_to_file(const std::string &payload) {
        auto file = state_dir_ / "processed_signals.json";
        auto temp_file = state_dir_ / ".processed_signals.json.tmp";

        try {
            std::filesystem::create_directories(state_dir_);
            {
                std::ofstream ofs(temp_file);
                ofs << payload;
            }

            std::filesystem::rename(temp_file, file);
            std::filesystem::permissions(
                file, std::filesystem::perms::owner_read |
                          std::filesystem::perms::owner_write);
        } catch (const std::exception &e) {
            BOOST_LOG_SEV(lg_, trivial::error)
                << "Failed to save processed signals to file: " << e.what();
        }
    }

    void remove_legacy_processed_signals_file() const {
        auto file = state_dir_ / "processed_signals.json";
        auto temp_file = state_dir_ / ".processed_signals.json.tmp";
        std::error_code ec;
        std::filesystem::remove(file, ec);
        std::filesystem::remove(temp_file, ec);
    }
};

} // namespace certctrl
