#pragma once

#include "data/data_shape.hpp"
#include "my_error_codes.hpp"
#include "signal_handlers/signal_handler_base.hpp"
#include "state/device_state_store.hpp"
#include <algorithm>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/json.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/trivial.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace certctrl {

/**
 * Signal dispatcher that routes update signals to appropriate handlers.
 * Handles deduplication by persisting processed signal IDs.
 */
class SignalDispatcher {
public:
  using PostSuccessHook =
      std::function<boost::asio::awaitable<monad::MyResult<void>>(
          const ::data::DeviceUpdateSignal &)>;

private:
  using SignalWaiter = boost::asio::experimental::concurrent_channel<void(
      boost::system::error_code, monad::MyResult<void>)>;

  std::unordered_map<std::string,
                     std::shared_ptr<signal_handlers::ISignalHandler>>
      handlers_;
  std::filesystem::path state_dir_;
  certctrl::IDeviceStateStore *state_store_{nullptr};
  PostSuccessHook post_success_hook_;
  std::unordered_set<std::string> processed_signals_;
  std::unordered_map<std::string, std::vector<std::shared_ptr<SignalWaiter>>>
      inflight_signals_;
  mutable std::mutex signals_mutex_;
  boost::log::sources::severity_logger<boost::log::trivial::severity_level> lg_;

public:
  explicit SignalDispatcher(const std::filesystem::path &config_dir,
                            certctrl::IDeviceStateStore *state_store = nullptr,
                            PostSuccessHook post_success_hook = {})
      : state_dir_(config_dir / "state"), state_store_(state_store),
        post_success_hook_(std::move(post_success_hook)) {
    // Ensure state directory exists
    std::filesystem::create_directories(state_dir_);
    load_processed_signals();
  }

  /**
   * Register a signal handler.
   * @param handler Shared pointer to the handler
   */
  void
  register_handler(std::shared_ptr<signal_handlers::ISignalHandler> handler) {
    handlers_[handler->signal_type()] = handler;
    BOOST_LOG_SEV(lg_, boost::log::trivial::trace)
        << "Registered handler for: " << handler->signal_type();
  }

  /**
   * Dispatch signal to appropriate handler.
   * Handles deduplication, unknown types, and error recovery.
   * @param signal The signal to dispatch
   * @return Awaitable structured result. Unknown signal types are treated as
   *         successful for forward compatibility. Real handler failures are
   *         propagated so callers can decide whether to ack/advance cursors.
   */
  boost::asio::awaitable<monad::MyResult<void>>
  dispatch_awaitable(const ::data::DeviceUpdateSignal &signal) {
    const std::string signal_id = make_signal_id(signal);
    auto executor = co_await boost::asio::this_coro::executor;
    auto waiter = std::make_shared<SignalWaiter>(executor, 1);

    const auto claim_status = try_claim(signal_id, waiter);
    if (claim_status == ClaimStatus::Processed) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::trace)
          << "Signal already processed: " << signal_id;
      co_return monad::MyResult<void>::Ok();
    }
    if (claim_status == ClaimStatus::Joined) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::trace)
          << "Joining in-flight signal: " << signal_id;
      co_return co_await waiter->async_receive(boost::asio::use_awaitable);
    }

    struct ClaimGuard {
      SignalDispatcher &dispatcher;
      const std::string &signal_id;
      bool completed{false};

      ~ClaimGuard() {
        if (!completed) {
          dispatcher.finish_claim(
              signal_id,
              monad::MyResult<void>::Err(monad::make_error(
                  my_errors::GENERAL::UNEXPECTED_RESULT,
                  "Signal dispatch exited before completion")),
              false);
        }
      }
    } claim{*this, signal_id};

    // Find handler
    auto it = handlers_.find(signal.type);
    if (it == handlers_.end()) {
      // Unknown signal type - log and ignore (forward compatibility)
      BOOST_LOG_SEV(lg_, boost::log::trivial::warning)
          << "Unknown signal type: " << signal.type << " (ignored)";
      co_await run_post_success_hook(signal);
      finish_claim(signal_id, monad::MyResult<void>::Ok(), true);
      claim.completed = true;
      co_return monad::MyResult<void>::Ok();
    }

    // Check if handler wants to process this signal
    if (!it->second->should_process(signal)) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::debug)
          << "Handler skipped signal: " << signal.type;
      finish_claim(signal_id, monad::MyResult<void>::Ok(), true);
      claim.completed = true;
      co_return monad::MyResult<void>::Ok();
    }

    monad::MyResult<void> result;
    try {
      result = co_await it->second->handle_awaitable(signal);
    } catch (const std::exception &ex) {
      result = monad::MyResult<void>::Err(monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT,
          std::string{"Signal handler coroutine failed: "} + ex.what()));
    } catch (...) {
      result = monad::MyResult<void>::Err(monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT,
          "Signal handler coroutine failed with an unknown exception"));
    }

    if (result.is_err()) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::error)
          << "Signal handler failed: type=" << signal.type
          << " error=" << result.error().what;
      finish_claim(signal_id, result, false);
      claim.completed = true;
      co_return result;
    }

    co_await run_post_success_hook(signal);
    finish_claim(signal_id, monad::MyResult<void>::Ok(), true);
    claim.completed = true;
    BOOST_LOG_SEV(lg_, boost::log::trivial::info)
        << "Signal processed successfully: " << signal.type;
    co_return monad::MyResult<void>::Ok();
  }

  /**
   * Get count of registered handlers.
   */
  size_t handler_count() const { return handlers_.size(); }

  /**
   * Get count of processed signals in memory.
   */
  size_t processed_count() const {
    std::lock_guard<std::mutex> lock(signals_mutex_);
    return processed_signals_.size();
  }

private:
  enum class ClaimStatus { Owner, Joined, Processed };

  /**
   * Generate unique signal ID from type and timestamp.
   */
  std::string make_signal_id(const ::data::DeviceUpdateSignal &signal) const {
    // Use type + timestamp as unique ID
    return signal.type + ":" + std::to_string(signal.ts_ms);
  }

  /**
   * Check if signal has already been processed.
   */
  ClaimStatus try_claim(const std::string &signal_id,
                        const std::shared_ptr<SignalWaiter> &waiter) {
    std::lock_guard<std::mutex> lock(signals_mutex_);
    if (processed_signals_.contains(signal_id)) {
      return ClaimStatus::Processed;
    }
    if (auto it = inflight_signals_.find(signal_id);
        it != inflight_signals_.end()) {
      it->second.push_back(waiter);
      return ClaimStatus::Joined;
    }
    inflight_signals_.emplace(signal_id,
                              std::vector<std::shared_ptr<SignalWaiter>>{});
    return ClaimStatus::Owner;
  }

  void finish_claim(const std::string &signal_id,
                    const monad::MyResult<void> &result, bool mark_processed) {
    std::vector<std::shared_ptr<SignalWaiter>> waiters;
    {
      std::lock_guard<std::mutex> lock(signals_mutex_);
      if (auto it = inflight_signals_.find(signal_id);
          it != inflight_signals_.end()) {
        waiters = std::move(it->second);
        inflight_signals_.erase(it);
      }
      if (mark_processed) {
        processed_signals_.insert(signal_id);
        save_processed_signals();
      }
    }
    for (const auto &waiter : waiters) {
      waiter->try_send(boost::system::error_code{}, result);
    }
  }

  boost::asio::awaitable<void>
  run_post_success_hook(const ::data::DeviceUpdateSignal &signal) {
    if (!post_success_hook_) {
      co_return;
    }

    try {
      auto result = co_await post_success_hook_(signal);
      if (result.is_err()) {
        BOOST_LOG_SEV(lg_, boost::log::trivial::warning)
            << "Post-success hook failed for type=" << signal.type
            << " error=" << result.error().what;
      }
    } catch (const std::exception &ex) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::warning)
          << "Post-success hook threw for type=" << signal.type
          << " error=" << ex.what();
    } catch (...) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::warning)
          << "Post-success hook threw for type=" << signal.type;
    }
  }

  /**
   * Load processed signals from disk on startup.
   */
  void load_processed_signals() {
    if (state_store_) {
      if (auto stored = state_store_->get_processed_signals_json()) {
        if (!stored->empty() && hydrate_from_serialized(*stored)) {
          BOOST_LOG_SEV(lg_, boost::log::trivial::info)
              << "Loaded " << processed_signals_.size()
              << " processed signals from SQLite";
          remove_legacy_processed_signals_file();
          return;
        }
      }
    }

    if (load_from_legacy_file()) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::info)
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
      BOOST_LOG_SEV(lg_, boost::log::trivial::error)
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
      BOOST_LOG_SEV(lg_, boost::log::trivial::error)
          << "Failed to parse processed signals payload: " << e.what();
      return false;
    }
  }

  bool load_from_legacy_file() {
    auto file = state_dir_ / "processed_signals.json";
    if (!std::filesystem::exists(file)) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::debug)
          << "No processed signals file found (first run)";
      return false;
    }

    try {
      std::ifstream ifs(file);
      std::string content((std::istreambuf_iterator<char>(ifs)),
                          std::istreambuf_iterator<char>());
      return hydrate_from_serialized(content);
    } catch (const std::exception &e) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::error)
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
        BOOST_LOG_SEV(lg_, boost::log::trivial::error)
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
      BOOST_LOG_SEV(lg_, boost::log::trivial::warning)
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
      std::filesystem::permissions(file,
                                   std::filesystem::perms::owner_read |
                                       std::filesystem::perms::owner_write);
    } catch (const std::exception &e) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::error)
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
