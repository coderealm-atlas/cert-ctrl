#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/system/error_code.hpp>

#include "backoff_utils.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "result_monad.hpp"
#include "state/device_state_store.hpp"

namespace certctrl {

struct CliCtx;

class ISessionRefresher {
public:
  virtual ~ISessionRefresher() = default;
  virtual boost::asio::awaitable<monad::MyResult<void>>
  refresh_awaitable(std::string reason) = 0;
};

class SessionRefresher : public ISessionRefresher,
                         public std::enable_shared_from_this<SessionRefresher> {
public:
  using RequestOverride =
      std::function<boost::asio::awaitable<monad::MyResult<void>>(
          const std::string &refresh_token, int attempt)>;
  using DelayObserver =
      std::function<void(std::chrono::milliseconds wait, int attempt)>;

  SessionRefresher(
      cjj365::IoContextManager &io_context_manager,
      certctrl::ICertctrlConfigProvider &config_provider,
      const certctrl::CliCtx &cli_ctx, customio::ConsoleOutput &output,
      client_async::HttpClientManager &http_client,
      IDeviceStateStore &state_store,
      std::optional<monad::ExponentialBackoffOptions> backoff_override =
          std::nullopt,
      RequestOverride request_override = {}, DelayObserver delay_observer = {});

  boost::asio::awaitable<monad::MyResult<void>>
  refresh_awaitable(std::string reason) override;

private:
  using RefreshChannel = boost::asio::experimental::concurrent_channel<void(
      boost::system::error_code, monad::MyResult<void>)>;

  struct RefreshWaiter {
    explicit RefreshWaiter(boost::asio::any_io_executor executor)
        : completion(std::move(executor), 1) {}

    RefreshChannel completion;
  };

  struct RefreshState {
    std::string primary_reason;
    std::vector<std::string> joined_reasons;
    std::vector<std::shared_ptr<RefreshWaiter>> waiters;
    std::string refresh_token_snapshot;
    monad::JitteredExponentialBackoff backoff;
  };

  void enqueue_refresh(std::string reason,
                       std::shared_ptr<RefreshWaiter> waiter);
  void start_refresh(std::shared_ptr<RefreshState> state);
  static boost::asio::awaitable<void>
  complete_refresh_awaitable(std::shared_ptr<SessionRefresher> self,
                             std::shared_ptr<RefreshState> state);
  boost::asio::awaitable<monad::MyResult<void>>
  run_refresh_awaitable(std::shared_ptr<RefreshState> state);
  boost::asio::awaitable<monad::MyResult<void>>
  attempt_refresh_awaitable(std::shared_ptr<RefreshState> state,
                            const std::string &refresh_token,
                            int first_attempt);
  boost::asio::awaitable<monad::MyResult<void>>
  perform_refresh_request_awaitable(std::shared_ptr<RefreshState> state,
                                    const std::string &refresh_token,
                                    int attempt);

  std::optional<std::string> load_refresh_token() const;
  bool adopt_tokens_from_state(const std::string &original_refresh_token) const;

  static bool is_rotation_error(const monad::Error &err);
  void notify_waiters(std::shared_ptr<RefreshState> state,
                      monad::MyResult<void> result);

  cjj365::IoContextManager &io_context_manager_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  bool keep_running_{false};
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;
  IDeviceStateStore &state_store_;
  monad::ExponentialBackoffOptions refresh_backoff_options_;
  std::mt19937 rng_;
  RequestOverride request_override_;
  DelayObserver delay_observer_;

  std::string refresh_lock_owner_;

  mutable std::mutex mutex_;
  std::shared_ptr<RefreshState> inflight_;
};

} // namespace certctrl
