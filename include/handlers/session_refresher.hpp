#pragma once

#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"

namespace certctrl {

class ISessionRefresher {
public:
  virtual ~ISessionRefresher() = default;
  virtual monad::IO<void> refresh(std::string reason) = 0;
};

class SessionRefresher : public ISessionRefresher,
                         public std::enable_shared_from_this<SessionRefresher> {
public:
  SessionRefresher(cjj365::IoContextManager &io_context_manager,
                   certctrl::ICertctrlConfigProvider &config_provider,
                   customio::ConsoleOutput &output,
                   client_async::HttpClientManager &http_client);

  monad::IO<void> refresh(std::string reason) override;

private:
  using RefreshCallback = monad::IO<void>::Callback;

  struct RefreshState {
    std::string primary_reason;
    std::vector<std::string> joined_reasons;
    std::vector<RefreshCallback> callbacks;
    std::string refresh_token_snapshot;
  };

  void enqueue_refresh(std::string reason, RefreshCallback cb);
  void start_refresh(std::shared_ptr<RefreshState> state);
  monad::IO<void> build_refresh_io(std::shared_ptr<RefreshState> state);
  monad::IO<void> attempt_refresh(std::shared_ptr<RefreshState> state,
                                  int attempt,
                                  std::chrono::milliseconds delay);
    monad::IO<void> perform_refresh_request(
      std::shared_ptr<RefreshState> state, const std::string &refresh_token,
      int attempt);
  monad::IO<void> handle_refresh_error(std::shared_ptr<RefreshState> state,
                                       monad::Error err);

  std::optional<std::string> load_refresh_token() const;
  bool detect_external_refresh(const std::string &original_token) const;
  std::optional<std::string>
  write_text_0600(const std::filesystem::path &p, const std::string &text);
  std::filesystem::path state_dir() const;

  static bool is_rotation_error(const monad::Error &err);
  void notify_callbacks(std::shared_ptr<RefreshState> state,
                        monad::Result<void, monad::Error> result);

  cjj365::IoContextManager &io_context_manager_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;
  std::filesystem::path runtime_dir_;

  mutable std::mutex mutex_;
  std::shared_ptr<RefreshState> inflight_;
};

} // namespace certctrl
