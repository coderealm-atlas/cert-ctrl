#include "handlers/session_refresher.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <fmt/format.h>

#include "certctrl_common.hpp"
#include "handlers/session_refresh_retry.hpp"
#include "http_client_awaitable.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <random>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace certctrl {

namespace asio = boost::asio;

namespace {

constexpr int kRefreshTokenRotatedCode = 10003;
constexpr std::string_view kRefreshTokenRotatedKey = "refresh_token_rotated";

struct ApiErrorDetails {
  std::optional<int> code;
  std::optional<std::string> key;
  std::optional<std::string> message;
};

class RefreshLockGuard {
public:
  RefreshLockGuard(IDeviceStateStore &state_store, std::string_view owner)
      : state_store_(state_store), owner_(owner) {}

  RefreshLockGuard(const RefreshLockGuard &) = delete;
  RefreshLockGuard &operator=(const RefreshLockGuard &) = delete;

  ~RefreshLockGuard() { (void)state_store_.release_refresh_lock(owner_); }

private:
  IDeviceStateStore &state_store_;
  std::string owner_;
};

void capture_error_fields(const boost::json::value &val,
                          ApiErrorDetails &details) {
  if (!val.is_object()) {
    return;
  }

  const auto &obj = val.as_object();
  if (!details.code) {
    if (auto *code = obj.if_contains("code")) {
      if (code->is_int64()) {
        details.code = static_cast<int>(code->as_int64());
      } else if (code->is_string()) {
        try {
          details.code = std::stoi(code->as_string().c_str());
        } catch (...) {
        }
      }
    }
  }

  if (!details.key) {
    if (auto *key = obj.if_contains("key"); key && key->is_string()) {
      details.key = boost::json::value_to<std::string>(*key);
    }
  }

  if (!details.message) {
    if (auto *msg = obj.if_contains("message"); msg && msg->is_string()) {
      details.message = boost::json::value_to<std::string>(*msg);
    } else if (auto *error_msg = obj.if_contains("error");
               error_msg && error_msg->is_string()) {
      details.message = boost::json::value_to<std::string>(*error_msg);
    }
  }

  if (auto *err = obj.if_contains("error")) {
    capture_error_fields(*err, details);
  }
  if (auto *data = obj.if_contains("data")) {
    capture_error_fields(*data, details);
  }
}

std::optional<ApiErrorDetails>
parse_api_error_details(std::string_view raw_body) {
  if (raw_body.empty()) {
    return std::nullopt;
  }

  try {
    auto parsed = boost::json::parse(raw_body);
    ApiErrorDetails details;
    capture_error_fields(parsed, details);
    if (details.code || details.key || details.message) {
      return details;
    }
  } catch (...) {
  }

  return std::nullopt;
}

bool is_rotation_code(const ApiErrorDetails &details) {
  if (details.code && *details.code == kRefreshTokenRotatedCode) {
    return true;
  }
  if (details.key && *details.key == kRefreshTokenRotatedKey) {
    return true;
  }
  if (details.message) {
    return boost::beast::iequals(*details.message,
                                 "refresh token has been rotated") ||
           details.message->find("rotated") != std::string::npos;
  }
  return false;
}

bool iequals(std::string_view haystack, std::string_view needle) {
  auto it = std::search(
      haystack.begin(), haystack.end(), needle.begin(), needle.end(),
      [](char a, char b) { return std::tolower(a) == std::tolower(b); });
  return it != haystack.end();
}
} // namespace

SessionRefresher::SessionRefresher(
    cjj365::IoContextManager &io_context_manager,
    certctrl::ICertctrlConfigProvider &config_provider,
    const certctrl::CliCtx &cli_ctx, customio::ConsoleOutput &output,
    client_async::HttpClientManager &http_client,
    IDeviceStateStore &state_store,
    std::optional<monad::ExponentialBackoffOptions> backoff_override,
    RequestOverride request_override, DelayObserver delay_observer)
    : io_context_manager_(io_context_manager),
      config_provider_(config_provider), output_(output),
      keep_running_(cli_ctx.params.keep_running), http_client_(http_client),
      state_store_(state_store), refresh_backoff_options_{},
      rng_(std::random_device{}()),
      request_override_(std::move(request_override)),
      delay_observer_(std::move(delay_observer)) {
#ifdef _WIN32
  refresh_lock_owner_ = "winproc";
#else
  refresh_lock_owner_ =
      fmt::format("pid:{}", static_cast<long long>(::getpid()));
#endif
  monad::ExponentialBackoffOptions defaults;
  defaults.initial_delay = session_refresh::kInitialRetryDelay;
  defaults.max_delay = session_refresh::kMaxRetryDelay;
  defaults.jitter = std::chrono::milliseconds::zero();
  refresh_backoff_options_ = backoff_override.value_or(defaults);
}

asio::awaitable<monad::MyResult<void>>
SessionRefresher::refresh_awaitable(std::string reason) {
  auto executor = co_await asio::this_coro::executor;
  auto waiter = std::make_shared<RefreshWaiter>(executor);
  enqueue_refresh(std::move(reason), waiter);
  co_return co_await waiter->completion.async_receive(asio::use_awaitable);
}

void SessionRefresher::enqueue_refresh(std::string reason,
                                       std::shared_ptr<RefreshWaiter> waiter) {
  std::shared_ptr<RefreshState> to_start;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!inflight_) {
      inflight_ = std::make_shared<RefreshState>();
      inflight_->primary_reason = std::move(reason);
      inflight_->backoff.UpdateOptions(refresh_backoff_options_);
      inflight_->backoff.Reset();
      to_start = inflight_;
    } else {
      inflight_->joined_reasons.push_back(std::move(reason));
    }
    inflight_->waiters.push_back(std::move(waiter));
  }

  if (to_start) {
    start_refresh(std::move(to_start));
  } else {
    output_.logger().trace()
        << "Joining in-flight session refresh" << std::endl;
  }
}

void SessionRefresher::start_refresh(std::shared_ptr<RefreshState> state) {
  asio::co_spawn(
      io_context_manager_.ioc(),
      complete_refresh_awaitable(shared_from_this(), std::move(state)),
      asio::detached);
}

asio::awaitable<void> SessionRefresher::complete_refresh_awaitable(
    std::shared_ptr<SessionRefresher> self,
    std::shared_ptr<RefreshState> state) {
  monad::MyResult<void> result = monad::MyResult<void>::Ok();
  try {
    result = co_await self->run_refresh_awaitable(state);
  } catch (const std::exception &ex) {
    result = monad::MyResult<void>::Err(monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        std::string{"Session refresh coroutine failed: "} + ex.what()));
  } catch (...) {
    result = monad::MyResult<void>::Err(monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        "Session refresh coroutine failed with an unknown exception"));
  }
  self->notify_waiters(std::move(state), std::move(result));
}

asio::awaitable<monad::MyResult<void>>
SessionRefresher::run_refresh_awaitable(std::shared_ptr<RefreshState> state) {
  constexpr std::chrono::milliseconds kRefreshLockTtl{
      std::chrono::seconds(120)};
  auto [acquired, lock_err] = state_store_.try_acquire_refresh_lock(
      refresh_lock_owner_, kRefreshLockTtl);
  if (lock_err) {
    co_return monad::MyResult<void>::Err(monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        "Failed to acquire refresh coordination lock: " + *lock_err));
  }
  if (!acquired) {
    if (keep_running_) {
      output_.logger().info()
          << "Another instance is refreshing session tokens; skipping refresh"
          << std::endl;
      co_return monad::MyResult<void>::Ok();
    }

    output_.printer().yellow()
        << "Another cert-ctrl instance is currently refreshing session tokens."
        << std::endl
        << "If you have the service running, please retry in a few seconds."
        << std::endl;
    co_return monad::MyResult<void>::Err(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                          "Refresh already in progress in another instance"));
  }

  RefreshLockGuard refresh_lock(state_store_, refresh_lock_owner_);

  auto refresh_token = load_refresh_token();
  if (!refresh_token || refresh_token->empty()) {
    co_return monad::MyResult<void>::Err(monad::make_error(
        my_errors::GENERAL::INVALID_ARGUMENT,
        "Refresh token not found. Run 'cert-ctrl login' to authenticate."));
  }

  state->refresh_token_snapshot = *refresh_token;
  auto result =
      co_await attempt_refresh_awaitable(state, *refresh_token, /*attempt=*/1);
  co_return result;
}

asio::awaitable<monad::MyResult<void>>
SessionRefresher::attempt_refresh_awaitable(std::shared_ptr<RefreshState> state,
                                            const std::string &refresh_token,
                                            int first_attempt) {
  for (int attempt = first_attempt;; ++attempt) {
    auto result = co_await perform_refresh_request_awaitable(
        state, refresh_token, attempt);
    if (result.is_ok()) {
      co_return result;
    }

    auto error = std::move(result).error();
    if (is_rotation_error(error) &&
        adopt_tokens_from_state(state->refresh_token_snapshot)) {
      output_.logger().info()
          << "Detected external session refresh while handling reason '"
          << state->primary_reason
          << "'; using updated tokens from shared state instead of failing"
          << std::endl;
      co_return monad::MyResult<void>::Ok();
    }

    if (is_rotation_error(error)) {
      output_.logger().warning()
          << "Session refresh aborted because the server rotated the refresh "
             "token family."
          << std::endl;
      output_.printer().yellow()
          << "Device session refresh failed because the refresh token has "
             "been rotated upstream."
          << std::endl
          << "Please rerun 'cert-ctrl login --force' to re-authorize this "
             "device."
          << std::endl;
      co_return monad::MyResult<void>::Err(std::move(error));
    }

    if (!session_refresh::is_retryable_error(error)) {
      co_return monad::MyResult<void>::Err(std::move(error));
    }

    auto wait = state->backoff.NextDelay(rng_);
    if (delay_observer_) {
      delay_observer_(wait, attempt);
    }
    output_.logger().warning() << "Device session refresh attempt " << attempt
                               << " failed: " << error.what << "; retrying in "
                               << wait.count() << "ms" << std::endl;

    asio::steady_timer timer(co_await asio::this_coro::executor);
    timer.expires_after(wait);
    boost::system::error_code timer_error;
    co_await timer.async_wait(
        asio::redirect_error(asio::use_awaitable, timer_error));
    if (timer_error) {
      co_return monad::MyResult<void>::Err(monad::make_error(
          timer_error.value(),
          "Session refresh retry timer failed: " + timer_error.message()));
    }
  }
}

asio::awaitable<monad::MyResult<void>>
SessionRefresher::perform_refresh_request_awaitable(
    std::shared_ptr<RefreshState> state, const std::string &refresh_token,
    int attempt) {
  if (request_override_) {
    co_return co_await request_override_(refresh_token, attempt);
  }

  const auto refresh_url =
      fmt::format("{}/auth/refresh", config_provider_.get().base_url);
  output_.logger().info() << "Refreshing device session via " << refresh_url
                          << " (reason: " << state->primary_reason
                          << ", attempt " << attempt << ')' << std::endl;

  auto exchange_result =
      async_support::make_http_exchange<monad::PostJsonTag>(refresh_url);
  if (exchange_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  exchange->setRequestJsonBody(
      boost::json::object{{"refresh_token", refresh_token}});
  auto request_result =
      co_await async_support::http_exchange_awaitable<monad::PostJsonTag>(
          http_client_, std::move(exchange));
  if (request_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(request_result).error());
  }
  exchange = std::move(request_result).value();

  if (!exchange->is_2xx()) {
    std::string error_msg = "Refresh token request failed";
    int status = 0;
    std::string response_body;
    if (exchange->response) {
      status = exchange->response->result_int();
      error_msg += " (HTTP " + std::to_string(status) + ")";
      if (!exchange->response->body().empty()) {
        response_body = std::string(exchange->response->body());
        error_msg += ": " + response_body;
      }
    }

    if (auto api_error = parse_api_error_details(response_body);
        api_error && is_rotation_code(*api_error)) {
      std::string base_msg = api_error->message.value_or(
          "Refresh token has been rotated by the server");
      auto error = monad::make_error(
          my_errors::GENERAL::UNAUTHORIZED,
          fmt::format(
              "{} (code {}) - please rerun 'cert-ctrl login --force' to "
              "re-authorize this device.",
              base_msg, kRefreshTokenRotatedCode));
      error.key = std::string{kRefreshTokenRotatedKey};
      error.response_status = status;
      error.params["server_code"] = kRefreshTokenRotatedCode;
      error.params["server_message"] = base_msg;
      co_return monad::MyResult<void>::Err(std::move(error));
    }

    auto error = monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                                   std::move(error_msg));
    error.response_status = status;
    co_return monad::MyResult<void>::Err(std::move(error));
  }

  auto payload_result =
      exchange->template parseJsonDataResponse<boost::json::object>();
  if (payload_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(payload_result).error());
  }

  auto payload = std::move(payload_result).value();
  const boost::json::object *data = &payload;
  if (auto *nested = payload.if_contains("data");
      nested && nested->is_object()) {
    data = &nested->as_object();
  }

  auto get_string = [](const boost::json::object &object,
                       std::string_view key) -> std::optional<std::string> {
    if (auto *value = object.if_contains(key); value && value->is_string()) {
      return boost::json::value_to<std::string>(*value);
    }
    return std::nullopt;
  };

  auto new_access_token = get_string(*data, "access_token");
  auto new_refresh_token = get_string(*data, "refresh_token");
  std::optional<int> new_expires_in;
  if (auto *value = data->if_contains("expires_in");
      value && value->is_number()) {
    new_expires_in = boost::json::value_to<int>(*value);
  }

  if ((!new_access_token || !new_refresh_token) &&
      data->if_contains("session")) {
    if (auto *session = data->if_contains("session");
        session && session->is_object()) {
      const auto &session_object = session->as_object();
      if (!new_access_token) {
        new_access_token = get_string(session_object, "access_token");
      }
      if (!new_refresh_token) {
        new_refresh_token = get_string(session_object, "refresh_token");
      }
      if (!new_expires_in) {
        if (auto *value = session_object.if_contains("expires_in");
            value && value->is_number()) {
          new_expires_in = boost::json::value_to<int>(*value);
        }
      }
    }
  }

  if (!new_access_token || new_access_token->empty() || !new_refresh_token ||
      new_refresh_token->empty()) {
    co_return monad::MyResult<void>::Err(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                          "Refresh response missing tokens"));
  }

  if (auto error = state_store_.save_tokens(new_access_token, new_refresh_token,
                                            new_expires_in)) {
    output_.logger().warning()
        << "Failed to persist refreshed tokens in state store: " << *error
        << std::endl;
  }

  output_.logger().trace()
      << "Device session refreshed; new access token expires in "
      << new_expires_in.value_or(0) << "s" << std::endl;
  co_return monad::MyResult<void>::Ok();
}

std::optional<std::string> SessionRefresher::load_refresh_token() const {
  if (auto stored = state_store_.get_refresh_token();
      stored && !stored->empty()) {
    return stored;
  }
  return std::nullopt;
}

bool SessionRefresher::adopt_tokens_from_state(
    const std::string &original_refresh_token) const {
  auto latest_refresh = state_store_.get_refresh_token();
  return latest_refresh && !latest_refresh->empty() &&
         *latest_refresh != original_refresh_token;
}

bool SessionRefresher::is_rotation_error(const monad::Error &err) {
  if (err.key == kRefreshTokenRotatedKey) {
    return true;
  }

  if (auto *server_code = err.params.if_contains("server_code");
      server_code && server_code->is_int64() &&
      server_code->as_int64() == kRefreshTokenRotatedCode) {
    return true;
  }

  return iequals(err.what, "refresh token has been rotated") ||
         err.what.find("rotated") != std::string::npos;
}

void SessionRefresher::notify_waiters(std::shared_ptr<RefreshState> state,
                                      monad::MyResult<void> result) {
  std::vector<std::shared_ptr<RefreshWaiter>> waiters;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (inflight_ == state) {
      inflight_.reset();
    }
    waiters = std::move(state->waiters);
  }

  for (auto &waiter : waiters) {
    if (waiter &&
        !waiter->completion.try_send(boost::system::error_code{}, result)) {
      output_.logger().warning()
          << "Failed to deliver session refresh result to a waiter"
          << std::endl;
    }
  }
}

} // namespace certctrl
