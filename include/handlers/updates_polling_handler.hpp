#pragma once

#include <algorithm>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fmt/format.h>
#include <memory>
#include <optional>
#include <string>
#include <vector> // indirectly needed via data structures; keep if build complains

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/data_shape.hpp"
#include "handlers/i_handler.hpp"
#include "handlers/install_config_manager.hpp"
#include "handlers/session_refresher.hpp"
#include "handlers/signal_dispatcher.hpp"
#include "handlers/signal_handlers/ca_assigned_handler.hpp"
#include "handlers/signal_handlers/ca_unassigned_handler.hpp"
#include "handlers/signal_handlers/cert_unassigned_handler.hpp"
#include "handlers/signal_handlers/cert_updated_handler.hpp"
#include "handlers/signal_handlers/config_updated_handler.hpp"
#include "handlers/signal_handlers/install_updated_handler.hpp"
#include "handlers/signal_handlers/state_resync_required_handler.hpp"
#include "http_client_awaitable.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "my_error_codes.hpp"
#include "state/device_state_store.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep
#include "version.h"
#include <jwt-cpp/jwt.h>

namespace po = boost::program_options;
namespace asio = boost::asio;

namespace certctrl {

struct UpdatesPollingHandlerTestFriend;

// Rough initial implementation of a device updates polling handler. It expects
// that the user already logged in and has a device access token persisted
// somewhere accessible (env var for now). Later refinement can integrate real
// credential / token storage.

struct UpdatesPollingHandlerOptions {
  int wait_seconds{0};
  std::size_t limit{20};
  bool long_poll{false};
};

class UpdatesPollingHandler
    : public certctrl::IHandler,
      public std::enable_shared_from_this<UpdatesPollingHandler> {
  cjj365::ConfigSources &config_sources_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  client_async::HttpClientManager &http_client_;
  customio::ConsoleOutput &output_hub_;
  certctrl::IDeviceStateStore &state_store_;
  CliCtx &cli_ctx_;
  src::severity_logger<trivial::severity_level> lg;
  po::options_description opt_desc_;
  UpdatesPollingHandlerOptions options_;
  std::string endpoint_base_; // /apiv1/devices/self/updates
  std::string cursor_;
  int last_http_status_{0};
  std::optional<::data::DeviceUpdatesResponse> last_updates_;
  std::string parse_error_;
  std::string last_request_url_;
  // loop controls
  int interval_ms_{
      5000}; // delay between polls when not long-polling (default 5s)
  // removed max_loops_ – service runs continuously while keep_running
  int consecutive_failures_{0};
  static constexpr int kFailureRetryBaseMs = 5000;
  static constexpr int kFailureRetryMaxMs = 60000;
  static constexpr int kFailureRetryMaxExponent = 5;
  // signal counters (cumulative this run)
  size_t install_updated_count_{0};
  size_t cert_updated_count_{0};
  size_t cert_unassigned_count_{0};
  // signal dispatcher
  std::unique_ptr<SignalDispatcher> signal_dispatcher_;
  std::shared_ptr<InstallConfigManager> install_config_manager_;
  std::shared_ptr<ISessionRefresher> session_refresher_;
  std::optional<int> server_override_delay_ms_;
  std::optional<std::string> cached_access_token_;
  std::string notify_endpoint_;
  bool notify_sent_this_run_{false};

public:
  UpdatesPollingHandler(
      cjj365::IoContextManager &io_context_manager,                //
      cjj365::ConfigSources &config_sources,                       //
      certctrl::ICertctrlConfigProvider &certctrl_config_provider, //
      CliCtx &cli_ctx,                                             //
      customio::ConsoleOutput &output_hub,                         //
      certctrl::IDeviceStateStore &state_store,                    //
      client_async::HttpClientManager &http_client,                //
      std::shared_ptr<InstallConfigManager> install_config_manager,
      std::shared_ptr<ISessionRefresher> session_refresher)
      : config_sources_(config_sources),
        certctrl_config_provider_(certctrl_config_provider),
        http_client_(http_client), output_hub_(output_hub),
        state_store_(state_store), cli_ctx_(cli_ctx),
        opt_desc_("updates polling options"),
        endpoint_base_(fmt::format("{}/apiv1/devices/self/updates",
                                   certctrl_config_provider_.get().base_url)),
        notify_endpoint_(fmt::format("{}/apiv1/devices/self/notify",
                                     certctrl_config_provider_.get().base_url)),
        install_config_manager_(std::move(install_config_manager)),
        session_refresher_(std::move(session_refresher)) {
    (void)io_context_manager;
    po::options_description create_opts("Updates Polling Options");
    create_opts.add_options()("wait", po::value<int>()->default_value(0),
                              "long poll wait seconds (0-30)")(
        "limit",
        po::value<std::size_t>()->default_value(static_cast<std::size_t>(20)),
        "max signals (1-100)")("interval",
                               po::value<int>()->default_value(5000),
                               "interval milliseconds between polls when not "
                               "long-polling (default 5000 = 5s)");
    opt_desc_.add(create_opts);
    po::parsed_options parsed = po::command_line_parser(cli_ctx_.unrecognized)
                                    .options(opt_desc_)
                                    .allow_unregistered()
                                    .run();
    po::store(parsed, cli_ctx_.vm);
    po::notify(cli_ctx_.vm);
    if (cli_ctx_.vm.count("wait")) {
      options_.wait_seconds = cli_ctx_.vm["wait"].as<int>();
      if (options_.wait_seconds > 0)
        options_.long_poll = true;
    }
    if (cli_ctx_.vm.count("limit")) {
      options_.limit = cli_ctx_.vm["limit"].as<std::size_t>();
    }
    interval_ms_ = certctrl_config_provider_.get().interval_seconds * 1000;
    BOOST_LOG_SEV(lg, trivial::trace)
        << "Using poll interval of " << interval_ms_ << " ms";

    // Initialize signal dispatcher with handlers
    auto runtime_dir = config_sources_.paths_.back();
    auto post_success_hook = [mgr = install_config_manager_](
                                 const ::data::DeviceUpdateSignal &signal)
        -> asio::awaitable<monad::MyResult<void>> {
      if (!mgr) {
        co_return monad::MyResult<void>::Ok();
      }
      co_return co_await mgr->maybe_run_after_update_script_for_signal(signal);
    };
    signal_dispatcher_ = std::make_unique<SignalDispatcher>(
        runtime_dir, &state_store_, std::move(post_success_hook));

    signal_dispatcher_->register_handler(
        std::make_shared<signal_handlers::ConfigUpdatedHandler>(
            certctrl_config_provider_, output_hub_, nullptr));

    if (install_config_manager_) {
      signal_dispatcher_->register_handler(
          std::make_shared<signal_handlers::StateResyncRequiredHandler>(
              install_config_manager_, state_store_, output_hub_));
    }

    if (!install_config_manager_) {
      BOOST_LOG_SEV(lg, trivial::warning)
          << "InstallConfigManager dependency missing; install/update signals "
             "will be skipped";
    } else {
      // Register signal handlers
      signal_dispatcher_->register_handler(
          std::make_shared<signal_handlers::InstallUpdatedHandler>(
              install_config_manager_, output_hub_));

      signal_dispatcher_->register_handler(
          std::make_shared<signal_handlers::CertUpdatedHandler>(
              install_config_manager_, output_hub_));

      signal_dispatcher_->register_handler(
          std::make_shared<signal_handlers::CertUnassignedHandler>(
              install_config_manager_, output_hub_));

      signal_dispatcher_->register_handler(
          std::make_shared<signal_handlers::CaAssignedHandler>(
              install_config_manager_, output_hub_));

      signal_dispatcher_->register_handler(
          std::make_shared<signal_handlers::CaUnassignedHandler>(
              install_config_manager_, output_hub_));
    }

    BOOST_LOG_SEV(lg, trivial::info)
        << "Registered " << signal_dispatcher_->handler_count()
        << " signal handlers";

    load_cursor_from_state();
  }

  std::string command() const override { return "updates"; }

  monad::MyResult<void> show_usage(const std::string &error = "") const {
    if (!error.empty()) {
      output_hub_.logger().error() << error << std::endl;
    }
    output_hub_.logger().info() << "Usage: cert-ctrl updates [clear-cursor] "
                                   "[--wait N] [--limit N] [--interval MS]\n"
                                << "  clear-cursor   Remove the persisted HTTP "
                                   "polling cursor from SQLite\n"
                                << std::endl;
    return monad::MyResult<void>::Ok();
  }

  const std::string &last_request_url() const noexcept {
    return last_request_url_;
  }

  asio::awaitable<monad::MyResult<void>> start_awaitable() override {
    if (cli_ctx_.positionals.size() >= 2) {
      const std::string &action = cli_ctx_.positionals[1];
      if (action == "clear-cursor") {
        co_return clear_persisted_cursor();
      }
      co_return show_usage("Unknown updates action '" + action + "'.");
    }

    if (!cli_ctx_.params.keep_running) {
      co_return co_await poll_once_awaitable();
    }
    // Continuous loop
    co_return co_await poll_loop_awaitable();
  }

  // Report agent version to the server via HTTP notify endpoint.
  // This is the same mechanism used by the polling workflow, but exposed so
  // WebSocket-first deployments can still report versions without enabling
  // updates polling.
  asio::awaitable<monad::MyResult<void>>
  report_agent_version_once_awaitable(bool allow_refresh_retry = true) {
    if (notify_sent_this_run_) {
      co_return monad::MyResult<void>::Ok();
    }

    auto access_token_opt = load_access_token_from_state();
    if ((!access_token_opt || access_token_opt->empty()) &&
        allow_refresh_retry) {
      output_hub_.logger().trace()
          << "Access token missing; attempting refresh before device notify."
          << std::endl;
      auto refresh =
          co_await refresh_access_token_awaitable("device notify bootstrap");
      if (refresh.is_err()) {
        co_return refresh;
      }
      co_return co_await report_agent_version_once_awaitable(false);
    }

    // Check if token is expired or expiring soon (within 60 seconds)
    static constexpr std::chrono::seconds kSkew{60};
    if (access_token_opt && !access_token_opt->empty() && allow_refresh_retry &&
        is_jwt_expiring_soon(*access_token_opt, kSkew)) {
      output_hub_.logger().info() << "Access token is expired/expiring; "
                                     "attempting refresh before device notify."
                                  << std::endl;
      auto refresh = co_await refresh_access_token_awaitable(
          "device notify token expired");
      if (refresh.is_err()) {
        co_return refresh;
      }
      co_return co_await report_agent_version_once_awaitable(false);
    }

    if (!access_token_opt || access_token_opt->empty()) {
      output_hub_.logger().warning()
          << "Skipping agent version notify: no cached session tokens were "
             "found. "
             "Run 'cert-ctrl login' to authenticate this device."
          << std::endl;
      co_return monad::MyResult<void>::Ok();
    }

    co_return co_await maybe_send_startup_notification_awaitable(
        *access_token_opt);
  }

  asio::awaitable<monad::MyResult<void>> poll_loop_awaitable() {
    int iteration = 0;
    while (true) {
      output_hub_.logger().trace()
          << "Starting poll iteration " << iteration++ << std::endl;
      auto result = co_await poll_once_awaitable();
      if (result.is_err()) {
        ++consecutive_failures_;
        BOOST_LOG_SEV(lg, trivial::error)
            << "poll iteration error: " << result.error();
      }

      if (!cli_ctx_.params.keep_running) {
        output_hub_.logger().info()
            << "keep_running flag cleared; stopping polling loop" << std::endl;
        co_return monad::MyResult<void>::Ok();
      }

      const bool needs_delay = server_override_delay_ms_.has_value() ||
                               consecutive_failures_ > 0 || !options_.long_poll;
      if (!needs_delay) {
        continue;
      }

      int delay_ms = 0;
      if (server_override_delay_ms_) {
        delay_ms = *server_override_delay_ms_;
        server_override_delay_ms_.reset();
      } else if (consecutive_failures_ > 0) {
        delay_ms = compute_failure_delay_ms();
      } else {
        delay_ms = interval_ms_;
      }
      if (delay_ms <= 0) {
        delay_ms = interval_ms_ > 0 ? interval_ms_ : kFailureRetryBaseMs;
      }
      if (consecutive_failures_ > 0) {
        output_hub_.logger().info()
            << "Retrying updates poll in " << delay_ms << " ms after "
            << consecutive_failures_ << " consecutive failures" << std::endl;
      }

      asio::steady_timer timer(co_await asio::this_coro::executor);
      timer.expires_after(std::chrono::milliseconds(delay_ms));
      co_await timer.async_wait(asio::use_awaitable);
    }
  }

private:
  bool is_jwt_expiring_soon(const std::string &token,
                            std::chrono::seconds skew) const {
    try {
      auto decoded = jwt::decode(token);
      if (!decoded.has_payload_claim("exp")) {
        return false;
      }
      const auto exp_time = decoded.get_payload_claim("exp").as_date();
      const auto now = std::chrono::system_clock::now();
      return exp_time <= now + skew;
    } catch (...) {
      // If token cannot be decoded, treat it as unusable and attempt refresh.
      return true;
    }
  }

  std::optional<std::string> load_access_token_from_state() {
    auto token = state_store_.get_access_token();
    if (token && !token->empty()) {
      cached_access_token_ = token;
      return cached_access_token_;
    }

    cached_access_token_.reset();
    return std::nullopt;
  }

  asio::awaitable<monad::MyResult<void>>
  refresh_access_token_awaitable(std::string reason) {
    if (!session_refresher_) {
      co_return monad::MyResult<void>::Err(monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT,
          "Session refresher unavailable; re-run cert-ctrl login."));
    }
    auto result =
        co_await session_refresher_->refresh_awaitable(std::move(reason));
    if (result.is_ok()) {
      cached_access_token_.reset();
    }
    co_return result;
  }
  // Helper methods - must be defined before poll_once() because they're
  // templates

  template <typename ExchangePtr>
  void maybe_update_interval_from_header(const ExchangePtr &ex) {
    static constexpr std::string_view kPollIntervalHeader = "X-Poll-Interval";
    auto header_it = ex->response->base().find(kPollIntervalHeader);
    if (header_it == ex->response->base().end()) {
      BOOST_LOG_SEV(lg, trivial::error)
          << "No " << kPollIntervalHeader << " header in response";
      return;
    }

    const std::string header_value(header_it->value());
    try {
      int new_interval_seconds = std::stoi(header_value);
      if (new_interval_seconds <= 0) {
        return;
      }
      const int new_interval_ms = new_interval_seconds * 1000;
      if (new_interval_ms != interval_ms_) {
        const int previous_interval_ms = interval_ms_;
        interval_ms_ = new_interval_ms;
        BOOST_LOG_SEV(lg, trivial::info)
            << "Server adjusted poll interval to " << interval_ms_
            << " ms (was " << previous_interval_ms << " ms)" << std::endl;
      } else {
        BOOST_LOG_SEV(lg, trivial::trace)
            << "Server poll interval unchanged at " << interval_ms_ << " ms";
      }
    } catch (const std::exception &e) {
      BOOST_LOG_SEV(lg, trivial::error)
          << "Failed to parse X-Poll-Interval header value '" << header_value
          << "': " << e.what() << std::endl;
    }
  }

  template <typename ExchangePtr>
  monad::MyResult<void> handle_no_content(ExchangePtr ex) {
    namespace http = boost::beast::http;

    // Extract cursor from ETag header
    consecutive_failures_ = 0;
    maybe_update_interval_from_header(ex);
    if (auto it = ex->response->find(http::field::etag);
        it != ex->response->end()) {
      std::string etag = std::string(it->value());
      if (!etag.empty() && etag.front() == '"' && etag.back() == '"' &&
          etag.size() >= 2) {
        cursor_ = etag.substr(1, etag.size() - 2);
      } else {
        cursor_ = std::move(etag);
      }
      save_cursor(cursor_);
    }

    BOOST_LOG_SEV(lg, trivial::trace) << "204 No Content, cursor=" << cursor_;

    return monad::MyResult<void>::Ok();
  }

  template <typename ExchangePtr>
  asio::awaitable<monad::MyResult<void>>
  handle_ok_with_signals_awaitable(ExchangePtr ex) {
    auto parse_result =
        ex->template parseJsonResponse<::data::DeviceUpdatesResponse>();

    if (parse_result.is_err()) {
      co_return monad::MyResult<void>::Err(parse_result.error());
    }

    auto resp = std::move(parse_result).value();
    consecutive_failures_ = 0;
    maybe_update_interval_from_header(ex);

    // Update cursor
    cursor_ = resp.data.cursor;
    save_cursor(cursor_);

    BOOST_LOG_SEV(lg, trivial::debug) << "200 OK, " << resp.data.signals.size()
                                      << " signals, cursor=" << cursor_;

    // Store response
    last_updates_ = std::move(resp);

    for (const auto &signal : last_updates_->data.signals) {
      if (signal.type == "install.updated") {
        ++install_updated_count_;
      } else if (signal.type == "cert.updated") {
        ++cert_updated_count_;
      } else if (signal.type == "cert.unassigned") {
        ++cert_unassigned_count_;
      }

      auto result = co_await signal_dispatcher_->dispatch_awaitable(signal);
      if (result.is_err()) {
        co_return result;
      }
    }

    co_return monad::MyResult<void>::Ok();
  }

  template <typename ExchangePtr>
  monad::MyResult<void> handle_error_status(ExchangePtr ex, int status) {
    std::string body = ex->response->body();
    BOOST_LOG_SEV(lg, trivial::error)
        << "HTTP " << status << " error on " << last_request_url_ << ": "
        << body.substr(0, 200);

    // Parse JSON error if available
    parse_error_ = body;

    if (status == 429 || status == 503) {
      namespace http = boost::beast::http;
      auto header_it = ex->response->find(http::field::retry_after);
      bool applied = false;
      if (header_it != ex->response->end()) {
        std::string header_value = std::string(header_it->value());
        try {
          int retry_seconds = std::stoi(header_value);
          if (retry_seconds > 0) {
            server_override_delay_ms_ =
                std::max(interval_ms_, retry_seconds * 1000);
            applied = true;
          }
        } catch (const std::exception &) {
          // ignore malformed Retry-After header
        }
      }
      if (!applied) {
        try {
          auto jv = boost::json::parse(body);
          if (jv.is_object()) {
            if (auto *err = jv.as_object().if_contains("error")) {
              if (err->is_object()) {
                if (auto *params = err->as_object().if_contains("params")) {
                  if (params->is_object()) {
                    if (auto *retry_after =
                            params->as_object().if_contains("retry_after")) {
                      if (retry_after->is_int64()) {
                        int retry_seconds =
                            static_cast<int>(retry_after->as_int64());
                        if (retry_seconds > 0) {
                          server_override_delay_ms_ =
                              std::max(interval_ms_, retry_seconds * 1000);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        } catch (const std::exception &) {
          // ignore malformed JSON
        }
      }
    }

    return monad::MyResult<void>::Err(
        monad::make_error(my_errors::NETWORK::READ_ERROR,
                          fmt::format("HTTP {} response", status)));
  }

  void save_cursor(const std::string &cursor) {
    const std::optional<std::string> payload(cursor);
    if (auto err = state_store_.save_updates_cursor(payload)) {
      BOOST_LOG_SEV(lg, trivial::error)
          << "Failed to persist cursor to SQLite: " << *err;
      return;
    }
  }

  void load_cursor_from_state() {
    if (auto stored = state_store_.get_updates_cursor()) {
      if (!stored->empty()) {
        cursor_ = *stored;
        BOOST_LOG_SEV(lg, trivial::info)
            << "Resuming updates cursor from SQLite entry";
        return;
      }
    }
  }

  int compute_failure_delay_ms() const {
    if (consecutive_failures_ <= 0) {
      return interval_ms_ > 0 ? interval_ms_ : kFailureRetryBaseMs;
    }

    int upper = kFailureRetryMaxMs;
    if (interval_ms_ > 0) {
      upper = std::min(upper, interval_ms_);
    }
    int lower = kFailureRetryBaseMs;
    if (interval_ms_ > 0) {
      lower = std::min(lower, interval_ms_);
    }
    if (upper < lower) {
      upper = lower;
    }

    int exponent =
        std::min(consecutive_failures_ - 1, kFailureRetryMaxExponent);
    int candidate = kFailureRetryBaseMs << exponent;
    if (candidate > upper) {
      candidate = upper;
    }
    if (candidate < lower) {
      candidate = lower;
    }
    if (candidate <= 0) {
      candidate = lower > 0 ? lower : kFailureRetryBaseMs;
    }

    return candidate;
  }

  asio::awaitable<monad::MyResult<void>>
  poll_once_awaitable(bool allow_refresh_retry = true,
                      bool allow_resync_retry = true) {
    auto access_token_opt = load_access_token_from_state();
    if ((!access_token_opt || access_token_opt->empty()) &&
        allow_refresh_retry) {
      output_hub_.logger().trace()
          << "Access token missing; attempting refresh before polling."
          << std::endl;
      auto refresh =
          co_await refresh_access_token_awaitable("updates polling bootstrap");
      if (refresh.is_err()) {
        co_return refresh;
      }
      co_return co_await poll_once_awaitable(false, true);
    }

    if (!access_token_opt || access_token_opt->empty()) {
      output_hub_.printer().yellow()
          << "No device access token found; please run `cert_ctrl login` first."
          << std::endl;
      co_return monad::MyResult<void>::Err(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          "device access token not available in state; run cert_ctrl login"));
    }
    const std::string access_token = *access_token_opt;

    // Build URL with query parameters
    std::string url = endpoint_base_;
    std::string query;
    if (!cursor_.empty()) {
      query += (query.empty() ? "?" : "&");
      query += std::string("cursor=") + cursor_;
    }
    if (options_.limit > 0) {
      query += (query.empty() ? "?" : "&");
      query += "limit=" + std::to_string(options_.limit);
    }
    if (options_.long_poll && options_.wait_seconds > 0) {
      query += (query.empty() ? "?" : "&");
      query += "wait=" + std::to_string(options_.wait_seconds);
    }
    url += query;

    co_await maybe_send_startup_notification_awaitable(access_token);
    co_return co_await execute_poll_request_awaitable(
        std::move(url), access_token, allow_refresh_retry, allow_resync_retry);
  }

public:
  int last_http_status() const { return last_http_status_; }
  const std::optional<::data::DeviceUpdatesResponse> &last_updates() const {
    return last_updates_;
  }
  const std::string &last_cursor() const { return cursor_; }
  const std::string &parse_error() const { return parse_error_; }
  size_t install_updated_count() const { return install_updated_count_; }
  size_t cert_updated_count() const { return cert_updated_count_; }
  size_t cert_unassigned_count() const { return cert_unassigned_count_; }
  friend struct UpdatesPollingHandlerTestFriend;

private:
  monad::MyResult<void> clear_persisted_cursor() {
    cursor_.clear();
    if (auto err = state_store_.save_updates_cursor(std::nullopt)) {
      return monad::MyResult<void>::Err(
          monad::make_error(my_errors::GENERAL::DELETE_FAILED,
                            "failed to clear updates cursor: " + *err));
    }
    output_hub_.logger().info()
        << "Cleared persisted updates cursor from SQLite state" << std::endl;
    return monad::MyResult<void>::Ok();
  }

  boost::json::object build_startup_notify_payload() const {
    boost::json::object payload;
    boost::json::array events;
    boost::json::object event;
    event["type"] = "agent_version";
    event["version"] = MYAPP_VERSION;
    event["agent"] = "cert-ctrl";
    if (auto device_id = load_device_public_id_from_state()) {
      event["device_public_id"] = *device_id;
    }
    events.push_back(event);
    payload["events"] = std::move(events);
    payload["schema"] = "certctrl.device.notify.v1";
    return payload;
  }

  asio::awaitable<monad::MyResult<void>> execute_poll_request_awaitable(
      std::string url, const std::string &access_token,
      bool allow_refresh_retry, bool allow_resync_retry) {
    namespace http = boost::beast::http;

    last_request_url_ = url;
    parse_error_.clear();
    output_hub_.logger().trace()
        << "Polling device updates at " << url << std::endl;

    auto exchange_result =
        async_support::make_http_exchange<monad::GetStringTag>(url);
    if (exchange_result.is_err()) {
      co_return monad::MyResult<void>::Err(exchange_result.error());
    }
    auto exchange = std::move(exchange_result).value();
    exchange->request.set(http::field::authorization,
                          std::string("Bearer ") + access_token);
    if (!cursor_.empty()) {
      exchange->request.set(http::field::if_none_match,
                            fmt::format("\"{}\"", cursor_));
    }

    auto request_result =
        co_await async_support::http_exchange_awaitable<monad::GetStringTag>(
            http_client_, std::move(exchange));
    if (request_result.is_err()) {
      co_return monad::MyResult<void>::Err(request_result.error());
    }
    auto response_exchange = std::move(request_result).value();
    if (!response_exchange->response.has_value()) {
      co_return monad::MyResult<void>::Err(monad::make_error(
          my_errors::NETWORK::READ_ERROR, "No response received"));
    }

    const int status = response_exchange->response->result_int();
    last_http_status_ = status;
    if (status == 204) {
      co_return handle_no_content(response_exchange);
    }
    if (status == 200) {
      co_return co_await handle_ok_with_signals_awaitable(response_exchange);
    }
    if (status == 409 && allow_resync_retry) {
      const std::string body = response_exchange->response->body();
      if (is_resync_required_response(body)) {
        BOOST_LOG_SEV(lg, trivial::warning)
            << "Polling cursor gap detected; running full resync and retrying"
            << std::endl;
        auto heal = co_await auto_heal_stale_cursor_awaitable(body);
        if (heal.is_ok()) {
          co_return co_await poll_once_awaitable(allow_refresh_retry, false);
        }
        BOOST_LOG_SEV(lg, trivial::error)
            << "Automatic full resync failed: " << heal.error().what
            << std::endl;
        co_return handle_error_status(response_exchange, status);
      }
    }
    if ((status == 401 || status == 403) && allow_refresh_retry) {
      BOOST_LOG_SEV(lg, trivial::info)
          << "Received HTTP " << status
          << " while polling; attempting token refresh." << std::endl;
      auto refresh = co_await refresh_access_token_awaitable(
          fmt::format("updates polling HTTP {}", status));
      if (refresh.is_ok()) {
        co_return co_await poll_once_awaitable(false, allow_resync_retry);
      }
      BOOST_LOG_SEV(lg, trivial::error)
          << "Token refresh failed: " << refresh.error().what << std::endl;
    }
    co_return handle_error_status(response_exchange, status);
  }

  bool is_resync_required_response(const std::string &body) const {
    try {
      auto jv = boost::json::parse(body);
      if (!jv.is_object()) {
        return false;
      }
      auto *error_v = jv.as_object().if_contains("error");
      if (!error_v || !error_v->is_object()) {
        return false;
      }
      const auto &error_obj = error_v->as_object();
      if (auto *code_v = error_obj.if_contains("code");
          code_v && code_v->is_int64() && code_v->as_int64() == 40901) {
        return true;
      }
      auto *params_v = error_obj.if_contains("params");
      if (!params_v || !params_v->is_object()) {
        return false;
      }
      const auto &params = params_v->as_object();
      if (auto *action_v = params.if_contains("action");
          action_v && action_v->is_string() &&
          action_v->as_string() == "full_resync") {
        return true;
      }
      return false;
    } catch (const std::exception &) {
      return false;
    }
  }

  asio::awaitable<monad::MyResult<void>>
  auto_heal_stale_cursor_awaitable(const std::string &body) {
    if (!install_config_manager_) {
      co_return monad::MyResult<void>::Err(
          monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                            "InstallConfigManager dependency missing; cannot "
                            "auto-heal cursor gap"));
    }

    output_hub_.logger().warning()
        << "Server requested a full resync after updates cursor gap: " << body
        << std::endl;

    auto clear = clear_persisted_cursor();
    if (clear.is_err()) {
      co_return clear;
    }
    co_return co_await install_config_manager_->full_resync_from_server();
  }

  asio::awaitable<monad::MyResult<void>>
  maybe_send_startup_notification_awaitable(const std::string &access_token) {
    namespace http = boost::beast::http;

    if (notify_sent_this_run_) {
      co_return monad::MyResult<void>::Ok();
    }

    auto exchange_result =
        async_support::make_http_exchange<monad::PostJsonTag>(notify_endpoint_);
    if (exchange_result.is_err()) {
      output_hub_.logger().warning()
          << "Failed to prepare agent version notification: "
          << exchange_result.error().what << std::endl;
      co_return monad::MyResult<void>::Ok();
    }
    auto exchange = std::move(exchange_result).value();
    const auto payload = build_startup_notify_payload();
    exchange->setRequestJsonBody(payload);
    exchange->request.set(http::field::authorization,
                          std::string("Bearer ") + access_token);
    output_hub_.logger().trace()
        << "Sending startup notification to " << notify_endpoint_
        << " with payload: " << payload << std::endl;

    auto request_result =
        co_await async_support::http_exchange_awaitable<monad::PostJsonTag>(
            http_client_, std::move(exchange));
    if (request_result.is_err()) {
      output_hub_.logger().warning()
          << "Failed to notify server of agent version: "
          << request_result.error().what << std::endl;
      co_return monad::MyResult<void>::Ok();
    }
    auto response_exchange = std::move(request_result).value();
    if (!response_exchange->is_2xx()) {
      const int status = response_exchange->response
                             ? response_exchange->response->result_int()
                             : 0;
      if (status == 401 || status == 403) {
        output_hub_.logger().warning()
            << "Device notify endpoint authorization failed via "
            << notify_endpoint_ << " (HTTP " << status
            << "). Token may be expired or the device is not onboarded. "
               "Re-run the device onboarding/registration flow to refresh "
               "credentials. Will retry next iteration."
            << std::endl;
      } else {
        output_hub_.logger().warning()
            << "Device notify endpoint returned HTTP " << status << " via "
            << notify_endpoint_ << "; will retry next iteration." << std::endl;
      }
      co_return monad::MyResult<void>::Ok();
    }

    notify_sent_this_run_ = true;
    output_hub_.logger().info() << "Reported agent version " << MYAPP_VERSION
                                << " via /devices/self/notify" << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  std::optional<std::string> load_device_public_id_from_state() const {
    if (auto store_id = state_store_.get_device_public_id()) {
      if (!store_id->empty()) {
        return store_id;
      }
    }
    return std::nullopt;
  }
};
} // namespace certctrl
