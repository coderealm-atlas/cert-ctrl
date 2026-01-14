#pragma once

#include <algorithm>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
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
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <vector> // indirectly needed via data structures; keep if build complains

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/data_shape.hpp"
#include <jwt-cpp/jwt.h>
#include "handlers/i_handler.hpp"
#include "handlers/install_config_manager.hpp"
#include "handlers/session_refresher.hpp"
#include "handlers/signal_dispatcher.hpp"
#include "handlers/signal_handlers/ca_assigned_handler.hpp"
#include "handlers/signal_handlers/ca_unassigned_handler.hpp"
#include "handlers/signal_handlers/cert_updated_handler.hpp"
#include "handlers/signal_handlers/cert_unassigned_handler.hpp"
#include "handlers/signal_handlers/config_updated_handler.hpp"
#include "handlers/signal_handlers/install_updated_handler.hpp"
#include "http_client_manager.hpp"
#include "http_client_monad.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "my_error_codes.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep
#include "version.h"
#include "state/device_state_store.hpp"

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
  asio::io_context &ioc_;
  cjj365::ConfigSources &config_sources_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  client_async::HttpClientManager &http_client_;
  customio::ConsoleOutput &output_hub_;
  certctrl::IDeviceStateStore &state_store_;
  CliCtx &cli_ctx_;
  src::severity_logger<trivial::severity_level> lg;
  po::options_description opt_desc_;
  UpdatesPollingHandlerOptions options_;
  boost::asio::any_io_executor exec_;
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
      : ioc_(io_context_manager.ioc()), config_sources_(config_sources),
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
    exec_ = boost::asio::make_strand(ioc_);
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
        -> monad::IO<void> {
      if (!mgr) {
        return monad::IO<void>::pure();
      }
      return mgr->maybe_run_after_update_script_for_signal(signal);
    };
    signal_dispatcher_ =
      std::make_unique<SignalDispatcher>(runtime_dir, &state_store_,
                                         std::move(post_success_hook));

    signal_dispatcher_->register_handler(
        std::make_shared<signal_handlers::ConfigUpdatedHandler>(
        certctrl_config_provider_, output_hub_, nullptr));

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

  const std::string &last_request_url() const noexcept {
    return last_request_url_;
  }

  monad::IO<void> start() override {
    if (!cli_ctx_.params.keep_running) {
      return poll_once();
    }
    // Continuous loop
    return poll_loop(0);
  }

  // Report agent version to the server via HTTP notify endpoint.
  // This is the same mechanism used by the polling workflow, but exposed so
  // WebSocket-first deployments can still report versions without enabling
  // updates polling.
  monad::IO<void> report_agent_version_once(bool allow_refresh_retry = true) {
    using namespace monad;

    if (notify_sent_this_run_) {
      return IO<void>::pure();
    }

    auto access_token_opt = load_access_token_from_state();
    if ((!access_token_opt || access_token_opt->empty()) && allow_refresh_retry) {
      output_hub_.logger().trace()
          << "Access token missing; attempting refresh before device notify."
          << std::endl;
      auto self = shared_from_this();
      return refresh_access_token("device notify bootstrap").then([self]() {
        return self->report_agent_version_once(false);
      });
    }

    // Check if token is expired or expiring soon (within 60 seconds)
    static constexpr std::chrono::seconds kSkew{60};
    if (access_token_opt && !access_token_opt->empty() && 
        allow_refresh_retry && is_jwt_expiring_soon(*access_token_opt, kSkew)) {
      output_hub_.logger().info()
          << "Access token is expired/expiring; attempting refresh before device notify."
          << std::endl;
      auto self = shared_from_this();
      return refresh_access_token("device notify token expired").then([self]() {
        return self->report_agent_version_once(false);
      });
    }

    if (!access_token_opt || access_token_opt->empty()) {
      output_hub_.logger().warning()
          << "Skipping agent version notify: no cached session tokens were found. "
             "Run 'cert-ctrl login' to authenticate this device."
          << std::endl;
      return IO<void>::pure();
    }

    return maybe_send_startup_notification(*access_token_opt);
  }

  monad::IO<void> poll_loop(int iter) {
    // perform one poll, swallow/log error, then schedule next (async delay if
    // needed)
    output_hub_.logger().trace()
        << "Starting poll iteration " << iter << std::endl;
    return poll_once()
        .catch_then([self = this->shared_from_this()](monad::Error e) {
          ++self->consecutive_failures_;
          BOOST_LOG_SEV(self->lg, trivial::error)
              << "poll iteration error: " << e;
          return monad::IO<void>::pure(); // continue
        })
        .then([self = this->shared_from_this(), iter]() {
          if (!self->cli_ctx_.params.keep_running) {
            self->output_hub_.logger().info()
                << "keep_running flag cleared; stopping polling loop"
                << std::endl;
            return monad::IO<void>::pure();
          }
          // Use asynchronous delay to avoid blocking thread when not
          // long-polling
          bool needs_delay = self->server_override_delay_ms_.has_value() ||
                             self->consecutive_failures_ > 0 ||
                             !self->options_.long_poll;
          if (needs_delay) {
            int delay_ms = 0;
            if (self->server_override_delay_ms_) {
              delay_ms = *self->server_override_delay_ms_;
              self->server_override_delay_ms_.reset();
            } else if (self->consecutive_failures_ > 0) {
              delay_ms = self->compute_failure_delay_ms();
            } else {
              delay_ms = self->interval_ms_;
            }

            if (delay_ms <= 0) {
              delay_ms = self->interval_ms_ > 0 ? self->interval_ms_
                                                : kFailureRetryBaseMs;
            }

            if (self->consecutive_failures_ > 0) {
              self->output_hub_.logger().info()
                  << "Retrying updates poll in " << delay_ms << " ms after "
                  << self->consecutive_failures_ << " consecutive failures"
                  << std::endl;
            }

            return monad::delay_for<void>(self->ioc_,
                                          std::chrono::milliseconds(delay_ms))
                .then([self, iter]() { return self->poll_loop(iter + 1); });
          }
          // Long-poll immediately chains next iteration (server waits
          // internally)
          return self->poll_loop(iter + 1);
        });
  }

private:
  bool is_jwt_expiring_soon(const std::string &token, std::chrono::seconds skew) const {
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

    if (config_sources_.paths_.empty()) {
      cached_access_token_.reset();
      return std::nullopt;
    }

    const auto runtime_dir = config_sources_.paths_.back();
    const auto token_path = runtime_dir / "state" / "access_token.txt";
    auto legacy_token = read_trimmed_file(token_path);
    if (legacy_token && !legacy_token->empty()) {
      cached_access_token_ = legacy_token;
      return cached_access_token_;
    }

    cached_access_token_.reset();
    return std::nullopt;
  }

  monad::IO<void> refresh_access_token(std::string reason) {
    if (!session_refresher_) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT,
          "Session refresher unavailable; re-run cert-ctrl login."));
    }
    return session_refresher_->refresh(std::move(reason))
        .then([this]() -> monad::IO<void> {
          cached_access_token_.reset();
          return monad::IO<void>::pure();
        });
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
  monad::IO<void> handle_no_content(ExchangePtr ex) {
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

    return monad::IO<void>::pure();
  }

  template <typename ExchangePtr>
  monad::IO<void> handle_ok_with_signals(ExchangePtr ex) {
    auto parse_result =
        ex->template parseJsonResponse<::data::DeviceUpdatesResponse>();

    if (parse_result.is_err()) {
      return monad::IO<void>::from_result(
          monad::Result<void, monad::Error>::Err(parse_result.error()));
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

    auto self = shared_from_this();
    auto dispatch_chain = monad::IO<void>::pure();

    for (const auto &signal : last_updates_->data.signals) {
      if (signal.type == "install.updated") {
        ++install_updated_count_;
      } else if (signal.type == "cert.updated") {
        ++cert_updated_count_;
      } else if (signal.type == "cert.unassigned") {
        ++cert_unassigned_count_;
      }

      auto signal_copy = signal;
      dispatch_chain = dispatch_chain.then(
          [self, signal_copy]() { return self->signal_dispatcher_->dispatch(signal_copy); });
    }

    return dispatch_chain;
  }

  template <typename ExchangePtr>
  monad::IO<void> handle_error_status(ExchangePtr ex, int status) {
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

    return monad::IO<void>::fail(
        monad::make_error(my_errors::NETWORK::READ_ERROR,
                          fmt::format("HTTP {} response", status)));
  }

  void save_cursor(const std::string &cursor) {
    const std::optional<std::string> payload(cursor);
    if (auto err = state_store_.save_updates_cursor(payload)) {
      BOOST_LOG_SEV(lg, trivial::error)
          << "Failed to persist cursor to SQLite: " << *err
          << "; falling back to legacy file";
      persist_cursor_to_file(cursor);
      return;
    }

    remove_legacy_cursor_file();
  }

  void load_cursor_from_state() {
    if (auto stored = state_store_.get_updates_cursor()) {
      if (!stored->empty()) {
        cursor_ = *stored;
        BOOST_LOG_SEV(lg, trivial::info)
            << "Resuming updates cursor from SQLite entry";
        remove_legacy_cursor_file();
        return;
      }
    }

    if (config_sources_.paths_.empty()) {
      return;
    }
    const auto runtime_dir = config_sources_.paths_.back();
    const auto cursor_path = runtime_dir / "state" / "last_cursor.txt";
    auto legacy_cursor = read_trimmed_file(cursor_path);
    if (!legacy_cursor || legacy_cursor->empty()) {
      return;
    }

    cursor_ = *legacy_cursor;
    BOOST_LOG_SEV(lg, trivial::info)
        << "Resuming updates cursor from legacy file";

    const std::optional<std::string> payload(cursor_);
    if (auto err = state_store_.save_updates_cursor(payload)) {
      BOOST_LOG_SEV(lg, trivial::warning)
          << "Failed to migrate cursor into SQLite: " << *err;
      return;
    }

    remove_legacy_cursor_file();
  }

  void persist_cursor_to_file(const std::string &cursor) {
    if (config_sources_.paths_.empty()) {
      return;
    }

    auto config_dir = config_sources_.paths_.back();
    auto cursor_file = config_dir / "state" / "last_cursor.txt";
    auto temp_file = config_dir / "state" / ".last_cursor.txt.tmp";

    try {
      std::filesystem::create_directories(config_dir / "state");

      std::ofstream ofs(temp_file);
      ofs << cursor;
      ofs.close();

      std::filesystem::rename(temp_file, cursor_file);
      std::filesystem::permissions(cursor_file,
                                   std::filesystem::perms::owner_read |
                                       std::filesystem::perms::owner_write);
    } catch (const std::exception &e) {
      BOOST_LOG_SEV(lg, trivial::error)
          << "Failed to save cursor to file: " << e.what();
    }
  }

  void remove_legacy_cursor_file() const {
    if (config_sources_.paths_.empty()) {
      return;
    }

    auto config_dir = config_sources_.paths_.back();
    auto cursor_file = config_dir / "state" / "last_cursor.txt";
    auto temp_file = config_dir / "state" / ".last_cursor.txt.tmp";
    std::error_code ec;
    std::filesystem::remove(cursor_file, ec);
    std::filesystem::remove(temp_file, ec);
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

  monad::IO<void> poll_once(bool allow_refresh_retry = true) {
    using namespace monad;

    auto access_token_opt = load_access_token_from_state();
    if ((!access_token_opt || access_token_opt->empty()) &&
        allow_refresh_retry) {
      output_hub_.logger().trace()
          << "Access token missing; attempting refresh before polling."
          << std::endl;
      auto self = shared_from_this();
      return refresh_access_token("updates polling bootstrap").then([self]() {
        return self->poll_once(false);
      });
    }

    if (!access_token_opt || access_token_opt->empty()) {
      output_hub_.printer().yellow()
          << "No device access token found; please run `cert_ctrl login` first."
          << std::endl;
      return IO<void>::fail(monad::make_error(
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

    auto self = shared_from_this();
    return maybe_send_startup_notification(access_token)
        .then([self, url = std::move(url), access_token,
               allow_refresh_retry]() mutable {
          return self->execute_poll_request(
              std::move(url), std::move(access_token), allow_refresh_retry);
        });
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

  monad::IO<void> execute_poll_request(std::string url,
                                       std::string access_token,
                                       bool allow_refresh_retry) {
    using monad::GetStringTag;
    using monad::http_io;
    using monad::http_request_io;
    namespace http = boost::beast::http;

    last_request_url_ = url;
    parse_error_.clear();
    output_hub_.logger().trace()
        << "Polling device updates at " << url << std::endl;

    auto self = shared_from_this();
    return http_io<GetStringTag>(url)
        .map([self, access_token = std::move(access_token)](auto ex) {
          ex->request.set(http::field::authorization,
                          std::string("Bearer ") + access_token);
          if (!self->cursor_.empty()) {
            ex->request.set(http::field::if_none_match,
                            fmt::format("\"{}\"", self->cursor_));
          }
          return ex;
        })
        .then(http_request_io<GetStringTag>(http_client_))
        .then([self, allow_refresh_retry](auto ex) -> monad::IO<void> {
          if (!ex->response.has_value()) {
            return monad::IO<void>::fail(monad::make_error(
                my_errors::NETWORK::READ_ERROR, "No response received"));
          }

          int status = ex->response->result_int();
          self->last_http_status_ = status;

          if (status == 204) {
            return self->handle_no_content(ex);
          } else if (status == 200) {
            return self->handle_ok_with_signals(ex);
          } else if ((status == 401 || status == 403) && allow_refresh_retry) {
            BOOST_LOG_SEV(self->lg, trivial::info)
                << "Received HTTP " << status
                << " while polling; attempting token refresh." << std::endl;
            auto reason = fmt::format("updates polling HTTP {}", status);
            return self->refresh_access_token(std::move(reason))
                .then([self]() { return self->poll_once(false); })
                .catch_then([self, ex, status](const monad::Error &err) {
                  BOOST_LOG_SEV(self->lg, trivial::error)
                      << "Token refresh failed: " << err.what << std::endl;
                  return self->handle_error_status(ex, status);
                });
          }
          return self->handle_error_status(ex, status);
        });
  }

  monad::IO<void>
  maybe_send_startup_notification(const std::string &access_token) {
    using monad::http_io;
    using monad::http_request_io;
    using monad::PostJsonTag;
    namespace http = boost::beast::http;

    if (notify_sent_this_run_) {
      return monad::IO<void>::pure();
    }

    auto payload_obj =
        std::make_shared<boost::json::object>(build_startup_notify_payload());
    auto self = shared_from_this();
    return http_io<PostJsonTag>(notify_endpoint_)
        .map([self, payload_obj, access_token](auto ex) {
          ex->setRequestJsonBody(*payload_obj);
          ex->request.set(http::field::authorization,
                          std::string("Bearer ") + access_token);
          self->output_hub_.logger().trace()
              << "Sending startup notification to " << self->notify_endpoint_
              << " with payload: " << *payload_obj << std::endl;
          return ex;
        })
        .then(http_request_io<PostJsonTag>(http_client_))
        .then([self](auto ex) -> monad::IO<void> {
          if (!ex->is_2xx()) {
            int status = ex->response ? ex->response->result_int() : 0;
            if (status == 401 || status == 403) {
              self->output_hub_.logger().warning()
                  << "Device notify endpoint authorization failed via "
                  << self->notify_endpoint_ << " (HTTP " << status
                  << "). Token may be expired or the device is not onboarded. "
                     "Re-run the device onboarding/registration flow to refresh credentials. "
                     "Will retry next iteration." << std::endl;
            } else {
              self->output_hub_.logger().warning()
                  << "Device notify endpoint returned HTTP " << status
                  << " via " << self->notify_endpoint_
                  << "; will retry next iteration." << std::endl;
            }
            return monad::IO<void>::pure();
          }
          self->notify_sent_this_run_ = true;
          self->output_hub_.logger().info()
              << "Reported agent version " << MYAPP_VERSION
              << " via /devices/self/notify" << std::endl;
          return monad::IO<void>::pure();
        })
        .catch_then([self](monad::Error err) {
          self->output_hub_.logger().warning()
              << "Failed to notify server of agent version: " << err.what
              << std::endl;
          return monad::IO<void>::pure();
        });
  }

  std::optional<std::string> load_device_public_id_from_state() const {
    if (auto store_id = state_store_.get_device_public_id()) {
      if (!store_id->empty()) {
        return store_id;
      }
    }

    if (config_sources_.paths_.empty()) {
      return std::nullopt;
    }
    const auto runtime_dir = config_sources_.paths_.back();
    const auto id_path = runtime_dir / "state" / "device_public_id.txt";
    return read_trimmed_file(id_path);
  }

  static std::optional<std::string>
  read_trimmed_file(const std::filesystem::path &path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
      return std::nullopt;
    }
    std::string contents((std::istreambuf_iterator<char>(ifs)), {});
    auto first = contents.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
      return std::nullopt;
    }
    auto last = contents.find_last_not_of(" \t\r\n");
    if (last == std::string::npos || last < first) {
      return std::nullopt;
    }
    return contents.substr(first, last - first + 1);
  }
};
} // namespace certctrl
