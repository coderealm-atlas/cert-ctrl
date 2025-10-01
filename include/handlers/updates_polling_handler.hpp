#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <optional>
#include <string>
#include <vector> // indirectly needed via data structures; keep if build complains
#include <format>
#include <cstdlib>
#include <chrono>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/i_handler.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "http_client_monad.hpp"
#include "data/data_shape.hpp"
#include "my_error_codes.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep

namespace po = boost::program_options;

namespace certctrl {

// Rough initial implementation of a device updates polling handler. It expects
// that the user already logged in and has a device access token persisted
// somewhere accessible (env var for now). Later refinement can integrate real
// credential / token storage.

struct UpdatesPollingHandlerOptions {
  int wait_seconds{0};
  int limit{20};
  bool long_poll{false};
};

class UpdatesPollingHandler : public certctrl::IHandler,
                              public std::enable_shared_from_this<UpdatesPollingHandler> {
  asio::io_context &ioc_;
  cjj365::ConfigSources &config_sources_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  client_async::HttpClientManager &http_client_;
  customio::ConsoleOutput &output_hub_;
  CliCtx &cli_ctx_;
  src::severity_logger<trivial::severity_level> lg;
  po::options_description opt_desc_;
  UpdatesPollingHandlerOptions options_;
  boost::asio::any_io_executor exec_;
  std::string endpoint_base_; // /apiv1/devices/self/updates
  std::string cursor_;
  int last_http_status_{0};
  std::optional<data::DeviceUpdatesResponse> last_updates_;
  std::string parse_error_;
  // loop controls
  int interval_ms_{1000}; // delay between polls when not long-polling
  // removed max_loops_ – service runs continuously while keep_running
  // signal counters (cumulative this run)
  size_t install_updated_count_{0};
  size_t cert_renewed_count_{0};
  size_t cert_revoked_count_{0};

public:
  UpdatesPollingHandler(cjj365::IoContextManager &io_context_manager,
                        cjj365::ConfigSources &config_sources,
                        certctrl::ICertctrlConfigProvider &certctrl_config_provider,
                        CliCtx &cli_ctx, customio::ConsoleOutput &output_hub,
                        client_async::HttpClientManager &http_client)
      : ioc_(io_context_manager.ioc()), config_sources_(config_sources),
        certctrl_config_provider_(certctrl_config_provider),
        output_hub_(output_hub), cli_ctx_(cli_ctx), http_client_(http_client),
        opt_desc_("updates polling options"),
        endpoint_base_(std::format("{}/apiv1/devices/self/updates", certctrl_config_provider_.get().base_url)) {
    exec_ = boost::asio::make_strand(ioc_);
    po::options_description create_opts("Updates Polling Options");
    create_opts.add_options()
      ("wait", po::value<int>()->default_value(0), "long poll wait seconds (0-30)")
      ("limit", po::value<int>()->default_value(20), "max signals (1-100)")
      ("interval", po::value<int>()->default_value(1000), "interval ms between polls when not long-polling");
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
      options_.limit = cli_ctx_.vm["limit"].as<int>();
    }
    if (cli_ctx_.vm.count("interval")) {
      interval_ms_ = cli_ctx_.vm["interval"].as<int>();
      if (interval_ms_ < 10) interval_ms_ = 10; // safety floor
    }
    output_hub_.logger().trace() << "UpdatesPollingHandler initialized with options: " << opt_desc_ << std::endl;
  }

  std::string command() const override { return "updates"; }

  monad::IO<void> start() override {
    if (!cli_ctx_.params.keep_running) {
      return poll_once();
    }
    // Continuous loop
    return poll_loop(0);
  }
  monad::IO<void> poll_loop(int iter) {
    // perform one poll, swallow/log error, then schedule next (async delay if needed)
    return poll_once()
        .catch_then([self = shared_from_this(), iter](monad::Error e) {
          self->output_hub_.logger().error() << "poll iteration error: " << e.what << std::endl;
          return monad::IO<void>::pure(); // continue
        })
        .then([self = shared_from_this(), iter]() {
          if (!self->cli_ctx_.params.keep_running) {
            self->output_hub_.logger().info() << "keep_running flag cleared; stopping polling loop" << std::endl;
            return monad::IO<void>::pure();
          }
          // Use asynchronous delay to avoid blocking thread when not long-polling
          if (!self->options_.long_poll) {
            return monad::delay_for<void>(self->ioc_, std::chrono::milliseconds(self->interval_ms_))
                .then([self, iter]() { return self->poll_loop(iter + 1); });
          }
          // Long-poll immediately chains next iteration (server waits internally)
          return self->poll_loop(iter + 1);
        });
  }

private:
  monad::IO<void> poll_once() {
    using namespace monad;
    namespace http = boost::beast::http;
    using monad::GetStringTag;
    using monad::http_io;
    using monad::http_request_io;
    // Obtain device token from env for prototype.
    const char *tok = std::getenv("DEVICE_ACCESS_TOKEN");
    if (!tok || !*tok) {
      return IO<void>::fail(monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                                         .what = "DEVICE_ACCESS_TOKEN env not set"});
    }
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
  return http_io<GetStringTag>(url)
        .map([tok, this](auto ex) {
          ex->request.set(http::field::authorization, std::string("Bearer ") + tok);
          if (!cursor_.empty()) {
            ex->request.set(http::field::if_none_match, cursor_);
          }
          return ex;
        })
        .then(http_request_io<GetStringTag>(http_client_))
        .then([this](auto ex) {
          auto &res = *ex->response;
          int status = static_cast<int>(res.result_int());
          last_http_status_ = status;
          last_updates_.reset();
          parse_error_.clear();
          if (auto et = res.find(http::field::etag); et != res.end()) {
            cursor_ = std::string(et->value());
          }
          if (status == 204) {
            output_hub_.logger().info() << "No updates (204). cursor=" << cursor_ << std::endl;
            return monad::IO<void>::pure();
          }
          if (status != 200) {
            output_hub_.logger().error() << "updates poll http status=" << status << std::endl;
            // try parse error json
            if (auto jr = ex->getJsonResponse(); jr.is_ok()) {
              output_hub_.logger().error() << boost::json::serialize(jr.value()) << std::endl;
            }
            return monad::IO<void>::fail(monad::Error{.code = status, .what = "unexpected status"});
          }
          auto jr = ex->getJsonResponse();
          if (jr.is_err()) {
            return monad::IO<void>::fail(jr.error());
          }
          auto v = jr.value();
          try {
            last_updates_ = boost::json::value_to<data::DeviceUpdatesResponse>(v);
            // Update cursor from parsed structure (authoritative)
            cursor_ = last_updates_->data.cursor;
            // Log signals
            for (auto &sig : last_updates_->data.signals) {
              output_hub_.logger().info() << "signal type=" << sig.type
                                          << " ts_ms=" << sig.ts_ms
                                          << " ref=" << boost::json::serialize(sig.ref)
                                          << std::endl;
              if (data::is_install_updated(sig)) ++install_updated_count_;
              else if (data::is_cert_renewed(sig)) ++cert_renewed_count_;
              else if (data::is_cert_revoked(sig)) ++cert_revoked_count_;
            }
          } catch (const std::exception &e) {
            parse_error_ = e.what();
            output_hub_.logger().error() << "Failed to parse updates response: " << parse_error_ << std::endl;
          }
          return monad::IO<void>::pure();
        });
  }

public:
  int last_http_status() const { return last_http_status_; }
  const std::optional<data::DeviceUpdatesResponse> &last_updates() const { return last_updates_; }
  const std::string &last_cursor() const { return cursor_; }
  const std::string &parse_error() const { return parse_error_; }
  size_t install_updated_count() const { return install_updated_count_; }
  size_t cert_renewed_count() const { return cert_renewed_count_; }
  size_t cert_revoked_count() const { return cert_revoked_count_; }
};
} // namespace certctrl
