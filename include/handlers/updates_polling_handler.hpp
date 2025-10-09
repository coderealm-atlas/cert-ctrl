#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <algorithm>
#include <format>
#include <optional>
#include <string>
#include <vector> // indirectly needed via data structures; keep if build complains
#include <memory>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/data_shape.hpp"
#include "handlers/i_handler.hpp"
#include "handlers/signal_dispatcher.hpp"
#include "handlers/signal_handlers/install_updated_handler.hpp"
#include "handlers/signal_handlers/cert_renewed_handler.hpp"
#include "handlers/signal_handlers/cert_revoked_handler.hpp"
#include "handlers/install_config_manager.hpp"
#include "http_client_manager.hpp"
#include "http_client_monad.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
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
  int interval_ms_{5000}; // delay between polls when not long-polling (default 5s)
  // removed max_loops_ – service runs continuously while keep_running
  // signal counters (cumulative this run)
  size_t install_updated_count_{0};
  size_t cert_renewed_count_{0};
  size_t cert_revoked_count_{0};
  // signal dispatcher
  std::unique_ptr<SignalDispatcher> signal_dispatcher_;
  std::shared_ptr<InstallConfigManager> install_config_manager_;
  std::optional<int> server_override_delay_ms_;

public:
  UpdatesPollingHandler(
      cjj365::IoContextManager &io_context_manager,
      cjj365::ConfigSources &config_sources,
      certctrl::ICertctrlConfigProvider &certctrl_config_provider,
      CliCtx &cli_ctx, customio::ConsoleOutput &output_hub,
      client_async::HttpClientManager &http_client)
      : ioc_(io_context_manager.ioc()), config_sources_(config_sources),
        certctrl_config_provider_(certctrl_config_provider),
        output_hub_(output_hub), cli_ctx_(cli_ctx), http_client_(http_client),
        opt_desc_("updates polling options"),
        endpoint_base_(std::format("{}/apiv1/devices/self/updates",
                                   certctrl_config_provider_.get().base_url)) {
    exec_ = boost::asio::make_strand(ioc_);
    po::options_description create_opts("Updates Polling Options");
  create_opts.add_options()("wait", po::value<int>()->default_value(0),
                "long poll wait seconds (0-30)")(
    "limit",
    po::value<std::size_t>()->default_value(static_cast<std::size_t>(20)),
    "max signals (1-100)")(
      "interval", po::value<int>()->default_value(5000),
        "interval milliseconds between polls when not long-polling (default 5000 = 5s)");
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
    if (cli_ctx_.vm.count("interval")) {
      interval_ms_ = cli_ctx_.vm["interval"].as<int>();
      if (interval_ms_ < 10)
        interval_ms_ = 10; // safety floor
    }
    output_hub_.logger().trace()
        << "UpdatesPollingHandler initialized with options: " << opt_desc_
        << std::endl;
    
  // Initialize signal dispatcher with handlers
  auto runtime_dir = config_sources_.paths_.back();
  signal_dispatcher_ = std::make_unique<SignalDispatcher>(runtime_dir);

  install_config_manager_ = std::make_shared<InstallConfigManager>(
    runtime_dir, certctrl_config_provider_, output_hub_, &http_client_);

  // Register signal handlers
  signal_dispatcher_->register_handler(
    std::make_shared<signal_handlers::InstallUpdatedHandler>(
      install_config_manager_,
      output_hub_));

  signal_dispatcher_->register_handler(
    std::make_shared<signal_handlers::CertRenewedHandler>(
      install_config_manager_,
      output_hub_));

  signal_dispatcher_->register_handler(
    std::make_shared<signal_handlers::CertRevokedHandler>(
      install_config_manager_,
      output_hub_));
    
    output_hub_.logger().info()
        << "Registered " << signal_dispatcher_->handler_count() 
        << " signal handlers" << std::endl;
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
  monad::IO<void> poll_loop(int iter) {
    // perform one poll, swallow/log error, then schedule next (async delay if
    // needed)
    return poll_once()
  .catch_then([self = this->shared_from_this(), iter](monad::Error e) {
          self->output_hub_.logger().error()
              << "poll iteration error: " << e.what << std::endl;
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
          if (!self->options_.long_poll) {
            int delay_ms = self->server_override_delay_ms_.value_or(self->interval_ms_);
            if (delay_ms < 10) {
              delay_ms = 10;
            }
            self->server_override_delay_ms_.reset();
            return monad::delay_for<void>(self->ioc_, std::chrono::milliseconds(delay_ms))
                .then([self, iter]() { return self->poll_loop(iter + 1); });
          }
          // Long-poll immediately chains next iteration (server waits
          // internally)
          return self->poll_loop(iter + 1);
        });
  }

private:
  // Helper methods - must be defined before poll_once() because they're templates
  
  template<typename ExchangePtr>
  monad::IO<void> handle_no_content(ExchangePtr ex) {
    namespace http = boost::beast::http;
    
    // Extract cursor from ETag header
    if (auto it = ex->response->find(http::field::etag); 
        it != ex->response->end()) {
      std::string etag = std::string(it->value());
      if (!etag.empty() && etag.front() == '"' && etag.back() == '"' && etag.size() >= 2) {
        cursor_ = etag.substr(1, etag.size() - 2);
      } else {
        cursor_ = std::move(etag);
      }
      save_cursor(cursor_);
    }
    
    output_hub_.logger().debug()
        << "204 No Content, cursor=" << cursor_ << std::endl;
    
    return monad::IO<void>::pure();
  }
  
  template<typename ExchangePtr>
  monad::IO<void> handle_ok_with_signals(ExchangePtr ex) {
  auto parse_result = ex->template parseJsonDataResponse<::data::DeviceUpdatesResponse>();
    
    if (parse_result.is_err()) {
      return monad::IO<void>::from_result(
          monad::Result<void, monad::Error>::Err(parse_result.error()));
    }
    
    auto resp = std::move(parse_result).value();
    
    // Update cursor
    cursor_ = resp.data.cursor;
    save_cursor(cursor_);
    
    output_hub_.logger().info()
        << "200 OK, " << resp.data.signals.size()
        << " signals, cursor=" << cursor_ << std::endl;
    
    // Store response
    last_updates_ = std::move(resp);
    
    // Dispatch signals synchronously
    for (const auto& signal : last_updates_->data.signals) {
      // Update counters
      if (signal.type == "install.updated")
        ++install_updated_count_;
      else if (signal.type == "cert.renewed")
        ++cert_renewed_count_;
      else if (signal.type == "cert.revoked")
        ++cert_revoked_count_;
      
      // Dispatch to handler (runs synchronously, errors caught internally)
      signal_dispatcher_->dispatch(signal).run([](monad::Result<void, monad::Error>) {
        // Errors already logged by dispatcher, just ignore result
      });
    }
    
    return monad::IO<void>::from_result(monad::Result<void, monad::Error>::Ok());
  }
  
  template<typename ExchangePtr>
  monad::IO<void> handle_error_status(ExchangePtr ex, int status) {
    std::string body = ex->response->body();
    output_hub_.logger().error()
        << "HTTP " << status << " error on " << last_request_url_ << ": "
        << body.substr(0, 200) << std::endl;
    
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
            server_override_delay_ms_ = std::max(interval_ms_, retry_seconds * 1000);
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
                    if (auto *retry_after = params->as_object().if_contains("retry_after")) {
                      if (retry_after->is_int64()) {
                        int retry_seconds = static_cast<int>(retry_after->as_int64());
                        if (retry_seconds > 0) {
                          server_override_delay_ms_ = std::max(interval_ms_, retry_seconds * 1000);
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
        monad::Error{
            .code = my_errors::NETWORK::READ_ERROR,
            .what = std::format("HTTP {} response", status)
        });
  }
  
  void save_cursor(const std::string& cursor) {
    auto config_dir = config_sources_.paths_.back();
    auto cursor_file = config_dir / "state" / "last_cursor.txt";
    auto temp_file = config_dir / "state" / ".last_cursor.txt.tmp";
    
    try {
      // Ensure state directory exists
      std::filesystem::create_directories(config_dir / "state");
      
      std::ofstream ofs(temp_file);
      ofs << cursor;
      ofs.close();
      
      std::filesystem::rename(temp_file, cursor_file);
      std::filesystem::permissions(cursor_file,
          std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write);
    } catch (const std::exception& e) {
      output_hub_.logger().error()
          << "Failed to save cursor: " << e.what() << std::endl;
    }
  }
  
  monad::IO<void> poll_once() {
    using namespace monad;
    namespace http = boost::beast::http;
    using monad::GetStringTag;
    using monad::http_io;
    using monad::http_request_io;
    
    // Obtain device token from env for prototype
  const char *tok = std::getenv("DEVICE_ACCESS_TOKEN");
  if (!tok || !*tok) {
    output_hub_.printer().yellow()
      << "No device access token found; please run `cert_ctrl login` first."
      << std::endl;
    return IO<void>::fail(
      monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
             .what = "DEVICE_ACCESS_TOKEN env not set; run cert_ctrl login"});
  }
    
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

  last_request_url_ = url;
  parse_error_.clear();

  return http_io<GetStringTag>(url)
        .map([tok, this](auto ex) {
          ex->request.set(http::field::authorization,
                          std::string("Bearer ") + tok);
          if (!cursor_.empty()) {
            ex->request.set(http::field::if_none_match,
                            std::format("\"{}\"", cursor_));
          }
          return ex;
        })
        .then(http_request_io<GetStringTag>(http_client_))
        .then([this](auto ex) -> monad::IO<void> {
          if (!ex->response.has_value()) {
            return monad::IO<void>::fail(
                monad::Error{.code = my_errors::NETWORK::READ_ERROR,
                            .what = "No response received"});
          }
          
          int status = ex->response->result_int();
          last_http_status_ = status;
          
          if (status == 204) {
            // No updates - extract cursor from ETag
            return handle_no_content(ex);
          } else if (status == 200) {
            // Has updates - parse JSON and dispatch signals
            return handle_ok_with_signals(ex);
          } else {
            // Error response
            return handle_error_status(ex, status);
          }
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
  size_t cert_renewed_count() const { return cert_renewed_count_; }
  size_t cert_revoked_count() const { return cert_revoked_count_; }
};
} // namespace certctrl
