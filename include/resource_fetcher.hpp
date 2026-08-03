#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/trivial.hpp>
#include <fmt/format.h>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "http_client_awaitable.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "state/device_state_store.hpp"

namespace certctrl::install_actions {

struct MaterializationData {
  std::shared_ptr<dto::InstallItem> item;
  std::string ob_type;
  std::int64_t ob_id{0};
  bool is_cert{false};
  bool is_ca{false};
  std::filesystem::path current_dir;
  std::string deploy_raw_json;
  std::string detail_raw_json;
  std::string ca_body;
  boost::json::object deploy_obj;
  boost::json::object detail_obj;
  boost::json::object ca_obj;
  bool detail_parsed{false};
  bool deploy_available{false};
  bool ca_parsed{false};
};

class IAccessTokenLoader {
public:
  virtual ~IAccessTokenLoader() = default;
  virtual std::optional<std::string> load_token() const = 0;
};

class AccessTokenLoaderFile : public IAccessTokenLoader {
public:
  explicit AccessTokenLoaderFile(certctrl::IDeviceStateStore &state_store)
      : state_store_(state_store) {}

  std::optional<std::string> load_token() const override {
    return state_store_.get_access_token();
  }

private:
  certctrl::IDeviceStateStore &state_store_;
};

class IResourceFetcher {
public:
  using AccessTokenLoader = std::function<std::optional<std::string>()>;
  virtual ~IResourceFetcher() = default;
  virtual boost::asio::awaitable<monad::MyResult<void>>
  fetch(std::optional<std::string> access_token,
        std::shared_ptr<MaterializationData> state) = 0;
};

class ResourceFetcher : public IResourceFetcher {
public:
  ResourceFetcher(cjj365::IoContextManager &,
                  certctrl::ICertctrlConfigProvider &config_provider,
                  customio::ConsoleOutput &output,
                  client_async::HttpClientManager &http_client)
      : config_provider_(config_provider), output_(output),
        http_client_(http_client) {}

  boost::asio::awaitable<monad::MyResult<void>>
  fetch(std::optional<std::string> token_opt,
        std::shared_ptr<MaterializationData> state) override {
    using Result = monad::MyResult<void>;
    output_.logger().debug()
        << "ResourceFetcher::fetch ob_type=" << state->ob_type
        << " ob_id=" << state->ob_id << " has_token="
        << (token_opt && !token_opt->empty() ? "true" : "false") << std::endl;

    if (!token_opt || token_opt->empty()) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::error)
          << "resource fetch missing token ob_id=" << state->ob_id;
      co_return Result::Err(
          monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                            "Device access token unavailable"));
    }
    if (state->is_cert) {
      co_return co_await fetch_cert(*token_opt, std::move(state));
    }
    if (state->is_ca) {
      output_.logger().debug()
          << "Dispatching CA fetch ob_id=" << state->ob_id << std::endl;
      co_return co_await fetch_ca(*token_opt, std::move(state));
    }

    BOOST_LOG_SEV(lg_, boost::log::trivial::error)
        << "ResourceFetcher::fetch called for unknown resource type ob_type="
        << state->ob_type << " ob_id=" << state->ob_id;
    co_return Result::Ok();
  }

private:
  std::optional<boost::json::object>
  parse_bundle_data(const std::string &body) const {
    boost::system::error_code ec;
    auto parsed = boost::json::parse(body, ec);
    if (ec || !parsed.is_object()) {
      return std::nullopt;
    }
    auto &obj = parsed.as_object();
    if (auto *data = obj.if_contains("data"); data && data->is_object()) {
      return data->as_object();
    }
    return std::nullopt;
  }

  boost::asio::awaitable<monad::MyResult<void>>
  fetch_ca(const std::string &token,
           std::shared_ptr<MaterializationData> state) {
    using Result = monad::MyResult<void>;
    const auto url =
        fmt::format("{}/apiv1/devices/self/cas/{}/bundle?pack=download",
                    config_provider_.get().base_url, state->ob_id);
    output_.logger().debug() << "Fetching CA bundle ob_id=" << state->ob_id
                             << " url=" << url << std::endl;

    auto body_result = co_await fetch_http_body(url, token, "ca bundle");
    if (body_result.is_err()) {
      co_return Result::Err(std::move(body_result).error());
    }
    state->ca_body = std::move(body_result).value();
    output_.logger().debug()
        << "Fetched CA bundle bytes=" << state->ca_body.size()
        << " ob_id=" << state->ob_id << std::endl;

    auto bundle_data = parse_bundle_data(state->ca_body);
    if (!bundle_data) {
      co_return Result::Err(
          monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                            "CA bundle response missing expected data"));
    }
    state->ca_obj = std::move(*bundle_data);
    state->ca_parsed = true;
    output_.logger().debug()
        << "Parsed CA bundle ob_id=" << state->ob_id << std::endl;
    co_return Result::Ok();
  }

  boost::asio::awaitable<monad::MyResult<void>>
  fetch_cert(const std::string &token,
             std::shared_ptr<MaterializationData> state) {
    using Result = monad::MyResult<void>;
    const auto base_url = config_provider_.get().base_url;
    const auto detail_url = fmt::format("{}/apiv1/devices/self/certificates/{}",
                                        base_url, state->ob_id);
    const auto deploy_url =
        fmt::format("{}/apiv1/devices/self/certificates/{}/deploy-materials",
                    base_url, state->ob_id);

    auto detail_result =
        co_await fetch_http_body(detail_url, token, "certificate detail");
    if (detail_result.is_err()) {
      co_return Result::Err(std::move(detail_result).error());
    }
    state->detail_raw_json = std::move(detail_result).value();

    auto deploy_result =
        co_await fetch_http_body(deploy_url, token, "deploy materials");
    if (deploy_result.is_err()) {
      auto err = std::move(deploy_result).error();
      if (err.response_status == 404 || err.response_status == 204) {
        state->deploy_available = false;
        boost::json::object placeholder;
        placeholder["note"] =
            "no deploy materials provided; generated locally by agent";
        state->deploy_raw_json =
            boost::json::serialize(boost::json::object{{"data", placeholder}});
        output_.logger().info()
            << "Deploy materials endpoint unavailable for cert " << state->ob_id
            << " (status=" << err.response_status
            << "); falling back to certificate detail payload" << std::endl;
      } else {
        co_return Result::Err(std::move(err));
      }
    } else {
      state->deploy_raw_json = std::move(deploy_result).value();
      state->deploy_available = true;
    }

    if (auto detail_err = parse_enveloped_object(
            state->detail_raw_json, "certificate detail", state->detail_obj)) {
      co_return Result::Err(std::move(*detail_err));
    }
    state->detail_parsed = true;

    if (!state->deploy_raw_json.empty()) {
      boost::json::object deploy_obj;
      if (auto deploy_err = parse_enveloped_object(
              state->deploy_raw_json, "deploy materials", deploy_obj)) {
        co_return Result::Err(std::move(*deploy_err));
      }
      state->deploy_obj = std::move(deploy_obj);
    }
    co_return Result::Ok();
  }

  boost::asio::awaitable<monad::MyResult<std::string>>
  fetch_http_body(const std::string &url, const std::string &token,
                  const char *context_label) {
    namespace asio = boost::asio;
    namespace http = boost::beast::http;
    using Result = monad::MyResult<std::string>;

    constexpr int kMaxAttempts = 12;
    auto retry_delay = std::chrono::seconds{3};
    const auto executor = co_await asio::this_coro::executor;

    for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
      BOOST_LOG_SEV(lg_, boost::log::trivial::trace)
          << "fetch_http_body attempt " << attempt << '/' << kMaxAttempts
          << " for url=" << url << " context=" << context_label;
      auto exchange_result =
          certctrl::async_support::make_http_exchange<monad::GetStringTag>(url);
      if (exchange_result.is_err()) {
        co_return Result::Err(std::move(exchange_result).error());
      }

      auto exchange = std::move(exchange_result).value();
      exchange->request.set(http::field::authorization,
                            std::string("Bearer ") + token);
      auto request_result =
          co_await certctrl::async_support::http_exchange_awaitable<
              monad::GetStringTag>(http_client_, exchange);
      if (request_result.is_err()) {
        co_return Result::Err(std::move(request_result).error());
      }

      exchange = std::move(request_result).value();
      if (!exchange->response) {
        co_return Result::Err(
            monad::make_error(my_errors::NETWORK::READ_ERROR,
                              "No response while fetching resource"));
      }

      const int status = exchange->response->result_int();
      auto body = exchange->response->body();
      if (status == 200) {
        BOOST_LOG_SEV(lg_, boost::log::trivial::trace)
            << "fetch_http_body succeeded for url=" << url
            << " context=" << context_label
            << " (status=200, bytes=" << body.size() << ')';
        co_return Result::Ok(std::move(body));
      }

      const bool wrap_pending =
          status == 409 && body.find("WRAP_PENDING") != std::string::npos;
      auto err = monad::make_error(
          my_errors::NETWORK::READ_ERROR,
          wrap_pending
              ? fmt::format("Resource fetch HTTP {} WRAP_PENDING", status)
              : fmt::format("Resource fetch HTTP {}", status));
      err.response_status = status;
      err.params["response_body_preview"] = body.substr(0, 512);

      const bool retryable = status == 503 || wrap_pending;
      if (!retryable || attempt == kMaxAttempts) {
        BOOST_LOG_SEV(lg_, boost::log::trivial::warning)
            << "fetch_http_body aborting status=" << status << " url=" << url
            << " context=" << context_label;
        co_return Result::Err(std::move(err));
      }

      BOOST_LOG_SEV(lg_, boost::log::trivial::warning)
          << "fetch_http_body retry for url=" << url
          << " context=" << context_label << " attempt=" << attempt;
      asio::steady_timer timer(executor, retry_delay);
      co_await timer.async_wait(asio::use_awaitable);
      retry_delay *= 2;
    }

    co_return Result::Err(
        monad::make_error(my_errors::NETWORK::READ_ERROR,
                          "Resource fetch exhausted without a response"));
  }

  std::optional<monad::Error>
  parse_enveloped_object(const std::string &raw, const char *context,
                         boost::json::object &out) const {
    boost::system::error_code ec;
    auto parsed = boost::json::parse(raw, ec);
    if (ec || !parsed.is_object()) {
      return monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                               fmt::format("{} response not a JSON object: {}",
                                           context, ec ? ec.message() : ""));
    }
    auto &obj = parsed.as_object();
    if (auto *data = obj.if_contains("data"); data && data->is_object()) {
      out = data->as_object();
      return std::nullopt;
    }
    return monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        fmt::format("{} response missing data object", context));
  }

  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;
  boost::log::sources::severity_logger<boost::log::trivial::severity_level> lg_;
};

} // namespace certctrl::install_actions
