#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/http.hpp>
#include <fmt/format.h>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "http_client_awaitable.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace certctrl::install_actions {

class IDeviceInstallConfigFetcher {
public:
  virtual ~IDeviceInstallConfigFetcher() = default;
  virtual boost::asio::awaitable<monad::MyResult<dto::DeviceInstallConfigDto>>
  fetch_install_config(std::optional<std::string> access_token,
                       std::optional<std::int64_t> expected_version,
                       const std::optional<std::string> &expected_hash) = 0;
};

class DeviceInstallConfigFetcher : public IDeviceInstallConfigFetcher {
public:
  DeviceInstallConfigFetcher(cjj365::IoContextManager &,
                             certctrl::ICertctrlConfigProvider &config_provider,
                             customio::ConsoleOutput &output,
                             client_async::HttpClientManager &http_client)
      : config_provider_(config_provider), output_(output),
        http_client_(http_client) {}

  boost::asio::awaitable<monad::MyResult<dto::DeviceInstallConfigDto>>
  fetch_install_config(
      std::optional<std::string> token_opt,
      std::optional<std::int64_t> expected_version,
      const std::optional<std::string> &expected_hash) override {
    namespace asio = boost::asio;
    namespace http = boost::beast::http;
    using Result = monad::MyResult<dto::DeviceInstallConfigDto>;

    if (!token_opt || token_opt->empty()) {
      co_return Result::Err(
          monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                            "Device access token unavailable"));
    }

    constexpr int kMaxAttempts = 4;
    auto retry_delay = std::chrono::milliseconds{200};
    const auto executor = co_await asio::this_coro::executor;
    const auto url = fmt::format("{}/apiv1/devices/self/install-config",
                                 config_provider_.get().base_url);

    for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
      auto exchange_result =
          certctrl::async_support::make_http_exchange<monad::GetStringTag>(url);
      if (exchange_result.is_err()) {
        co_return Result::Err(std::move(exchange_result).error());
      }

      auto exchange = std::move(exchange_result).value();
      exchange->request.set(http::field::authorization,
                            std::string("Bearer ") + *token_opt);
      auto request_result =
          co_await certctrl::async_support::http_exchange_awaitable<
              monad::GetStringTag>(http_client_, exchange);
      if (request_result.is_err()) {
        co_return Result::Err(std::move(request_result).error());
      }

      exchange = std::move(request_result).value();
      if (!exchange->response) {
        co_return Result::Err(monad::make_error(
            my_errors::NETWORK::READ_ERROR, "No response for install-config"));
      }

      const int status = exchange->response->result_int();
      if (status != 200) {
        auto err = monad::make_error(
            my_errors::NETWORK::READ_ERROR,
            fmt::format("install-config fetch HTTP status {}", status));
        err.response_status = status;
        err.params["response_body_preview"] = exchange->response->body();
        co_return Result::Err(std::move(err));
      }

      auto parsed =
          exchange
              ->template parseJsonDataResponse<dto::DeviceInstallConfigDto>();
      if (parsed.is_err()) {
        co_return Result::Err(std::move(parsed).error());
      }
      auto config = std::move(parsed).value();

      if (expected_version && config.version < *expected_version) {
        output_.logger().warning()
            << "Fetched install-config version " << config.version
            << " is older than expected " << *expected_version << std::endl;
        if (attempt == kMaxAttempts) {
          auto err = monad::make_error(
              my_errors::GENERAL::UNEXPECTED_RESULT,
              fmt::format("install-config fetch returned stale version {} "
                          "(expected >= {})",
                          config.version, *expected_version));
          err.params["expected_version"] = std::to_string(*expected_version);
          err.params["observed_version"] = std::to_string(config.version);
          err.params["retry_reason"] = "stale_version";
          co_return Result::Err(std::move(err));
        }

        output_.logger().info()
            << "Retrying install-config fetch (attempt " << (attempt + 1) << '/'
            << kMaxAttempts << ") after " << retry_delay.count() << "ms"
            << std::endl;
        asio::steady_timer timer(executor, retry_delay);
        co_await timer.async_wait(asio::use_awaitable);
        retry_delay *= 2;
        continue;
      }

      if (expected_version && config.version > *expected_version) {
        output_.logger().info()
            << "Fetched install-config version " << config.version
            << " (ahead of expected " << *expected_version << ')' << std::endl;
      }
      if (expected_hash && !config.installs_hash.empty() &&
          config.installs_hash != *expected_hash) {
        output_.logger().warning()
            << "Fetched install-config hash mismatch" << std::endl;
      }

      co_return Result::Ok(std::move(config));
    }

    co_return Result::Err(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                          "install-config fetch exhausted without a result"));
  }

private:
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;
};

} // namespace certctrl::install_actions
