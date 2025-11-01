#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <fmt/format.h>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "http_client_manager.hpp"
#include "http_client_monad.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "my_error_codes.hpp"

namespace asio = boost::asio;

namespace certctrl::install_actions {

class IDeviceInstallConfigFetcher {
public:
  virtual ~IDeviceInstallConfigFetcher() = default;
  virtual monad::IO<dto::DeviceInstallConfigDto>
  fetch_install_config(std::optional<std::string> access_token,
                       std::optional<std::int64_t> expected_version,
                       const std::optional<std::string> &expected_hash) = 0;
};

// default implementation that fetches from remote server
class DeviceInstallConfigFetcher : public IDeviceInstallConfigFetcher {
public:
  DeviceInstallConfigFetcher(
      cjj365::IoContextManager &io_context_manager,
      certctrl::ICertctrlConfigProvider &config_provider,
      customio::ConsoleOutput &output,
      client_async::HttpClientManager &http_client)
      : config_provider_(config_provider), output_(output),
        http_client_(http_client), io_context_(io_context_manager.ioc()) {}

  monad::IO<dto::DeviceInstallConfigDto> fetch_install_config(
      std::optional<std::string> token_opt,
      std::optional<std::int64_t> expected_version,
      const std::optional<std::string> &expected_hash) override {
  auto perform_fetch = [this, token_opt]()
    -> monad::IO<dto::DeviceInstallConfigDto> {
      if (!token_opt || token_opt->empty()) {
    return monad::IO<dto::DeviceInstallConfigDto>::fail(
      monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                 "Device access token unavailable"));
      }

      const auto &cfg = config_provider_.get();
      std::string url =
          fmt::format("{}/apiv1/devices/self/install-config", cfg.base_url);

      return monad::http_io<monad::GetStringTag>(url)
          .map([token = *token_opt](auto ex) {
            namespace http = boost::beast::http;
            ex->request.set(http::field::authorization,
                            std::string("Bearer ") + token);
            return ex;
          })
          .then(monad::http_request_io<monad::GetStringTag>(http_client_))
          .then([](auto ex) -> monad::IO<dto::DeviceInstallConfigDto> {
            if (!ex->response.has_value()) {
              return monad::IO<dto::DeviceInstallConfigDto>::fail(
                  monad::make_error(my_errors::NETWORK::READ_ERROR,
                                    "No response for install-config"));
            }

            const int status = ex->response->result_int();
            if (status != 200) {
              auto err = monad::make_error(
                  my_errors::NETWORK::READ_ERROR,
                  fmt::format("install-config fetch HTTP status {}", status));
              err.response_status = status;
              err.params["response_body_preview"] = ex->response->body();
              return monad::IO<dto::DeviceInstallConfigDto>::fail(
                  std::move(err));
            }

            return monad::IO<dto::DeviceInstallConfigDto>::from_result(
                ex->template parseJsonDataResponse<
                    dto::DeviceInstallConfigDto>());
          });
    };

    constexpr int kMaxAttempts = 4;
    constexpr std::chrono::milliseconds kBaseRetryDelay{200};

    auto retry_count = std::make_shared<int>(0);
    auto next_delay =
        std::make_shared<std::chrono::milliseconds>(kBaseRetryDelay);

  auto validated_fetch = perform_fetch().then(
    [this, expected_version,
     expected_hash](dto::DeviceInstallConfigDto config)
      -> monad::IO<dto::DeviceInstallConfigDto> {
          if (expected_version && config.version < *expected_version) {
            output_.logger().warning()
                << "Fetched install-config version " << config.version
                << " is older than expected " << *expected_version << std::endl;

        auto err = monad::make_error(
                my_errors::GENERAL::UNEXPECTED_RESULT,
                fmt::format("install-config fetch returned stale version {} "
                            "(expected >= {})",
                            config.version, *expected_version));
            err.params["expected_version"] = std::to_string(*expected_version);
            err.params["observed_version"] = std::to_string(config.version);
            err.params["retry_reason"] = "stale_version";
        return monad::IO<dto::DeviceInstallConfigDto>::fail(
          std::move(err));
          }

          if (expected_version && config.version > *expected_version) {
            output_.logger().info()
                << "Fetched install-config version " << config.version
                << " (ahead of expected " << *expected_version << ")"
                << std::endl;
          }

          if (expected_hash && !config.installs_hash.empty() &&
              config.installs_hash != *expected_hash) {
            output_.logger().warning()
                << "Fetched install-config hash mismatch" << std::endl;
          }

      return monad::IO<dto::DeviceInstallConfigDto>::pure(
        std::move(config));
        });

    auto should_retry = [this, retry_count, next_delay,
                         kMaxAttempts](const monad::Error &err) -> bool {
      auto *reason = err.params.if_contains("retry_reason");
      if (!reason || !reason->is_string() ||
          reason->as_string() != "stale_version") {
        return false;
      }

      const int current_attempt = *retry_count;
      const bool can_retry = (current_attempt + 1) < kMaxAttempts;
      if (can_retry) {
        auto delay = *next_delay;
        output_.logger().info()
            << "Retrying install-config fetch (attempt "
            << (current_attempt + 2) << "/" << kMaxAttempts << ") after "
            << delay.count() << "ms" << std::endl;
        *next_delay = *next_delay * 2;
      } else {
        output_.logger().warning()
            << "install-config fetch exhausted retries for stale version"
            << std::endl;
      }

      ++(*retry_count);
      return can_retry;
    };

  return std::move(validated_fetch)
    .retry_exponential_if(kMaxAttempts, kBaseRetryDelay, io_context_,
                should_retry);
  }

private:
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;
  asio::io_context &io_context_;
};
} // namespace certctrl