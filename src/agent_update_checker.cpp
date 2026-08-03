#include "handlers/agent_update_checker.hpp"

#include <boost/beast/http/field.hpp>
#include <boost/json.hpp>
#include <boost/url/parse.hpp>
#include <fmt/format.h>

#include "data/agent_update_check.hpp"
#include "http_client_awaitable.hpp"
#include "my_error_codes.hpp"

namespace certctrl {

AgentUpdateChecker::AgentUpdateChecker(
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    client_async::HttpClientManager &http_client)
    : config_provider_(config_provider), output_(output),
      http_client_(http_client) {}

std::string AgentUpdateChecker::detect_platform() {
#if defined(_WIN32)
  return "windows";
#elif defined(__APPLE__)
  return "macos";
#elif defined(__linux__)
  return "linux";
#else
  return "unknown";
#endif
}

std::string AgentUpdateChecker::detect_architecture() {
#if defined(__x86_64__) || defined(_M_X64)
  return "x64";
#elif defined(__aarch64__) || defined(_M_ARM64)
  return "arm64";
#elif defined(__arm__) || defined(_M_ARM)
  return "arm";
#elif defined(__i386__) || defined(_M_IX86)
  return "x86";
#else
  return "unknown";
#endif
}

boost::asio::awaitable<monad::MyResult<void>>
AgentUpdateChecker::run_once_awaitable(const std::string &current_version) {
  namespace http = boost::beast::http;

  const auto &config = config_provider_.get();
  if (config.update_check_url.empty()) {
    output_.logger().info()
        << "Agent update check skipped: update_check_url not configured"
        << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  auto parsed = boost::urls::parse_uri(config.update_check_url);
  if (parsed.has_error()) {
    output_.logger().warning()
        << "Agent update check skipped: invalid update_check_url '"
        << config.update_check_url << "'" << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  boost::urls::url url = parsed.value();
  url.params().set("current", current_version);
  url.params().set("platform", detect_platform());
  url.params().set("arch", detect_architecture());

  const auto user_agent = fmt::format("cert-ctrl/{} ({}; {})", current_version,
                                      detect_platform(), detect_architecture());
  output_.logger().info() << "Checking for agent updates via " << url
                          << std::endl;

  auto exchange_result =
      async_support::make_http_exchange<monad::GetStringTag>(url.buffer());
  if (exchange_result.is_err()) {
    co_return monad::MyResult<void>::Err(exchange_result.error());
  }
  auto exchange = std::move(exchange_result).value();
  exchange->request.set(http::field::user_agent, user_agent);
  exchange->request.set(http::field::accept, "application/json");

  auto request_result =
      co_await async_support::http_exchange_awaitable<monad::GetStringTag>(
          http_client_, std::move(exchange));
  if (request_result.is_err()) {
    co_return monad::MyResult<void>::Err(request_result.error());
  }
  auto response_exchange = std::move(request_result).value();
  if (!response_exchange->response.has_value()) {
    co_return monad::MyResult<void>::Err(
        monad::make_error(my_errors::NETWORK::READ_ERROR,
                          "No response from update check service"));
  }

  const int status = response_exchange->response->result_int();
  if (status < 200 || status >= 300) {
    output_.logger().warning()
        << "Agent update check HTTP " << status << " from " << url << std::endl;
    co_return monad::MyResult<void>::Err(
        monad::make_error(status, fmt::format("HTTP {} response", status)));
  }

  auto parse_result =
      response_exchange->template parseJsonResponse<boost::json::value>();
  if (parse_result.is_err()) {
    auto error = parse_result.error();
    output_.logger().error()
        << "Failed to parse update check response: " << error.what << std::endl;
    co_return monad::MyResult<void>::Err(std::move(error));
  }

  auto response = boost::json::value_to<data::AgentUpdateCheckResponse>(
      parse_result.value());
  output_.logger().info() << "Agent version status: current="
                          << response.current_version
                          << ", latest=" << response.latest_version
                          << std::endl;

  if (!response.newer_version_available) {
    output_.logger().info() << "Agent is up to date." << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  output_.printer().yellow()
      << "A newer agent version is available: " << response.latest_version
      << std::endl;
  if (response.security_update && *response.security_update) {
    output_.printer().red()
        << "This release contains security updates." << std::endl;
  }
  if (!response.deprecation_warnings.empty()) {
    output_.printer().magenta() << "Deprecation warnings:" << std::endl;
    for (const auto &warning : response.deprecation_warnings) {
      output_.printer().magenta() << "  - " << warning << std::endl;
    }
  }
  if (response.update_urgency) {
    output_.logger().info()
        << "Update urgency: " << *response.update_urgency << std::endl;
  }
  if (response.minimum_supported_version) {
    output_.logger().info()
        << "Minimum supported version: " << *response.minimum_supported_version
        << std::endl;
  }
  if (response.changelog_url) {
    output_.logger().info()
        << "Changelog: " << *response.changelog_url << std::endl;
  }
  if (!response.install_commands.empty()) {
    output_.printer().green()
        << "Recommended installation commands:" << std::endl;
    for (const auto &[platform, command] : response.install_commands) {
      output_.printer().green()
          << "  " << platform << ": " << command << std::endl;
    }
  } else if (!response.download_urls.empty()) {
    output_.logger().info() << "Download URLs:" << std::endl;
    for (const auto &[key, value] : response.download_urls) {
      output_.logger().info() << "  " << key << ": " << value << std::endl;
    }
  }

  co_return monad::MyResult<void>::Ok();
}

} // namespace certctrl
