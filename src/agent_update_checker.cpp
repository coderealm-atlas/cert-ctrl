#include "handlers/agent_update_checker.hpp"

#include <boost/beast/http/field.hpp>
#include <boost/json.hpp>
#include <boost/url/parse.hpp>
#include <format>
#include <optional>

#include "data/agent_update_check.hpp"
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

monad::IO<void> AgentUpdateChecker::run_once(
    const std::string &current_version) {
  using namespace monad;
  namespace http = boost::beast::http;

  const auto &cfg_ref = config_provider_.get();
  if (cfg_ref.update_check_url.empty()) {
    output_.logger().info()
        << "Agent update check skipped: update_check_url not configured"
        << std::endl;
    return IO<void>::pure();
  }

  auto *output = &output_;
  auto &client = http_client_;
  std::string update_url = cfg_ref.update_check_url;

  auto parsed = boost::urls::parse_uri(update_url);
  if (parsed.has_error()) {
    output->logger().warning()
        << "Agent update check skipped: invalid update_check_url '"
        << update_url << "'" << std::endl;
    return IO<void>::pure();
  }

  boost::urls::url url = parsed.value();
  url.params().set("current", current_version);
  url.params().set("platform", detect_platform());
  url.params().set("arch", detect_architecture());

  auto user_agent =
      std::format("cert-ctrl/{} ({}; {})", current_version, detect_platform(),
                  detect_architecture());

  output->logger().info()
      << "Checking for agent updates via " << url << std::endl;

  return http_io<GetStringTag>(url)
      .map([user_agent](auto ex) {
        ex->request.set(http::field::user_agent, user_agent);
        ex->request.set(http::field::accept, "application/json");
        return ex;
      })
      .then(http_request_io<GetStringTag>(client))
      .then([output, url_string = url.buffer()](auto ex) -> IO<void> {
        if (!ex->response.has_value()) {
          return IO<void>::fail(
              monad::Error{.code = my_errors::NETWORK::READ_ERROR,
                           .what = "No response from update check service"});
        }
        const int status = ex->response->result_int();
        if (status < 200 || status >= 300) {
          output->logger().warning()
              << "Agent update check HTTP " << status << " from "
              << url_string << std::endl;
          return IO<void>::fail(monad::Error{
              .code = status,
              .what = std::format("HTTP {} response", status)});
        }

        auto parse_result =
            ex->template parseJsonResponse<boost::json::value>();
        if (parse_result.is_err()) {
          auto err = parse_result.error();
          output->logger().error()
              << "Failed to parse update check response: " << err.what
              << std::endl;
          return IO<void>::fail(err);
        }

        const auto value = parse_result.value();
        auto response =
            boost::json::value_to<data::AgentUpdateCheckResponse>(value);

        output->logger().info()
            << "Agent version status: current=" << response.current_version
            << ", latest=" << response.latest_version << std::endl;

        if (response.newer_version_available) {
          output->printer().yellow()
              << "A newer agent version is available: "
              << response.latest_version << std::endl;
          if (response.security_update && *response.security_update) {
            output->printer().red()
                << "This release contains security updates." << std::endl;
          }
          if (!response.deprecation_warnings.empty()) {
            output->printer().magenta()
                << "Deprecation warnings:" << std::endl;
            for (const auto &warning : response.deprecation_warnings) {
              output->printer().magenta() << "  - " << warning << std::endl;
            }
          }
          if (response.update_urgency.has_value()) {
            output->logger().info()
                << "Update urgency: " << *response.update_urgency << std::endl;
          }
          if (response.minimum_supported_version.has_value()) {
            output->logger().info()
                << "Minimum supported version: "
                << *response.minimum_supported_version << std::endl;
          }
          if (!response.download_urls.empty()) {
            output->logger().info() << "Download URLs:" << std::endl;
            for (const auto &[key, value] : response.download_urls) {
              output->logger().info()
                  << "  " << key << ": " << value << std::endl;
            }
          }
          if (response.changelog_url.has_value()) {
            output->logger().info()
                << "Changelog: " << *response.changelog_url << std::endl;
          }
        } else {
          output->logger().info()
              << "Agent is up to date." << std::endl;
        }

        return IO<void>::pure();
      });
}

} // namespace certctrl
