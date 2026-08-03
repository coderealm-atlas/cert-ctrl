#include "handlers/update_handler.hpp"

namespace certctrl {

UpdateHandler::UpdateHandler(certctrl::ICertctrlConfigProvider &config_provider,
                             customio::ConsoleOutput &output,
                             client_async::HttpClientManager &http_client,
                             certctrl::CliCtx &cli_ctx,
                             std::shared_ptr<AgentUpdateChecker> update_checker)
    : output_(output) {
  (void)config_provider;
  (void)http_client;
  (void)cli_ctx;
  (void)update_checker;
}

std::string UpdateHandler::command() const { return "update"; }

std::string UpdateHandler::detect_platform() {
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

boost::asio::awaitable<monad::MyResult<void>> UpdateHandler::start_awaitable() {
  output_.logger().info()
      << "cert-ctrl does not perform self-updates automatically yet."
      << std::endl;
  output_.logger().info()
      << "Use the installer script for your platform to upgrade to the latest "
         "build:"
      << std::endl;

  const auto platform = detect_platform();
  if (platform == "windows") {
    output_.logger().info()
        << "  Windows: irm https://install.lets-script.com/install.ps1 | iex"
        << std::endl;
  } else if (platform == "macos") {
    output_.logger().info()
        << "  macOS: curl -fsSL "
           "https://install.lets-script.com/install-macos.sh | sudo bash"
        << std::endl;
  } else {
    output_.logger().info()
        << "  Linux: curl -fsSL https://install.lets-script.com/install.sh | "
           "sudo bash"
        << std::endl;
  }

  output_.logger().info()
      << "Add --version <tag> if you need to pin a specific release."
      << std::endl;
  output_.logger().info()
      << "The installer stops the running service, replaces the binary, "
         "updates PATH, and restarts when applicable."
      << std::endl;
  co_return monad::MyResult<void>::Ok();
}

} // namespace certctrl
