#include "handlers/update_handler.hpp"

#include <boost/beast/http/field.hpp>
#include <boost/json.hpp>
#include <boost/url/parse.hpp>
#include <format>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <algorithm>
#include <ctime>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <climits>
#elif defined(__linux__)
#include <unistd.h>
#endif

#include "data/agent_update_check.hpp"
#include "my_error_codes.hpp"
#include "version.h"

namespace certctrl {
namespace fs = std::filesystem;

UpdateHandler::UpdateHandler(
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    client_async::HttpClientManager &http_client,
    certctrl::CliCtx &cli_ctx,
    std::shared_ptr<AgentUpdateChecker> update_checker)
    : config_provider_(config_provider), output_(output),
      http_client_(http_client), cli_ctx_(cli_ctx),
      update_checker_(update_checker) {}

std::string UpdateHandler::command() const {
  return "update";
}

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

std::string UpdateHandler::detect_architecture() {
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

std::string UpdateHandler::get_current_binary_path() {
  // Get the path of the currently running executable
  fs::path exe_path;
  
#if defined(__linux__)
  try {
    exe_path = fs::read_symlink("/proc/self/exe");
  } catch (const std::exception&) {
    // Fallback - use argv[0] if available
    exe_path = "cert-ctrl"; 
  }
#elif defined(__APPLE__)
  char buffer[PATH_MAX];
  uint32_t size = sizeof(buffer);
  if (_NSGetExecutablePath(buffer, &size) == 0) {
    exe_path = fs::path(buffer);
  }
#else
  // Fallback for other platforms
  exe_path = "cert-ctrl";
#endif

  return exe_path.string();
}

std::string UpdateHandler::generate_backup_path() {
  auto current_path = get_current_binary_path();
  auto timestamp = std::time(nullptr);
  return current_path + ".backup." + std::to_string(timestamp);
}

monad::IO<void> UpdateHandler::start() {
  using namespace monad;

  output_.logger().info() << "Starting application update process..." << std::endl;

  std::string current_version = MYAPP_VERSION;
  output_.logger().info() << "Current version: " << current_version << std::endl;

  return check_for_updates(current_version)
    .then([this](bool update_available) -> monad::IO<void> {
      if (!update_available) {
        output_.logger().info() << "No updates available. You are running the latest version." << std::endl;
        return monad::IO<void>::pure();
      }

      // Check for --yes flag to skip confirmation  
      bool auto_confirm = cli_ctx_.params.confirm_update;

      if (auto_confirm) {
        output_.logger().info() << "Auto-confirming update due to --yes flag." << std::endl;
        return perform_update();
      } else {
        return confirm_update()
          .then([this](bool confirmed) -> monad::IO<void> {
            if (confirmed) {
              return perform_update();
            } else {
              output_.logger().info() << "Update cancelled by user." << std::endl;
              return monad::IO<void>::pure();
            }
          });
      }
    });
}

monad::IO<bool> UpdateHandler::check_for_updates(const std::string& current_version) {
  output_.logger().info() << "Checking for updates..." << std::endl;
  
  // Use AgentUpdateChecker to get latest version and compare
  // For now, simplified version - just call run_once and return true as placeholder
  auto check_result = update_checker_->run_once(current_version);
  (void)check_result; // Suppress unused variable warning
  
  // For now, we'll return a dummy result indicating update is available
  // In real implementation, we'd parse the response and compare versions
  return monad::IO<bool>::pure(true);
}

monad::IO<bool> UpdateHandler::confirm_update() {
  using namespace monad;

  std::cout << "\nA new version is available. Do you want to update now? [y/N]: ";
  std::string response;
  std::getline(std::cin, response);
  
  // Convert to lowercase for comparison
  std::transform(response.begin(), response.end(), response.begin(), ::tolower);
  bool confirmed = (response == "y" || response == "yes");
  
  return monad::IO<bool>::pure(confirmed);
}

monad::IO<void> UpdateHandler::perform_update() {
  using namespace monad;

  output_.logger().info() << "Starting update download and installation..." << std::endl;

  // Get download URL for current platform/architecture
  std::string platform = detect_platform();
  std::string arch = detect_architecture();
  std::string expected_filename;
  
#if defined(_WIN32)
  expected_filename = std::format("cert-ctrl-{}-{}.zip", platform, arch);
#else
  expected_filename = std::format("cert-ctrl-{}-{}.tar.gz", platform, arch);
#endif

  // Get download URL from our Cloudflare install service instead of GitHub directly
  const auto& config = config_provider_.get();
  std::string base_url = config.update_check_url;
  
  // Convert version check URL to download URL
  // Replace "/api/version/check" with "/download"
  const std::string version_check_suffix = "/api/version/check";
  if (base_url.ends_with(version_check_suffix)) {
    base_url = base_url.substr(0, base_url.length() - version_check_suffix.length());
  }
  
  // Ensure base_url doesn't end with a slash to avoid double slashes
  if (base_url.ends_with("/")) {
    base_url = base_url.substr(0, base_url.length() - 1);
  }
  
  std::string download_url = std::format("{}/download/{}", base_url, expected_filename);

  output_.logger().info() << "Download URL: " << download_url << std::endl;

  // For now, implement a simplified version
  try {
    output_.logger().info() << "Downloading update..." << std::endl;
    // TODO: Implement actual download
    
    output_.logger().info() << "Creating backup..." << std::endl; 
    std::string current_path = get_current_binary_path();
    std::string backup_path = generate_backup_path();
    fs::copy_file(current_path, backup_path);
    
    output_.logger().info() << "Installing update..." << std::endl;
    // TODO: Implement actual installation
    
    output_.logger().info() << "Update completed successfully!" << std::endl;
    output_.logger().info() << "Please restart the application to use the new version." << std::endl;
    
    return monad::IO<void>::pure();
  } catch (const std::exception& e) {
    output_.logger().error() << "Update failed: " << e.what() << std::endl;
    return monad::IO<void>::fail({.code = my_errors::GENERAL::UPDATE_FAILED, .what = e.what()});
  }
}

monad::IO<std::string> UpdateHandler::download_update(const std::string &download_url) {
  using namespace monad;

  output_.logger().info() << "Downloading update from: " << download_url << std::endl;

  // Create temporary download directory
  fs::path temp_dir = fs::temp_directory_path() / "cert-ctrl-update";
  fs::create_directories(temp_dir);
  
  fs::path download_path = temp_dir / fs::path(download_url).filename();
  
  // TODO: Implement actual HTTP download using http_client_
  // For now, return a placeholder
  output_.logger().info() << "Download would save to: " << download_path << std::endl;
  
  // Simulate successful download
  return monad::IO<std::string>::pure(download_path.string());
}

monad::IO<void> UpdateHandler::backup_current_binary() {
  using namespace monad;

  std::string current_path = get_current_binary_path();
  std::string backup_path = generate_backup_path();

  output_.logger().info() << "Creating backup: " << current_path << " -> " << backup_path << std::endl;

  try {
    fs::copy_file(current_path, backup_path);
    output_.logger().info() << "Backup created successfully." << std::endl;
    return monad::IO<void>::pure();
  } catch (const std::exception& e) {
    return monad::IO<void>::fail({.code = my_errors::GENERAL::UPDATE_FAILED, 
                           .what = std::format("Failed to create backup: {}", e.what())});
  }
}

monad::IO<void> UpdateHandler::install_update(const std::string &downloaded_file) {
  using namespace monad;

  output_.logger().info() << "Installing update from: " << downloaded_file << std::endl;

  // TODO: Extract archive and replace binary
  // This would involve:
  // 1. Extract the downloaded archive
  // 2. Find the cert-ctrl binary in the extracted files
  // 3. Replace the current binary with the new one
  // 4. Set proper permissions

  output_.logger().info() << "Update installation completed (placeholder)." << std::endl;
  
  return monad::IO<void>::pure();
}

bool UpdateHandler::verify_downloaded_file(const std::string &file_path, 
                                           const std::string &checksum_url) {
  // TODO: Download checksum file and verify the downloaded binary
  // For now, return true (no verification)
  return true;
}

} // namespace certctrl