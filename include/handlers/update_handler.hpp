#pragma once

#include <memory>
#include <string>

#include "handlers/i_handler.hpp"
#include "handlers/agent_update_checker.hpp"
#include "io_monad.hpp"
#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "http_client_manager.hpp"
#include "customio/console_output.hpp"

namespace certctrl {

class UpdateHandler : public IHandler {
private:
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;
  certctrl::CliCtx &cli_ctx_;
  std::shared_ptr<AgentUpdateChecker> update_checker_;

  // Platform detection
  std::string detect_platform();
  std::string detect_architecture();
  
  // Update workflow steps
  monad::IO<bool> check_for_updates(const std::string &current_version);
  monad::IO<bool> confirm_update();
  monad::IO<void> perform_update();
  monad::IO<std::string> download_update(const std::string &download_url);
  monad::IO<void> install_update(const std::string &downloaded_file);
  monad::IO<void> backup_current_binary();
  monad::IO<void> replace_binary(const std::string &new_binary_path);
  
  // Helper methods
  std::string get_current_binary_path();
  std::string generate_backup_path();
  bool verify_downloaded_file(const std::string &file_path, const std::string &checksum_url);

public:
  UpdateHandler(certctrl::ICertctrlConfigProvider &config_provider,
                customio::ConsoleOutput &output,
                client_async::HttpClientManager &http_client,
                certctrl::CliCtx &cli_ctx,
                std::shared_ptr<AgentUpdateChecker> update_checker);

  std::string command() const override;
  monad::IO<void> start() override;
};

} // namespace certctrl