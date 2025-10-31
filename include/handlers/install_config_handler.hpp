#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/program_options.hpp>

#include "certctrl_common.hpp"
#include "customio/console_output.hpp"
#include "handlers/i_handler.hpp"
#include "handlers/install_config_manager.hpp"

namespace cjj365 {
class ConfigSources;
}

namespace client_async {
class HttpClientManager;
}

namespace certctrl {

// Lifetime: constructed per CLI session (via DI vector of handlers).
// Owned by HandlerDispatcher for the duration of command processing.
// Holds a shared_ptr InstallConfigManager created at construction time and
// reused across user operations on this handler instance.

class InstallConfigHandler
    : public IHandler,
      public std::enable_shared_from_this<InstallConfigHandler> {
private:
  certctrl::CliCtx &cli_ctx_;
  customio::ConsoleOutput &output_;
  cjj365::ConfigSources &config_sources_;
  client_async::HttpClientManager &http_client_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  std::unique_ptr<InstallConfigManager> install_config_manager_;

  struct PullOptions {
    bool no_apply{false};
    bool skip_copy{false};
    bool skip_import{false};
    std::optional<std::int64_t> cert_id;
    std::optional<std::int64_t> ca_id;
  };

  PullOptions parse_pull_options(const std::string &action) const;

  monad::IO<void> handle_pull();
  monad::IO<void> handle_apply();
  monad::IO<void> handle_show();
  monad::IO<void> handle_clear_cache();

  static std::optional<std::int64_t>
  get_optional_id(const boost::program_options::variables_map &vm,
                  const char *name);

  monad::IO<void> apply_copy_and_import(
      std::shared_ptr<const dto::DeviceInstallConfigDto> config,
      const PullOptions &options);

  monad::IO<void> run_copy_stage();
  monad::IO<void> run_import_stage();
  void clear_active_context();

  monad::IO<void> show_usage(const std::string &error) const;
  monad::IO<void> show_usage() const;

  std::shared_ptr<const dto::DeviceInstallConfigDto> active_config_;
  std::optional<PullOptions> active_options_;

public:
  InstallConfigHandler(
      cjj365::ConfigSources &config_sources,  //
      certctrl::CliCtx &cli_ctx, //
      customio::ConsoleOutput &output, //
      client_async::HttpClientManager &http_client, //
      std::unique_ptr<InstallConfigManager> install_config_manager,//
      certctrl::ICertctrlConfigProvider &config_provider);

  ~InstallConfigHandler() {
    DEBUG_PRINT("DEBUG_PRINT: InstallConfigHandler destroyed");
  }

  std::string command() const override;
  monad::IO<void> start() override;
};

} // namespace certctrl
