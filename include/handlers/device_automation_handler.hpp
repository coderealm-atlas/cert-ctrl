#pragma once

#include <memory>
#include <optional>
#include <string>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/i_handler.hpp"
#include "http_client_manager.hpp"
#include "io_monad.hpp"
#include "state/device_state_store.hpp"

namespace certctrl {

class DeviceAutomationHandler
    : public IHandler,
      public std::enable_shared_from_this<DeviceAutomationHandler> {
public:
  DeviceAutomationHandler(CliCtx &cli_ctx,                   //
                          customio::ConsoleOutput &output,   //
                          certctrl::ICertctrlConfigProvider &config_provider,
                          client_async::HttpClientManager &http_client,
                          certctrl::IDeviceStateStore &state_store);

  std::string command() const override { return "device"; }
  monad::IO<void> start() override;

private:
  struct ActionOptions {
    bool requested_help{false};
    std::optional<std::string> api_key;
    std::optional<std::string> payload_inline;
    std::optional<std::string> payload_file;
  };

  CliCtx &cli_ctx_;
  customio::ConsoleOutput &output_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  client_async::HttpClientManager &http_client_;
  certctrl::IDeviceStateStore &state_store_;

  monad::IO<void> show_usage(const std::string &error = "") const;
  monad::IO<void> handle_assign_certificate(const std::string &api_key);
  monad::IO<void> handle_install_config_update(const ActionOptions &options);
  monad::IO<void> dispatch_action(const std::string &action,
                                  const ActionOptions &options);
  ActionOptions parse_action_options(const std::string &action) const;
};

} // namespace certctrl
