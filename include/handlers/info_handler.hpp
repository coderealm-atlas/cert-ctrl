#pragma once

#include <filesystem>
#include <string>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/i_handler.hpp"
#include "simple_data.hpp"
#include "state/device_state_store.hpp"

namespace certctrl {

class InfoHandler : public IHandler {
  cjj365::ConfigSources &config_sources_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  customio::ConsoleOutput &output_hub_;
  CliCtx &cli_ctx_;
  certctrl::IDeviceStateStore &state_store_;

public:
  InfoHandler(cjj365::ConfigSources &config_sources,
              certctrl::ICertctrlConfigProvider &config_provider,
              customio::ConsoleOutput &output_hub, CliCtx &cli_ctx,
              certctrl::IDeviceStateStore &state_store);

  std::string command() const override { return "info"; }

  boost::asio::awaitable<monad::MyResult<void>> start_awaitable() override;
};

} // namespace certctrl
