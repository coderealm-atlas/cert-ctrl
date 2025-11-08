#pragma once

#include <filesystem>
#include <string>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/i_handler.hpp"
#include "io_monad.hpp"
#include "simple_data.hpp"

namespace certctrl {

class InfoHandler : public IHandler {
  cjj365::ConfigSources &config_sources_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  customio::ConsoleOutput &output_hub_;
  CliCtx &cli_ctx_;

public:
  InfoHandler(cjj365::ConfigSources &config_sources,
              certctrl::ICertctrlConfigProvider &config_provider,
              customio::ConsoleOutput &output_hub,
              CliCtx &cli_ctx);

  std::string command() const override { return "info"; }

  monad::IO<void> start() override;
};

} // namespace certctrl
