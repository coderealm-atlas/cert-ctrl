#pragma once

#include "customio/console_output.hpp"
#include <google/protobuf/util/json_util.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include <boost/asio/io_context.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <string>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "dicmeta.pb.h"
#include "handlers/i_handler.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "my_error_codes.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep

namespace po = boost::program_options;

namespace certctrl {

struct ConfHandlerOptions {};

class ConfHandler : public certctrl::IHandler {
  asio::io_context &ioc_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  customio::ConsoleOutput &output_hub_;
  CliCtx &cli_ctx_;
  src::severity_logger<trivial::severity_level> lg;

  po::options_description opt_desc_;
  ConfHandlerOptions options_;

public:
  ConfHandler(cjj365::IoContextManager &io_context_manager,
              certctrl::ICertctrlConfigProvider &certctrl_config_provider,
              CliCtx &cli_ctx, //
              customio::ConsoleOutput &output_hub)
      : ioc_(io_context_manager.ioc()),
        certctrl_config_provider_(certctrl_config_provider),
        output_hub_(output_hub), cli_ctx_(cli_ctx),
        opt_desc_("misc subcommand options") {
    boost::program_options::options_description create_opts("conf Options");
    opt_desc_.add(create_opts);
    po::parsed_options parsed = po::command_line_parser(cli_ctx_.unrecognized)
                                    .options(opt_desc_)
                                    .allow_unregistered()
                                    .run();
    po::store(parsed, cli_ctx_.vm);
    po::notify(cli_ctx_.vm);
    output_hub_.logger().trace()
        << "ConfHandler initialized with options: " << opt_desc_ << std::endl;
  }

  // IHandler
  std::string command() const override { return "conf"; }

  std::string print_opt_desc() const {
    std::ostringstream oss;
    oss << "Usage: \ncert-ctrl conf get <key>\ncert-ctrl conf set <key> "
           "<value>\n"
        << std::endl;
    return oss.str();
  }

  monad::IO<void> show_usage(const std::string &msg = "") {
    if (!msg.empty()) {
      output_hub_.logger().error() << msg << std::endl;
    }
    return monad::IO<void>::fail(
        monad::make_error(my_errors::GENERAL::SHOW_OPT_DESC,
                          print_opt_desc()));
  }

  monad::IO<void> start() override;
};
} // namespace certctrl