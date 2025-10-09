#pragma once

#include "customio/console_output.hpp"
#include "data/device_auth_types.hpp"
#include "http_client_manager.hpp"
#include <google/protobuf/util/json_util.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <string>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "handlers/i_handler.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "my_error_codes.hpp"
#include "simple_data.hpp"
#include "util/device_fingerprint.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep
#include "data/data_shape.hpp"

namespace po = boost::program_options;

namespace certctrl {

struct LoginHandlerOptions {};

class LoginHandler : public certctrl::IHandler,
                     public std::enable_shared_from_this<LoginHandler> {
  asio::io_context &ioc_;
  cjj365::ConfigSources &config_sources_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  client_async::HttpClientManager &http_client_;
  customio::ConsoleOutput &output_hub_;
  CliCtx &cli_ctx_;
  src::severity_logger<trivial::severity_level> lg;
  po::options_description opt_desc_;
  LoginHandlerOptions options_;
  std::string device_auth_url_;
  std::optional<::data::deviceauth::StartResp> start_resp_;
  std::optional<::data::deviceauth::PollResp> poll_resp_;
  bool registration_completed_{false};
  boost::asio::any_io_executor exec_;

public:
  LoginHandler(cjj365::IoContextManager &io_context_manager,
               cjj365::ConfigSources &config_sources,
               certctrl::ICertctrlConfigProvider &certctrl_config_provider,
               CliCtx &cli_ctx, //
               customio::ConsoleOutput &output_hub,
               client_async::HttpClientManager &http_client)
      : ioc_(io_context_manager.ioc()),
        config_sources_(config_sources),
        certctrl_config_provider_(certctrl_config_provider),
        output_hub_(output_hub), cli_ctx_(cli_ctx), http_client_(http_client),
        device_auth_url_(std::format("{}/auth/device",
                                     certctrl_config_provider_.get().base_url)),
        opt_desc_("misc subcommand options") {
    exec_ = boost::asio::make_strand(ioc_);
    boost::program_options::options_description create_opts("conf Options");
    opt_desc_.add(create_opts);
    po::parsed_options parsed = po::command_line_parser(cli_ctx_.unrecognized)
                                    .options(opt_desc_)
                                    .allow_unregistered()
                                    .run();
    po::store(parsed, cli_ctx_.vm);
    po::notify(cli_ctx_.vm);
    output_hub_.logger().trace()
        << "LoginHandler initialized with options: " << opt_desc_ << std::endl;
  }

  // IHandler
  std::string command() const override { return "login"; }

  std::string print_opt_desc() const {
    std::ostringstream oss;
    oss << opt_desc_;
    return oss.str();
  }

  monad::IO<void> show_usage(const std::string &msg = "") {
    if (!msg.empty()) {
      output_hub_.logger().error() << msg << std::endl;
    }
    return monad::IO<void>::fail(
        {.code = my_errors::GENERAL::SHOW_OPT_DESC, .what = print_opt_desc()});
  }

  monad::IO<void> start() override;
  monad::IO<void> poll();
  monad::IO<void> register_device();

  monad::IO<::data::deviceauth::StartResp> start_device_authorization();
  monad::IO<::data::deviceauth::PollResp> poll_device_once();
};
} // namespace certctrl