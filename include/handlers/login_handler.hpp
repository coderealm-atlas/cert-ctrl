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
#include <filesystem>
#include <chrono>
#include <optional>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "handlers/i_handler.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "my_error_codes.hpp"
#include "simple_data.hpp"
#include "state/device_state_store.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep
#include <fmt/format.h>

namespace po = boost::program_options;

namespace certctrl {

struct LoginHandlerOptions {
  bool force{false};
  std::optional<std::string> api_key;
};

struct DeviceRegistrationRequestConfig {
  std::optional<std::string> user_id;
  std::optional<std::string> registration_code;
  std::optional<std::string> refresh_token;
  bool include_cached_refresh_token{true};
  std::optional<std::string> api_key;
  std::string endpoint_path;
};

class LoginHandler : public certctrl::IHandler,
                     public std::enable_shared_from_this<LoginHandler> {
  asio::io_context &ioc_;
  cjj365::ConfigSources &config_sources_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  client_async::HttpClientManager &http_client_;
  IDeviceStateStore &state_store_;
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
  std::optional<std::filesystem::path> runtime_dir_;

public:
  LoginHandler(cjj365::IoContextManager &io_context_manager,
               cjj365::ConfigSources &config_sources,
               certctrl::ICertctrlConfigProvider &certctrl_config_provider,
               CliCtx &cli_ctx, //
               customio::ConsoleOutput &output_hub,
               client_async::HttpClientManager &http_client,
               IDeviceStateStore &state_store)
      : ioc_(io_context_manager.ioc()),
        config_sources_(config_sources),
        certctrl_config_provider_(certctrl_config_provider),
        http_client_(http_client), state_store_(state_store),
        output_hub_(output_hub), cli_ctx_(cli_ctx),
        device_auth_url_(fmt::format("{}/auth/device",
                                     certctrl_config_provider_.get().base_url)),
        opt_desc_("misc subcommand options") {
    exec_ = boost::asio::make_strand(ioc_);
    try {
      if (!config_sources.paths_.empty()) {
        runtime_dir_ = std::filesystem::path(config_sources.paths_.back());
      }
    } catch (...) {
      runtime_dir_.reset();
    }

    boost::program_options::options_description create_opts("Login Options");
    create_opts.add_options()
        ("force",
         po::bool_switch(&options_.force)->default_value(false),
         "Force device re-authorization; clears cached session tokens before login.")
        ("apikey", po::value<std::string>(),
         "Direct device registration using an API key; skips the device authorization flow.");
    opt_desc_.add(create_opts);
    po::parsed_options parsed = po::command_line_parser(cli_ctx_.unrecognized)
                                    .options(opt_desc_)
                                    .allow_unregistered()
                                    .run();
    po::store(parsed, cli_ctx_.vm);
    po::notify(cli_ctx_.vm);
    if (cli_ctx_.vm.count("apikey")) {
      options_.api_key = cli_ctx_.vm["apikey"].as<std::string>();
    }
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
        monad::make_error(my_errors::GENERAL::SHOW_OPT_DESC,
                          print_opt_desc()));
  }

  monad::IO<void> start() override;
  monad::IO<void> poll();
  monad::IO<void> register_device();
  monad::IO<void> register_device_with_api_key(const std::string &api_key);

  monad::IO<::data::deviceauth::StartResp> start_device_authorization();
  monad::IO<::data::deviceauth::PollResp> poll_device_once();

private:
  void clear_cached_session();
  monad::IO<bool> reuse_existing_session_if_possible();
  monad::IO<bool>
  refresh_session_with_token(const std::string &refresh_token);
  std::optional<std::filesystem::path> resolve_runtime_dir() const;
  static bool is_access_token_valid(const std::string &token,
                                    std::chrono::seconds skew);
  monad::IO<void> perform_device_registration(
      DeviceRegistrationRequestConfig config,
      ::data::deviceauth::PollResp *poll_state);
};
} // namespace certctrl