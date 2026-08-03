#include "handlers/install_config_handler.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <chrono>

#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "util/my_logging.hpp"

namespace certctrl {

InstallConfigHandler::InstallConfigHandler(
    cjj365::ConfigSources &config_sources,        //
    certctrl::CliCtx &cli_ctx,                    //
    customio::ConsoleOutput &output,              //
    client_async::HttpClientManager &http_client, //
    std::unique_ptr<InstallConfigManager> install_config_manager,
    certctrl::ICertctrlConfigProvider &config_provider)
    : cli_ctx_(cli_ctx), output_(output), config_sources_(config_sources),
      http_client_(http_client),
      install_config_manager_(std::move(install_config_manager)),
      config_provider_(config_provider) {
  // auto runtime_dir = config_sources_.paths_.empty()
  //                        ? std::filesystem::path{}
  //                        : config_sources_.paths_.back();
  // install_config_manager_ = std::make_shared<InstallConfigManager>(
  //     runtime_dir, config_provider_, output_, &http_client_);
}

std::string InstallConfigHandler::command() const { return "install-config"; }

boost::asio::awaitable<monad::MyResult<void>>
InstallConfigHandler::start_awaitable() {
  if (cli_ctx_.positionals.size() < 2) {
    co_return show_usage();
  }

  const std::string action = cli_ctx_.positionals[1];

  output_.logger().info()
      << "CLI install-config command detected; invalidating cached state"
      << std::endl;
  install_config_manager_->invalidate_all_caches();

  if (action == "pull") {
    co_return co_await handle_pull_awaitable();
  }
  if (action == "apply") {
    co_return co_await handle_apply_awaitable();
  }
  if (action == "show") {
    co_return handle_show();
  }
  if (action == "clear-cache") {
    co_return handle_clear_cache();
  }

  co_return show_usage(fmt::format("Unknown action '{}'.", action));
}

monad::MyResult<void> InstallConfigHandler::show_usage() const {
  return show_usage("");
}

monad::MyResult<void>
InstallConfigHandler::show_usage(const std::string &error) const {
  if (!error.empty()) {
    output_.logger().error() << error << std::endl;
  }
  output_.logger().info()
      << "Usage: cert-ctrl install-config <action> [options]\n"
      << "  pull          Fetch the latest install-config and optionally "
         "apply\n"
      << "    --no-apply             Stage without applying copy/import "
         "actions\n"
      << "    --cert-id <id>         Apply copy actions for a single "
         "certificate\n"
      << "    --ca-id <id>           Apply copy/import for a single CA\n"
      << "    --skip-copy            Skip copy actions when applying\n"
      << "    --skip-import          Skip CA import actions when applying\n"
      << "  apply         Apply the staged install-config (optionally "
         "filtered)\n"
      << "    --cert-id <id>         Apply copy actions for a single "
         "certificate\n"
      << "    --ca-id <id>           Apply copy/import for a single CA\n"
      << "    --skip-copy            Skip copy actions\n"
      << "    --skip-import          Skip CA import actions\n"
      << "  show          Display staged version information\n"
      << "  clear-cache   Drop cached install-config data\n"
      << std::endl;
  return monad::MyResult<void>::Ok();
}

std::optional<std::int64_t> InstallConfigHandler::get_optional_id(
    const boost::program_options::variables_map &vm, const char *name) {
  if (vm.count(name)) {
    return vm[name].as<std::int64_t>();
  }
  return std::nullopt;
}

InstallConfigHandler::PullOptions
InstallConfigHandler::parse_pull_options(const std::string &action) const {
  namespace po = boost::program_options;
  PullOptions opts;

  po::options_description desc("install-config options");
  desc.add_options()("no-apply", po::bool_switch(&opts.no_apply),
                     "Do not apply actions")(
      "skip-copy", po::bool_switch(&opts.skip_copy), "Skip copy actions")(
      "skip-import", po::bool_switch(&opts.skip_import),
      "Skip CA import actions")("cert-id", po::value<std::int64_t>(),
                                "Apply only copy actions for certificate ID")(
      "ca-id", po::value<std::int64_t>(),
      "Apply only copy/import actions for CA ID");

  std::vector<std::string> args = cli_ctx_.unrecognized;
  auto remove_prefix = [&](const std::string &token) {
    auto it = std::find(args.begin(), args.end(), token);
    if (it != args.end()) {
      args.erase(it);
    }
  };
  remove_prefix(command());
  remove_prefix(action);

  po::variables_map vm;
  try {
    po::store(po::command_line_parser(args).options(desc).run(), vm);
    po::notify(vm);
  } catch (const std::exception &ex) {
    output_.logger().error()
        << "Failed to parse options: " << ex.what() << std::endl;
  }

  opts.cert_id = get_optional_id(vm, "cert-id");
  opts.ca_id = get_optional_id(vm, "ca-id");
  return opts;
}

boost::asio::awaitable<monad::MyResult<void>>
InstallConfigHandler::handle_pull_awaitable() {
  auto options = parse_pull_options("pull");

  output_.logger().info() << "Fetching latest install-config from API"
                          << std::endl;
  auto config_result = co_await install_config_manager_->ensure_config_version(
      std::nullopt, std::nullopt);
  if (config_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(config_result).error());
  }
  auto config = std::move(config_result).value();
  if (!config) {
    output_.logger().warning()
        << "install-config fetch returned no payload" << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  output_.logger().info() << "Fetched install-config version "
                          << config->version << std::endl;
  if (options.no_apply) {
    output_.logger().info()
        << "Staged install-config without applying actions." << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  auto rearm_result =
      co_await install_config_manager_->rearm_local_install_update_window();
  if (rearm_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(rearm_result).error());
  }
  auto persist_result =
      co_await install_config_manager_->approve_and_persist_after_update_script(
          *config);
  if (persist_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(persist_result).error());
  }
  co_return co_await apply_copy_and_import_awaitable(std::move(config),
                                                     options);
}

boost::asio::awaitable<monad::MyResult<void>>
InstallConfigHandler::handle_apply_awaitable() {
  auto options = parse_pull_options("apply");

  output_.logger().info() << "Fetching latest install-config before apply"
                          << std::endl;

  auto config_result = co_await install_config_manager_->ensure_config_version(
      std::nullopt, std::nullopt);
  if (config_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(config_result).error());
  }
  auto config = std::move(config_result).value();
  if (!config) {
    output_.logger().warning()
        << "install-config fetch returned no payload" << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  output_.logger().info() << "Applying install-config version "
                          << config->version << std::endl;
  auto rearm_result =
      co_await install_config_manager_->rearm_local_install_update_window();
  if (rearm_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(rearm_result).error());
  }
  auto persist_result =
      co_await install_config_manager_->approve_and_persist_after_update_script(
          *config);
  if (persist_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(persist_result).error());
  }
  co_return co_await apply_copy_and_import_awaitable(std::move(config),
                                                     options);
}

monad::MyResult<void> InstallConfigHandler::handle_show() {
  auto config_ptr = install_config_manager_->cached_config_snapshot();
  if (!config_ptr) {
    std::cerr << "No staged install-config available." << std::endl;
    return monad::MyResult<void>::Ok();
  }

  std::cerr << "Staged install-config version: " << config_ptr->version
            << " (installs=" << config_ptr->installs.size() << ")" << std::endl;
  return monad::MyResult<void>::Ok();
}

monad::MyResult<void> InstallConfigHandler::handle_clear_cache() {
  install_config_manager_->clear_cache();
  std::cerr << "Cleared cached install-config state (disk and memory)."
            << std::endl;
  return monad::MyResult<void>::Ok();
}

boost::asio::awaitable<monad::MyResult<void>>
InstallConfigHandler::apply_copy_and_import_awaitable(
    std::shared_ptr<const dto::DeviceInstallConfigDto> config,
    const PullOptions &options) {
  auto log_error = [](const monad::Error &error) {
    BOOST_LOG_SEV(app_logger(), trivial::error)
        << "apply_copy_and_import encountered error code=" << error.code
        << " status=" << error.response_status << " what=" << error.what;
  };

  auto copy_result = co_await run_copy_stage_awaitable(*config, options);
  if (copy_result.is_err()) {
    log_error(copy_result.error());
    co_return copy_result;
  }
  auto import_result = co_await run_import_stage_awaitable(*config, options);
  if (import_result.is_err()) {
    log_error(import_result.error());
    co_return import_result;
  }

  ::data::DeviceUpdateSignal synthetic_signal{};
  synthetic_signal.type = "install.updated";
  synthetic_signal.ts_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();
  auto script_result = co_await install_config_manager_
                           ->maybe_run_after_update_script_for_signal(
                               *config, synthetic_signal,
                               /*bypass_auto_apply_config_gate=*/true);
  if (script_result.is_err()) {
    log_error(script_result.error());
    co_return script_result;
  }

  output_.logger().info() << "install-config actions completed successfully."
                          << std::endl;
  co_return monad::MyResult<void>::Ok();
}

boost::asio::awaitable<monad::MyResult<void>>
InstallConfigHandler::run_copy_stage_awaitable(
    const dto::DeviceInstallConfigDto &config, const PullOptions &options) {
  BOOST_LOG_SEV(app_logger(), trivial::trace)
      << "apply_copy_and_import select_copy start cert_id="
      << (options.cert_id ? std::to_string(*options.cert_id) : "<none>")
      << " ca_id="
      << (options.ca_id ? std::to_string(*options.ca_id) : "<none>")
      << " skip_copy=" << (options.skip_copy ? "true" : "false");

  if (options.skip_copy) {
    co_return monad::MyResult<void>::Ok();
  }

  if (options.cert_id && options.ca_id) {
    auto cert_result = co_await install_config_manager_->apply_copy_actions(
        config, std::optional<std::string>("cert"), options.cert_id);
    if (cert_result.is_err()) {
      co_return cert_result;
    }
    co_return co_await install_config_manager_->apply_copy_actions(
        config, std::optional<std::string>("ca"), options.ca_id);
  }

  if (options.cert_id) {
    co_return co_await install_config_manager_->apply_copy_actions(
        config, std::optional<std::string>("cert"), options.cert_id);
  }

  if (options.ca_id) {
    co_return co_await install_config_manager_->apply_copy_actions(
        config, std::optional<std::string>("ca"), options.ca_id);
  }

  co_return co_await install_config_manager_->apply_copy_actions(
      config, std::nullopt, std::nullopt);
}

boost::asio::awaitable<monad::MyResult<void>>
InstallConfigHandler::run_import_stage_awaitable(
    const dto::DeviceInstallConfigDto &config, const PullOptions &options) {
  DEBUG_PRINT("InstallConfigHandler::apply_copy_and_import - select_import");
  if (options.skip_import || options.cert_id) {
    BOOST_LOG_SEV(app_logger(), trivial::trace)
        << "Skipping import_ca actions due to options";
    co_return monad::MyResult<void>::Ok();
  }

  std::optional<std::string> target_type;
  std::optional<std::int64_t> target_id;
  if (options.ca_id) {
    target_type = std::string("ca");
    target_id = options.ca_id;
  }

  BOOST_LOG_SEV(app_logger(), trivial::trace)
      << "apply_copy_and_import select_import start target_type="
      << (target_type ? *target_type : std::string("<none>"))
      << " target_id=" << (target_id ? std::to_string(*target_id) : "<none>")
      << " skip_import=" << (options.skip_import ? "true" : "false");
  DEBUG_PRINT("InstallConfigHandler::apply_copy_and_import - calling "
              "apply_import_ca_actions");

  co_return co_await install_config_manager_->apply_import_ca_actions(
      config, target_type, target_id);
}

} // namespace certctrl
