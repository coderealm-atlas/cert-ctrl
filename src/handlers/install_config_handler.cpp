#include "handlers/install_config_handler.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <filesystem>

#include "my_error_codes.hpp"
#include "result_monad.hpp"

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

monad::IO<void> InstallConfigHandler::start() {
  using ReturnIO = monad::IO<void>;

  if (cli_ctx_.positionals.size() < 2) {
    return show_usage();
  }

  const std::string action = cli_ctx_.positionals[1];

  if (action == "pull") {
    return handle_pull();
  }
  if (action == "apply") {
    return handle_apply();
  }
  if (action == "show") {
    return handle_show();
  }
  if (action == "clear-cache") {
    return handle_clear_cache();
  }

  return show_usage(fmt::format("Unknown action '{}'.", action));
}

monad::IO<void> InstallConfigHandler::show_usage() const {
  return show_usage("");
}

monad::IO<void>
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
  return monad::IO<void>::pure();
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

monad::IO<void> InstallConfigHandler::handle_pull() {
  using ReturnIO = monad::IO<void>;
  auto options = parse_pull_options("pull");

  output_.logger().info() << "Fetching latest install-config from API"
                          << std::endl;
  auto self = shared_from_this();
  return install_config_manager_
      ->ensure_config_version(std::nullopt, std::nullopt)
      .then([self, options](std::shared_ptr<const dto::DeviceInstallConfigDto>
                                config_ptr) mutable {
        if (!config_ptr) {
          self->output_.logger().warning()
              << "install-config fetch returned no payload" << std::endl;
          return monad::IO<void>::pure();
        }

        self->output_.logger().info() << "Fetched install-config version "
                                      << config_ptr->version << std::endl;

        if (options.no_apply) {
          self->output_.logger().info()
              << "Staged install-config without applying actions." << std::endl;
          return monad::IO<void>::pure();
        }

        return self->apply_copy_and_import(config_ptr, options);
      });
}

monad::IO<void> InstallConfigHandler::handle_apply() {
  using ReturnIO = monad::IO<void>;
  auto options = parse_pull_options("apply");

  auto config_ptr = install_config_manager_->cached_config_snapshot();
  if (!config_ptr) {
    output_.logger().warning()
        << "No staged install-config found; fetch before applying."
        << std::endl;
    return ReturnIO::pure();
  }

  output_.logger().info() << "Applying staged install-config version "
                          << config_ptr->version << std::endl;

  return apply_copy_and_import(config_ptr, options);
}

monad::IO<void> InstallConfigHandler::handle_show() {
  using ReturnIO = monad::IO<void>;
  auto config_ptr = install_config_manager_->cached_config_snapshot();
  if (!config_ptr) {
    std::cerr << "No staged install-config available." << std::endl;
    return ReturnIO::pure();
  }

  std::cerr << "Staged install-config version: " << config_ptr->version
            << " (installs=" << config_ptr->installs.size() << ")" << std::endl;
  return ReturnIO::pure();
}

monad::IO<void> InstallConfigHandler::handle_clear_cache() {
  install_config_manager_->clear_cache();
  std::cerr << "Cleared cached install-config state (memory only)."
            << std::endl;
  return monad::IO<void>::pure();
}

monad::IO<void> InstallConfigHandler::apply_copy_and_import(
    std::shared_ptr<const dto::DeviceInstallConfigDto> config,
    const PullOptions &options) {
  using ReturnIO = monad::IO<void>;

  active_config_ = std::move(config);
  active_options_ = options;
  auto self = shared_from_this();

  return run_copy_stage()
      .then([self]() { return self->run_import_stage(); })
      .then([self]() {
        self->output_.logger().info()
            << "install-config actions completed successfully." << std::endl;
        self->clear_active_context();
        return monad::IO<void>::pure();
      })
      .catch_then([self](monad::Error err) -> ReturnIO {
        BOOST_LOG_SEV(app_logger(), trivial::error)
            << "apply_copy_and_import encountered error code=" << err.code
            << " status=" << err.response_status << " what=" << err.what;
        self->clear_active_context();
        return ReturnIO::fail(std::move(err));
      });
}

monad::IO<void> InstallConfigHandler::run_copy_stage() {
  using ReturnIO = monad::IO<void>;
  if (!active_config_ || !active_options_) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "copy stage invoked without active context"));
  }

  const auto &options = *active_options_;
  BOOST_LOG_SEV(app_logger(), trivial::trace)
      << "apply_copy_and_import select_copy start cert_id="
      << (options.cert_id ? std::to_string(*options.cert_id) : "<none>")
      << " ca_id="
      << (options.ca_id ? std::to_string(*options.ca_id) : "<none>")
      << " skip_copy=" << (options.skip_copy ? "true" : "false");

  if (options.skip_copy) {
    return ReturnIO::pure();
  }

  const auto &config = *active_config_;

  if (options.cert_id && options.ca_id) {
    auto self = shared_from_this();
    return install_config_manager_
        ->apply_copy_actions(config, std::optional<std::string>("cert"),
                             options.cert_id)
        .then([self]() {
          const auto &config_inner = *self->active_config_;
          const auto &options_inner = *self->active_options_;
          return self->install_config_manager_->apply_copy_actions(
              config_inner, std::optional<std::string>("ca"),
              options_inner.ca_id);
        });
  }

  if (options.cert_id) {
    return install_config_manager_->apply_copy_actions(
        config, std::optional<std::string>("cert"), options.cert_id);
  }

  if (options.ca_id) {
    return install_config_manager_->apply_copy_actions(
        config, std::optional<std::string>("ca"), options.ca_id);
  }

  return install_config_manager_->apply_copy_actions(config, std::nullopt,
                                                     std::nullopt);
}

monad::IO<void> InstallConfigHandler::run_import_stage() {
  DEBUG_PRINT("NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN");
  using ReturnIO = monad::IO<void>;
  if (!active_config_ || !active_options_) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "import stage invoked without active context"));
  }

  const auto &options = *active_options_;
  DEBUG_PRINT("InstallConfigHandler::apply_copy_and_import - select_import");
  if (options.skip_import || options.cert_id) {
    BOOST_LOG_SEV(app_logger(), trivial::trace)
        << "Skipping import_ca actions due to options";
    return ReturnIO::pure();
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

  return install_config_manager_->apply_import_ca_actions(
      *active_config_, target_type, target_id);
}

void InstallConfigHandler::clear_active_context() {
  active_config_.reset();
  active_options_.reset();
}

} // namespace certctrl
