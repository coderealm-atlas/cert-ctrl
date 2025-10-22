#include "handlers/install_config_handler.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <filesystem>

namespace certctrl {

InstallConfigHandler::InstallConfigHandler(
    cjj365::ConfigSources &config_sources, certctrl::CliCtx &cli_ctx,
    customio::ConsoleOutput &output,
    client_async::HttpClientManager &http_client,
    certctrl::ICertctrlConfigProvider &config_provider)
    : cli_ctx_(cli_ctx), output_(output), config_sources_(config_sources),
      http_client_(http_client), config_provider_(config_provider) {
  auto runtime_dir = config_sources_.paths_.empty()
                          ? std::filesystem::path{}
                          : config_sources_.paths_.back();
  install_config_manager_ = std::make_shared<InstallConfigManager>(
      runtime_dir, config_provider_, output_, &http_client_);
}

std::string InstallConfigHandler::command() const {
  return "install-config";
}

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

monad::IO<void> InstallConfigHandler::show_usage(
    const std::string &error) const {
  if (!error.empty()) {
    output_.logger().error() << error << std::endl;
  }
  output_.logger().info()
      << "Usage: cert-ctrl install-config <action> [options]\n"
      << "  pull          Fetch the latest install-config and optionally apply\n"
      << "    --no-apply             Stage without applying copy/import actions\n"
      << "    --cert-id <id>         Apply copy actions for a single certificate\n"
      << "    --ca-id <id>           Apply copy/import for a single CA\n"
      << "    --skip-copy            Skip copy actions when applying\n"
      << "    --skip-import          Skip CA import actions when applying\n"
      << "  apply         Apply the staged install-config (optionally filtered)\n"
      << "    --cert-id <id>         Apply copy actions for a single certificate\n"
      << "    --ca-id <id>           Apply copy/import for a single CA\n"
      << "    --skip-copy            Skip copy actions\n"
      << "    --skip-import          Skip CA import actions\n"
      << "  show          Display staged version information\n"
      << "  clear-cache   Drop cached install-config data\n" << std::endl;
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
  desc.add_options()
      ("no-apply", po::bool_switch(&opts.no_apply), "Do not apply actions")
      ("skip-copy", po::bool_switch(&opts.skip_copy), "Skip copy actions")
      ("skip-import", po::bool_switch(&opts.skip_import),
       "Skip CA import actions")
      ("cert-id", po::value<std::int64_t>(),
       "Apply only copy actions for certificate ID")
      ("ca-id", po::value<std::int64_t>(),
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
    output_.logger().error() << "Failed to parse options: " << ex.what()
                             << std::endl;
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

  return install_config_manager_
      ->ensure_config_version(std::nullopt, std::nullopt)
      .then([this, options](std::shared_ptr<const dto::DeviceInstallConfigDto>
                                config_ptr) mutable {
        if (!config_ptr) {
          output_.logger().warning()
              << "install-config fetch returned no payload" << std::endl;
          return monad::IO<void>::pure();
        }

        output_.logger().info()
            << "Fetched install-config version " << config_ptr->version
            << std::endl;

        if (options.no_apply) {
          output_.logger().info()
              << "Staged install-config without applying actions." << std::endl;
          return monad::IO<void>::pure();
        }

        return apply_copy_and_import(config_ptr, options);
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
    output_.logger().info() << "No staged install-config available." << std::endl;
    return ReturnIO::pure();
  }

  output_.logger().info()
  << "Staged install-config version: " << config_ptr->version
  << " (installs=" << config_ptr->installs.size() << ")"
  << std::endl;
  return ReturnIO::pure();
}

monad::IO<void> InstallConfigHandler::handle_clear_cache() {
  install_config_manager_->clear_cache();
  output_.logger().info()
      << "Cleared cached install-config state (memory only)." << std::endl;
  return monad::IO<void>::pure();
}

monad::IO<void> InstallConfigHandler::apply_copy_and_import(
    std::shared_ptr<const dto::DeviceInstallConfigDto> config,
    const PullOptions &options) {
  using ReturnIO = monad::IO<void>;

  auto select_copy = [this, config, options]() -> monad::IO<void> {
    if (options.skip_copy) {
      return ReturnIO::pure();
    }

    if (options.cert_id && options.ca_id) {
      auto copy_cert = install_config_manager_->apply_copy_actions(
          *config, std::optional<std::string>("cert"), options.cert_id);
  return copy_cert.then([this, config, options]() {
        return install_config_manager_->apply_copy_actions(
            *config, std::optional<std::string>("ca"), options.ca_id);
      });
    }

    if (options.cert_id) {
      return install_config_manager_->apply_copy_actions(
          *config, std::optional<std::string>("cert"), options.cert_id);
    }

    if (options.ca_id) {
      return install_config_manager_->apply_copy_actions(
          *config, std::optional<std::string>("ca"), options.ca_id);
    }

    return install_config_manager_->apply_copy_actions(
        *config, std::nullopt, std::nullopt);
  };

  auto select_import = [this, config, options]() -> monad::IO<void> {
    if (options.skip_import || options.cert_id) {
      return ReturnIO::pure();
    }

    std::optional<std::string> target_type;
    std::optional<std::int64_t> target_id;
    if (options.ca_id) {
      target_type = std::string("ca");
      target_id = options.ca_id;
    }

    return install_config_manager_->apply_import_ca_actions(
        *config, target_type, target_id);
  };

  return select_copy().then([select_import]() { return select_import(); })
      .then([this]() {
        output_.logger().info()
            << "install-config actions completed successfully." << std::endl;
        return monad::IO<void>::pure();
      });
}

} // namespace certctrl
