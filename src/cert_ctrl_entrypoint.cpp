#include <boost/json.hpp>

#include "cert_ctrl_entry.hpp"
#include "certctrl_common.hpp"
#include "common_macros.hpp"
#include "util/my_logging.hpp"
#include "version.h"
#include <boost/program_options.hpp>
#if !defined(_WIN32)
#include <unistd.h>
#endif
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <securitybaseapi.h>
#include <windows.h>
#endif

namespace po = boost::program_options;

namespace {

namespace js = boost::json;

struct DefaultPaths {
  fs::path config_dir;
  fs::path runtime_dir;
};

fs::path get_env_path(const char *name) {
  if (const char *value = std::getenv(name); value && *value) {
    return fs::path(value);
  }
  return {};
}

// Resolve default configuration and runtime directory paths with environment
// variable support.
//
// Environment variable precedence (highest to lowest):
// 1. CERTCTRL_CONFIG_DIR + CERTCTRL_RUNTIME_DIR - Direct path overrides
// 2. CERTCTRL_BASE_DIR - Base directory override (appends /config and /runtime)
// 3. Platform-specific defaults with individual overrides
// 4. Pure platform-specific defaults
//
// Platform defaults:
// - Linux: /etc/certctrl (config), /var/lib/certctrl (runtime)
// - macOS: /Library/Application Support/certctrl/{config,runtime}
// - Windows: %PROGRAMDATA%/certctrl/{config,runtime}
DefaultPaths resolve_default_paths() {
  // Check for environment variable overrides first
  fs::path config_override = get_env_path("CERTCTRL_CONFIG_DIR");
  fs::path runtime_override = get_env_path("CERTCTRL_RUNTIME_DIR");

  if (!config_override.empty() && !runtime_override.empty()) {
    return {config_override, runtime_override};
  }

  // Check for base directory override
  fs::path base_override = get_env_path("CERTCTRL_BASE_DIR");
  if (!base_override.empty()) {
    fs::path config_dir =
        config_override.empty() ? (base_override / "config") : config_override;
    fs::path runtime_dir = runtime_override.empty()
                               ? (base_override / "runtime")
                               : runtime_override;
    return {config_dir, runtime_dir};
  }

#ifdef _WIN32
  fs::path program_data = get_env_path("PROGRAMDATA");
  if (program_data.empty()) {
    program_data = fs::path("C:/ProgramData");
  }
  auto base = program_data / "certctrl";
  fs::path config_dir =
      config_override.empty() ? (base / "config") : config_override;
  fs::path runtime_dir =
      runtime_override.empty() ? (base / "runtime") : runtime_override;
  return {config_dir, runtime_dir};
#elif defined(__APPLE__)
  fs::path base("/Library/Application Support/certctrl");
  fs::path config_dir =
      config_override.empty() ? (base / "config") : config_override;
  fs::path runtime_dir =
      runtime_override.empty() ? (base / "runtime") : runtime_override;
  return {config_dir, runtime_dir};
#else
  // Linux/Unix defaults
  fs::path config_dir =
      config_override.empty() ? fs::path("/etc/certctrl") : config_override;
  fs::path runtime_dir = runtime_override.empty()
                             ? fs::path("/var/lib/certctrl")
                             : runtime_override;
  return {config_dir, runtime_dir};
#endif
}

void ensure_directory_exists(const fs::path &dir) {
  std::error_code ec;
  fs::create_directories(dir, ec);
  if (ec && !fs::exists(dir)) {
    throw std::runtime_error(std::string("Failed to create directory '") +
                             dir.string() + "': " + ec.message());
  }
}

void write_json_if_missing(const fs::path &file_path,
                           const js::value &content) {
  if (fs::exists(file_path)) {
    return;
  }
  ensure_directory_exists(file_path.parent_path());
  std::ofstream ofs(file_path);
  if (!ofs) {
    throw std::runtime_error("Unable to write default config file: " +
                             file_path.string());
  }
  ofs << js::serialize(content) << std::endl;
}

bool bootstrap_default_config_dir(const fs::path &config_dir,
                                  const fs::path &runtime_dir) {
  std::error_code ec;
  fs::create_directories(config_dir, ec);
  if (ec && !fs::exists(config_dir)) {
    std::cerr << "Warning: unable to create default config directory '"
              << config_dir << "': " << ec.message() << std::endl;
    return false;
  }

  try {
    js::object application{
      {"auto_apply_config", true},
        {"verbose", "info"},
        {"interval_seconds", 30},
        {"url_base", "https://api.cjj365.cc"},
        {"short_poll", js::object{{"enabled", false},
                                  {"poll_url", js::value(nullptr)},
                                  {"idle_interval_seconds", 30},
                                  {"interval_seconds", 5},
                                  {"jitter_seconds", 1},
                                  {"backoff_seconds", 30},
                                  {"fast_mode_ttl_seconds", 120}}},
        {"update_check_url",
         "https://install.lets-script.com/api/version/check"},
        {"runtime_dir", runtime_dir.string()}};
    write_json_if_missing(config_dir / "application.json", application);

    js::object httpclient{{"threads_num", 2},
                          {"ssl_method", "tlsv12_client"},
                          {"insecure_skip_verify", false},
                          {"verify_paths", js::array{}},
                          {"certificates", js::array{}},
                          {"certificate_files", js::array{}},
                          {"proxy_pool", js::array{}}};
    write_json_if_missing(config_dir / "httpclient_config.json", httpclient);

    js::object ioc{{"threads_num", 1}, {"name", "certctrl-ioc"}};
    write_json_if_missing(config_dir / "ioc_config.json", ioc);

    js::object log{{"level", "info"},
                   {"log_dir", (runtime_dir / "logs").string()},
                   {"log_file", "certctrl.log"},
                   {"rotation_size", 10 * 1024 * 1024}};
    write_json_if_missing(config_dir / "log_config.json", log);

    js::array websocket_allowlist{"content-type", "user-agent",
                    "stripe-signature"};
    js::object websocket{{"enabled", true},
               {"remote_endpoint",
                "wss://api.cjj365.cc/api/websocket"},
               {"webhook_base_url", "https://api.cjj365.cc/hooks"},
               {"verify_tls", true},
               {"request_timeout_seconds", 45},
               {"ping_interval_seconds", 20},
               {"max_concurrent_requests", 12},
               {"max_payload_bytes", 5 * 1024 * 1024},
               {"reconnect_initial_delay_ms", 1000},
               {"reconnect_max_delay_ms", 30000},
               {"reconnect_jitter_ms", 250},
               {"tunnel",
                js::object{{"local_base_url", "http://127.0.0.1:9000"},
                     {"header_allowlist", websocket_allowlist},
                     {"routes", js::array{}}}}};
    write_json_if_missing(config_dir / "websocket_config.json", websocket);
  } catch (const std::exception &ex) {
    std::cerr << "Warning: failed to write default configuration files: "
              << ex.what() << std::endl;
    return false;
  }

  return true;
}

std::optional<fs::path>
find_runtime_dir_override(const std::vector<fs::path> &config_dirs,
                          const std::vector<std::string> &profiles) {
  // Look through resolved config directories (profile-aware) to see if any
  // application*.json sets runtime_dir. This lets a user pin runtime_dir in
  // config instead of env/CLI; the first hit wins.
  std::optional<fs::path> runtime_dir;
  auto apply_file = [&](const fs::path &file) {
    if (!fs::exists(file)) {
      return;
    }
    std::ifstream ifs(file);
    if (!ifs) {
      return;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
    boost::system::error_code ec;
    auto value = js::parse(content, ec);
    if (ec || !value.is_object()) {
      return;
    }
    if (auto *rd = value.as_object().if_contains("runtime_dir")) {
      if (rd->is_string()) {
        runtime_dir = fs::path(std::string(rd->as_string()));
      }
    }
  };

  for (const auto &dir : config_dirs) {
    apply_file(dir / "application.json");
    for (const auto &profile : profiles) {
      apply_file(dir / ("application." + profile + ".json"));
    }
    apply_file(dir / "application.override.json");
  }
  return runtime_dir;
}

void add_unique_path(std::vector<fs::path> &paths, const fs::path &candidate) {
  if (candidate.empty()) {
    return;
  }
  if (std::find(paths.begin(), paths.end(), candidate) == paths.end()) {
    paths.push_back(candidate);
  }
}

bool is_running_with_elevated_privileges() {
#if defined(_WIN32)
  BOOL is_admin = FALSE;
  SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
  PSID admin_group = nullptr;

  if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &admin_group)) {
    CheckTokenMembership(nullptr, admin_group, &is_admin);
    FreeSid(admin_group);
  }

  return is_admin == TRUE;
#else
  return ::geteuid() == 0;
#endif
}

} // namespace

int RunCertCtrlApplication(int argc, char *argv[]) {
  // Early version check - handle version requests before any initialization
  for (int i = 1; i < argc; ++i) {
    std::string arg(argv[i]);
    if (arg == "-v" || arg == "--version" || arg == "version" || arg == "v") {
      std::cout << MYAPP_VERSION << std::endl;
      return EXIT_SUCCESS;
    }
  }

  // Fail fast on common flag typos. We keep allow_unregistered() so subcommands
  // can parse their own flags later, but we don't want global typos to be
  // silently ignored.
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i] ? std::string_view(argv[i])
                                         : std::string_view{};
    if (arg == "--base-url" || arg.rfind("--base-url=", 0) == 0) {
      std::cerr << "Unknown option '--base-url'. Did you mean '--url-base'?"
                << std::endl;
      return EXIT_FAILURE;
    }
  }

  try {
    po::variables_map vm;
    po::options_description generic_desc("A cert-ctrl tool");

    certctrl::CliParams cli_params;
    std::vector<std::string> config_dirs_args;

    generic_desc.add_options() //
        ("config-dirs,c",
         po::value<std::vector<std::string>>(&config_dirs_args)
             ->multitoken()
             ->composing(),
         "paths of the configuration directories.") //
        ("profiles",
         po::value<std::vector<std::string>>(&cli_params.profiles)
             ->default_value(std::vector<std::string>{}, "")
             ->notifier([&](const std::vector<std::string> &profiles) mutable {
               if (profiles.empty()) {
                 cli_params.profiles.push_back("default");
               }
             }),
         "profiles to use from the configuration file.") //
        ("verbose",
         po::value<std::string>(&cli_params.verbose)->default_value("info"),
         "verbosity level, like info, trace, vvvv.") //
        ("silent", po::bool_switch(&cli_params.silent)->default_value(false),
         "suppress all output.") //
        ("offset", po::value<size_t>(&cli_params.offset)->default_value(0),
         "offset") //
        ("limit", po::value<size_t>(&cli_params.limit)->default_value(10),
         "limit") //
        ("url-base",
         po::value<std::string>()->value_name("URL")->notifier(
             [&](const std::string &value) {
               cli_params.url_base_override = value;
             }),
         "override the API base URL for this run without persisting") //
        ("keep-running",
         po::bool_switch(&cli_params.keep_running)->default_value(false),
         "keep running after processing the command.") //
        ("no-root",
         po::bool_switch(&cli_params.allow_non_root)->default_value(false),
         "suppress warning when running without root privileges.") //
        ("yes,y",
         po::bool_switch(&cli_params.confirm_update)->default_value(false),
         "automatically confirm update without prompting (for update "
         "subcommand).") //
        ("help,h", "Print help");

    po::options_description hidden_desc("Hidden options");
    hidden_desc.add_options() //
        ("positionals",
         po::value<std::vector<std::string>>()->default_value({}, ""),
         "all positional arguments");

    po::options_description cmdline_options("Allowed options");
    cmdline_options.add(generic_desc).add(hidden_desc);

    po::positional_options_description p;
    p.add("positionals", -1); // command will get all positional arguments.

    po::parsed_options parsed = po::command_line_parser(argc, argv)
                                    .options(cmdline_options)
                                    .positional(p)
                                    .allow_unregistered()
                                    .run();
    po::store(parsed, vm);
    po::notify(vm);

    if (!config_dirs_args.empty()) {
      cli_params.config_dirs.clear();
      for (const auto &dir_str : config_dirs_args) {
        fs::path config_dir(dir_str);
        if (!fs::exists(config_dir)) {
          throw std::runtime_error("Config directory does not exist: " +
                                   config_dir.string());
        }
        cli_params.config_dirs.push_back(std::move(config_dir));
      }
    }

    std::vector<std::string> positionals =
        vm["positionals"].as<std::vector<std::string>>();
    if (positionals.size() > 0) {
      cli_params.subcmd = positionals[0];
    }

    std::vector<std::string> unrecognized = po::collect_unrecognized(
        parsed.options, po::collect_unrecognized_mode::include_positional);

    certctrl::normalize_cli_subcommand(cli_params.subcmd, positionals,
                                       unrecognized);

    auto showUsage = [&]() {
      std::cerr << generic_desc << std::endl;
      std::cerr << "Subcommands:" << std::endl;
      std::cerr << "  login          Login the device." << std::endl;
      // std::cerr << "  conf           Configure the device." << std::endl;
      std::cerr << "  install-config Manage install configuration "
                   "(pull/apply/show/clear-cache)."
                << std::endl
                << "  certificates   Inspect staged certificate materials."
                << std::endl
                << "  ca             Inspect cached certificate authorities."
                << std::endl
                << "  info           Show device and environment diagnostics."
                << std::endl
                << "  device         API key automation actions (assign-cert)."
                << std::endl
                << std::endl;
      std::cerr << "Default behavior:" << std::endl;
      std::cerr << "  No subcommand -> agent update check followed by a device "
                   "updates poll."
                << std::endl
                << std::endl;
    };

    if (vm.count("help")) {
      showUsage();
      return 0;
    }

    if (vm.count("version")) {
      std::cout << MYAPP_VERSION << std::endl;
      return 0;
    }

    if (!cli_params.allow_non_root && !is_running_with_elevated_privileges()) {
#if defined(_WIN32)
      const char *required_privilege = "administrator";
      const char *rerun_instruction =
          "For full functionality, re-run as administrator";
#else
      const char *required_privilege = "root";
      const char *rerun_instruction = "For full functionality, re-run as root";
#endif
      std::cerr << "Warning: cert-ctrl is not running with "
                << required_privilege << " privileges. " << rerun_instruction
                << " or pass --no-root to acknowledge running without elevated "
                   "privileges."
                << std::endl;
      return EXIT_FAILURE;
    }

    const DefaultPaths defaults = resolve_default_paths();
    const bool default_config_available =
        bootstrap_default_config_dir(defaults.config_dir, defaults.runtime_dir);

    std::vector<fs::path> ordered_config_dirs;
    if (default_config_available && fs::exists(defaults.config_dir)) {
      add_unique_path(ordered_config_dirs, defaults.config_dir);
    }

    for (const auto &dir : cli_params.config_dirs) {
      add_unique_path(ordered_config_dirs, dir);
    }

    if (ordered_config_dirs.empty()) {
      std::cerr << "No configuration directories found. Provide --config-dirs"
                << " or ensure the default directory '" << defaults.config_dir
                << "' is accessible." << std::endl;
      return EXIT_FAILURE;
    }

    auto runtime_override =
        find_runtime_dir_override(ordered_config_dirs, cli_params.profiles);
    fs::path resolved_runtime_dir =
        runtime_override.value_or(defaults.runtime_dir);

    try {
      ensure_directory_exists(resolved_runtime_dir);
      ensure_directory_exists(resolved_runtime_dir / "logs");
    } catch (const std::exception &ex) {
      std::cerr << "Failed to prepare runtime directory '"
                << resolved_runtime_dir << "': " << ex.what() << std::endl;
      return EXIT_FAILURE;
    }

    add_unique_path(ordered_config_dirs, resolved_runtime_dir);
    cli_params.config_dirs = ordered_config_dirs;
    cli_params.runtime_dir = resolved_runtime_dir;

    std::map<std::string, std::string> cli_overrides;
    if (cli_params.url_base_override &&
        !cli_params.url_base_override->empty()) {
      cli_overrides.emplace("url_base", *cli_params.url_base_override);
      std::cerr << "Using runtime URL base override: "
                << *cli_params.url_base_override << std::endl;
    }

    static cjj365::ConfigSources config_sources(
        cli_params.config_dirs, cli_params.profiles, std::move(cli_overrides));
    {
      auto log_config_result = config_sources.json_content("log_config");
      if (log_config_result.is_err()) {
        std::cerr << "Failed to load log_config: " << log_config_result.error()
                  << std::endl;
        return EXIT_FAILURE;
      }
      DEBUG_PRINT("log config: " << log_config_result.value());
      cjj365::LoggingConfig logging_config =
          json::value_to<cjj365::LoggingConfig>(log_config_result.value());

      init_my_log(logging_config);
    }

    // reference variable be here.
    static certctrl::CliCtx cli_ctx(std::move(vm), std::move(positionals),
                                    std::move(unrecognized),
                                    std::move(cli_params));

    if (!cli_ctx.is_specified_by_user("verbose")) {
      auto certctrl_config_result = config_sources.json_content("application");
      auto certctrl_config = json::value_to<certctrl::CertctrlConfig>(
          certctrl_config_result.value());
      cli_ctx.params.verbose = certctrl_config.verbose;
    }

    // clang-format off
    // gdb --args ./build/apps/certctrl/certctrl_debug -c  apps/certctrl/config_dir account list --verbose trace
    // run
    // bt
    // mkdir -p ~/.config/gdb
    // echo "add-auto-load-safe-path /home/jianglibo/bb/build/" >> ~/.config/gdb/gdbinit
    // clang-format on
    // Set up async signal handling
    {
      using namespace certctrl;
      using namespace certctrl::type_tags;

      AppKind sk = AppKind::One;

      if (sk == AppKind::One) {
        launch<OneTag>(config_sources, cli_ctx);
      } else {
        launch<TwoTag>(config_sources, cli_ctx);
      }
    }
    return EXIT_SUCCESS;
  } catch (const std::exception &e) {
    std::cerr << "error catched on main: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
}

#ifdef _WIN32
extern bool run_windows_service_if_available(int argc, char *argv[]);
#endif

int main(int argc, char *argv[]) {
#ifdef _WIN32
  if (run_windows_service_if_available(argc, argv)) {
    return 0;
  }
#endif
  return RunCertCtrlApplication(argc, argv);
}
