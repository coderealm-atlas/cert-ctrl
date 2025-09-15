#include <boost/json/value.hpp>

#include "certctrl_common.hpp"
#include "common_macros.hpp"
#include "cert_ctrl_entry.hpp"
#include "util/my_logging.hpp"
#include <boost/program_options.hpp>

namespace po = boost::program_options;

int main(int argc, char *argv[]) {
  try {
    po::variables_map vm;
    po::options_description generic_desc("A cert-ctrl tool");

    certctrl::CliParams cli_params;

    generic_desc.add_options() //
        ("config-dirs,c",
         po::value<std::vector<fs::path>>(&cli_params.config_dirs)
             ->default_value(std::vector<fs::path>{}, "")
             ->notifier([&](const std::vector<fs::path> &config_dirs) mutable {
               for (const auto &config_dir : config_dirs) {
                 if (!fs::exists(config_dir)) {
                   throw std::runtime_error("Config directory does not exist.");
                 }
               }
             }),
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
        ("keep-running",
         po::bool_switch(&cli_params.keep_running)->default_value(false),
         "keep running after processing the command.") //
        ("help,h", "Print help");

    po::options_description hidden_desc("Hidden options");
    hidden_desc.add_options() //
        ("positionals",
         po::value<std::vector<std::string>>()->default_value({}, ""),
         "all positional arguments");

    certctrl::CommonOptions common_options;
    po::options_description common_desc("common options");
    common_desc.add_options() //
        ("verbose",
         po::value<std::string>(&common_options.verbose)->default_value("info"),
         "verbosity level, like info, trace, vvvv.") //
        ("silent",
         po::bool_switch(&common_options.silent)->default_value(false),
         "suppress all output.") //
        ("offset", po::value<size_t>(&common_options.offset)->default_value(0),
         "offset") //
        ("limit", po::value<size_t>(&common_options.limit)->default_value(10),
         "limit"); //

    po::options_description cmdline_options("Allowed options");
    cmdline_options.add(generic_desc).add(common_desc).add(hidden_desc);

    po::positional_options_description p;
    p.add("positionals", -1); // command will get all positional arguments.

    po::parsed_options parsed = po::command_line_parser(argc, argv)
                                    .options(cmdline_options)
                                    .positional(p)
                                    .allow_unregistered()
                                    .run();
    po::store(parsed, vm);
    po::notify(vm);
    std::vector<std::string> positionals =
        vm["positionals"].as<std::vector<std::string>>();
    if (positionals.size() > 0) {
      cli_params.subcmd = positionals[0];
    }

    std::vector<std::string> unrecognized = po::collect_unrecognized(
        parsed.options, po::collect_unrecognized_mode::include_positional);

    auto showUsage = [&]() {
      std::cerr << generic_desc << std::endl;
      std::cerr << "Subcommands:" << std::endl;
      std::cerr << "  login          Login the device." << std::endl;
      std::cerr << "  conf           Configure the device." << std::endl
                << std::endl;
      std::cerr << common_desc << std::endl;
    };

    if (cli_params.subcmd.empty() && !cli_params.keep_running) {
      showUsage();
      return EXIT_SUCCESS;
    }
    static cjj365::ConfigSources config_sources(cli_params.config_dirs,
                                                cli_params.profiles);
    auto log_config_result = config_sources.json_content("log_config");
    if (log_config_result.is_err()) {
      std::cerr << "Failed to load log_config: " << log_config_result.error()
                << std::endl;
      return EXIT_FAILURE;
    }
    cjj365::LoggingConfig logging_config =
        json::value_to<cjj365::LoggingConfig>(log_config_result.value());

    init_my_log(logging_config);

    // reference variable be here.
    static certctrl::CliCtx cli_ctx(
        std::move(vm), std::move(common_options), std::move(positionals),
        std::move(unrecognized), std::move(cli_params));

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

      AppKind sk =  AppKind::One;

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
