#include "handlers/conf_handler.hpp"
#include <format>

namespace certctrl {

using VoidPureIO = monad::IO<void>;

VoidPureIO ConfHandler::start() {
  if (auto setv_r = cli_ctx_.get_set_kv(); setv_r.is_ok()) {
    auto [key, value] = setv_r.value();
    if (key == "auto_fetch_config") {
      bool bool_value = parse_bool(value);
      if (bool_value != certctrl_config_provider_.get().auto_fetch_config) {
        certctrl_config_provider_.get().auto_fetch_config = bool_value;
        certctrl_config_provider_.save({{"auto_fetch_config", bool_value}});
      }
      output_hub_.info() << "Set auto_fetch_config to "
                         << (bool_value ? "true" : "false") << std::endl;
    } else if (key == "verbose") {
      certctrl_config_provider_.get().verbose = value;
      certctrl_config_provider_.save({{"verbose", value}});
      output_hub_.info() << "Set verbose to " << value << std::endl;
    } else {
      std::string msg =
          std::format("Unknown configuration key: {}, "
                      "supported keys are: auto_fetch_config, verbose",
                      key);
      return show_usage(msg);
    }
  } else if (auto getv_r = cli_ctx_.get_get_k(); getv_r.is_ok()) {
    auto key = getv_r.value();
    if (key == "auto_fetch_config") {
      output_hub_.info() << "auto_fetch_config = "
                         << (certctrl_config_provider_.get().auto_fetch_config
                                 ? "true"
                                 : "false")
                         << std::endl;
    } else if (key == "verbose") {
      output_hub_.info() << "verbose = "
                         << certctrl_config_provider_.get().verbose
                         << std::endl;
    } else {
      std::string msg =
          std::format("Unknown configuration key: {}, "
                      "supported keys are: auto_fetch_config, verbose",
                      key);
      return show_usage(msg);
    }
  } else {
    if (cli_ctx_.positional_contains("set")) {
      std::cerr << "Usage: cert-ctrl conf set <key> <value>\n";
    } else {
      return show_usage(print_opt_desc());
    }
  }
  return VoidPureIO::pure();
}
} // namespace certctrl