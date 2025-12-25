#include "handlers/conf_handler.hpp"
#include <fmt/format.h>

namespace certctrl {

using VoidPureIO = monad::IO<void>;

VoidPureIO ConfHandler::start() {
  auto normalize_websocket_key = [](const std::string &key) {
    return key == "websocket_enabled" || key == "websocket.enabled";
  };

  if (auto setv_r = cli_ctx_.get_set_kv(); setv_r.is_ok()) {
    auto [key, value] = setv_r.value();
    if (key == "auto_apply_config") {
      bool bool_value = parse_bool(value);
      if (bool_value != certctrl_config_provider_.get().auto_apply_config) {
        certctrl_config_provider_.get().auto_apply_config = bool_value;
        certctrl_config_provider_.save({{"auto_apply_config", bool_value}});
      }
      output_hub_.logger().info()
          << "Set auto_apply_config to " << (bool_value ? "true" : "false")
          << std::endl;
    } else if (key == "verbose") {
      certctrl_config_provider_.get().verbose = value;
      certctrl_config_provider_.save({{"verbose", value}});
      output_hub_.logger().info() << "Set verbose to " << value << std::endl;
    } else if (normalize_websocket_key(key)) {
      bool bool_value = parse_bool(value);
      if (bool_value != websocket_config_provider_.get().enabled) {
        websocket_config_provider_.get().enabled = bool_value;
        websocket_config_provider_.save({{"enabled", bool_value}});
      }
      output_hub_.logger().info()
          << "Set websocket.enabled to " << (bool_value ? "true" : "false")
          << std::endl;
    } else {
      std::string msg = fmt::format(
          "Unknown configuration key: {}, supported keys are: auto_apply_config, verbose, websocket.enabled",
          key);
      return show_usage(msg);
    }
  } else if (auto getv_r = cli_ctx_.get_get_k(); getv_r.is_ok()) {
    auto key = getv_r.value();
    if (key == "auto_apply_config") {
      output_hub_.logger().info()
          << "auto_apply_config = "
          << (certctrl_config_provider_.get().auto_apply_config ? "true"
                                                                : "false")
          << std::endl;
    } else if (key == "verbose") {
      output_hub_.logger().info()
          << "verbose = " << certctrl_config_provider_.get().verbose
          << std::endl;
    } else if (normalize_websocket_key(key)) {
      output_hub_.logger().info()
          << "websocket.enabled = "
          << (websocket_config_provider_.get().enabled ? "true" : "false")
          << std::endl;
    } else {
      std::string msg = fmt::format(
          "Unknown configuration key: {}, supported keys are: auto_apply_config, verbose, websocket.enabled",
          key);
      return show_usage(msg);
    }
  } else {
    return show_usage(print_opt_desc());
  }
  return VoidPureIO::pure();
}
} // namespace certctrl