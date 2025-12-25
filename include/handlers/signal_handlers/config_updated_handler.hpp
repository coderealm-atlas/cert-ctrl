#pragma once

#include "conf/certctrl_config.hpp"
#include "conf/websocket_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "my_error_codes.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep

#include <boost/json.hpp>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace certctrl {
namespace signal_handlers {

/**
 * Handler for "config.updated" signals.
 *
 * Canonical implementation (full-object workflow):
 * - Consumes ref.replace entries of {file, content}.
 * - application: selectively applies allowlisted keys (auto_apply_config, verbose)
 *   and persists via ICertctrlConfigProvider::save (application.override.json).
 * - websocket: persists the full snapshot via IWebsocketConfigProvider::save_replace
 *   and triggers a websocket session restart callback (if provided).
 */
class ConfigUpdatedHandler : public ISignalHandler {
private:
  certctrl::ICertctrlConfigProvider &config_provider_;
  certctrl::IWebsocketConfigProvider *websocket_config_provider_{nullptr};
  std::function<void()> on_websocket_config_updated_;
  customio::ConsoleOutput &output_hub_;
  src::severity_logger<trivial::severity_level> lg;

  static monad::IO<void> fail_invalid_argument(const std::string &what) {
    monad::Error err{};
    err.code = my_errors::GENERAL::INVALID_ARGUMENT;
    err.what = what;
    return monad::IO<void>::fail(std::move(err));
  }

public:
  ConfigUpdatedHandler(certctrl::ICertctrlConfigProvider &config_provider,
                      customio::ConsoleOutput &output_hub,
                      certctrl::IWebsocketConfigProvider *websocket_config_provider = nullptr,
                      std::function<void()> on_websocket_config_updated = {})
      : config_provider_(config_provider),
        websocket_config_provider_(websocket_config_provider),
        on_websocket_config_updated_(std::move(on_websocket_config_updated)),
        output_hub_(output_hub) {}

  std::string signal_type() const override { return "config.updated"; }

  monad::IO<void> handle(const ::data::DeviceUpdateSignal &signal) override {
    namespace json = boost::json;

    if (signal.ref.if_contains("set")) {
      return fail_invalid_argument(
          "config.updated ref.set is not supported; use ref.replace");
    }

    if (const json::value *replace_val = signal.ref.if_contains("replace")) {
      if (!replace_val->is_array()) {
        return fail_invalid_argument("config.updated ref.replace must be an array");
      }
      const auto &arr = replace_val->as_array();

      json::object application_patch;
      std::optional<json::object> websocket_content;

      for (const auto &entry_val : arr) {
        if (!entry_val.is_object()) {
          return fail_invalid_argument(
              "config.updated ref.replace entries must be objects");
        }
        const auto &entry = entry_val.as_object();

        const auto *file_val = entry.if_contains("file");
        const auto *content_val = entry.if_contains("content");
        if (!file_val || !file_val->is_string()) {
          return fail_invalid_argument(
              "config.updated ref.replace entry.file must be string");
        }
        if (!content_val || !content_val->is_object()) {
          return fail_invalid_argument(
              "config.updated ref.replace entry.content must be object");
        }
        const std::string file = std::string(file_val->as_string().c_str());
        const auto &content_obj = content_val->as_object();

        if (file == "application") {
          if (const json::value *v = content_obj.if_contains("auto_apply_config")) {
            if (!v->is_bool()) {
              return fail_invalid_argument(
                  "config.updated replace(application).content.auto_apply_config must be boolean");
            }
            const bool bool_value = v->as_bool();
            config_provider_.get().auto_apply_config = bool_value;
            application_patch["auto_apply_config"] = bool_value;
          }

          if (const json::value *v = content_obj.if_contains("verbose")) {
            if (!v->is_string()) {
              return fail_invalid_argument(
                  "config.updated replace(application).content.verbose must be string");
            }
            const std::string str_value = std::string(v->as_string().c_str());
            config_provider_.get().verbose = str_value;
            application_patch["verbose"] = str_value;
          }
        } else if (file == "websocket") {
          websocket_content = content_obj;
        } else {
          BOOST_LOG_SEV(lg, trivial::info)
              << "config.updated ignoring unsupported replace file: " << file;
        }
      }

      if (!application_patch.empty()) {
        BOOST_LOG_SEV(lg, trivial::info)
            << "Applying config.updated application patch: "
            << json::serialize(application_patch);
        auto save_r = config_provider_.save(application_patch);
        if (save_r.is_err()) {
          return monad::IO<void>::fail(save_r.error());
        }
      }

      if (websocket_content.has_value()) {
        if (!websocket_config_provider_) {
          output_hub_.logger().info()
              << "config.updated replace(websocket) ignored: websocket config provider not available"
              << std::endl;
          return monad::IO<void>::pure();
        }

        try {
          websocket_config_provider_->get() =
              boost::json::value_to<certctrl::WebsocketConfig>(
                  json::value(*websocket_content));
        } catch (const std::exception &ex) {
          return fail_invalid_argument(
              std::string("config.updated replace(websocket).content invalid: ") + ex.what());
        }

        auto save_r = websocket_config_provider_->save_replace(*websocket_content);
        if (save_r.is_err()) {
          return monad::IO<void>::fail(save_r.error());
        }

        BOOST_LOG_SEV(lg, trivial::info)
            << "Applied websocket config snapshot";

        if (on_websocket_config_updated_) {
          on_websocket_config_updated_();
        }
      }

      return monad::IO<void>::pure();
    }

    output_hub_.logger().info()
        << "Received config.updated without ref.replace; no action taken. ref="
        << json::serialize(signal.ref) << std::endl;
    return monad::IO<void>::pure();
  }
};

} // namespace signal_handlers
} // namespace certctrl
