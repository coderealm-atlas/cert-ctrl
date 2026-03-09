#pragma once

#include <boost/json.hpp>
#include <memory>
#include <optional>
#include <string>

#include "customio/console_output.hpp"
#include "handlers/install_config_manager.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "my_error_codes.hpp"
#include "state/device_state_store.hpp"

namespace certctrl {
namespace signal_handlers {

class StateResyncRequiredHandler : public ISignalHandler {
private:
  std::shared_ptr<InstallConfigManager> config_manager_;
  certctrl::IDeviceStateStore &state_store_;
  customio::ConsoleOutput &output_hub_;

public:
  StateResyncRequiredHandler(std::shared_ptr<InstallConfigManager> config_manager,
                             certctrl::IDeviceStateStore &state_store,
                             customio::ConsoleOutput &output_hub)
      : config_manager_(std::move(config_manager)), state_store_(state_store),
        output_hub_(output_hub) {}

  std::string signal_type() const override { return "state.resync_required"; }

  monad::IO<void> handle(const ::data::DeviceUpdateSignal &signal) override {
    if (!config_manager_) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT,
          "state.resync_required received without InstallConfigManager"));
    }

    std::string reason = "unspecified";
    std::string earliest_id;
    if (auto *reason_v = signal.ref.if_contains("reason");
        reason_v && reason_v->is_string()) {
      reason = std::string(reason_v->as_string().c_str());
    }
    if (auto *earliest_v = signal.ref.if_contains("earliest_retained_id");
        earliest_v && earliest_v->is_string()) {
      earliest_id = std::string(earliest_v->as_string().c_str());
    }

    output_hub_.logger().warning()
        << "Processing state.resync_required reason=" << reason
        << (earliest_id.empty() ? std::string{} : " earliest_retained_id=" + earliest_id)
        << std::endl;

    if (auto err = state_store_.save_updates_cursor(std::nullopt)) {
      return monad::IO<void>::fail(
          monad::make_error(my_errors::GENERAL::DELETE_FAILED,
                            "failed to clear polling cursor before full resync: " +
                                *err));
    }
    if (auto err = state_store_.save_websocket_resume_token(std::nullopt)) {
      return monad::IO<void>::fail(
          monad::make_error(my_errors::GENERAL::DELETE_FAILED,
                            "failed to clear websocket resume token before full resync: " +
                                *err));
    }

    return config_manager_->full_resync_from_server();
  }
};

} // namespace signal_handlers
} // namespace certctrl