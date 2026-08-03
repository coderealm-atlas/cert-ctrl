#pragma once

#include "customio/console_output.hpp"
#include "handlers/install_config_manager.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include <boost/json.hpp>

namespace certctrl {
namespace signal_handlers {

class CaAssignedHandler : public ISignalHandler {
private:
  std::shared_ptr<InstallConfigManager> config_manager_;
  customio::ConsoleOutput &output_hub_;

public:
  CaAssignedHandler(std::shared_ptr<InstallConfigManager> config_manager,
                    customio::ConsoleOutput &output_hub)
      : config_manager_(std::move(config_manager)), output_hub_(output_hub) {}

  std::string signal_type() const override { return "ca.assigned"; }

  boost::asio::awaitable<monad::MyResult<void>>
  handle_awaitable(const ::data::DeviceUpdateSignal &signal) override {
    if (!config_manager_) {
      output_hub_.logger().warning()
          << "CaAssignedHandler missing InstallConfigManager; skipping signal"
          << std::endl;
      co_return monad::MyResult<void>::Ok();
    }

    auto typed = ::data::get_ca_assigned(signal);
    if (!typed || typed->ca_id <= 0) {
      output_hub_.logger().warning()
          << "ca.assigned signal missing ca_id: "
          << boost::json::serialize(signal.ref) << std::endl;
      co_return monad::MyResult<void>::Ok();
    }

    output_hub_.logger().info()
        << "Processing ca.assigned: " << boost::json::serialize(signal.ref)
        << std::endl;

    co_return co_await config_manager_->handle_ca_assignment(typed->ca_id,
                                                             typed->ca_name);
  }
};

} // namespace signal_handlers
} // namespace certctrl
