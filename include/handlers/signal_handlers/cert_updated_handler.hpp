#pragma once

#include "customio/console_output.hpp"
#include "handlers/install_config_manager.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep
#include <boost/json.hpp>

namespace certctrl {
namespace signal_handlers {

/**
 * Handler for "cert.updated" signals.
 * Fetches and installs updated certificates and their wrapped materials.
 */
class CertUpdatedHandler : public ISignalHandler {
private:
  std::shared_ptr<InstallConfigManager> config_manager_;
  customio::ConsoleOutput &output_hub_;
  src::severity_logger<trivial::severity_level> lg;

public:
  CertUpdatedHandler(std::shared_ptr<InstallConfigManager> config_manager,
                     customio::ConsoleOutput &output_hub)
      : config_manager_(std::move(config_manager)), output_hub_(output_hub) {}

  std::string signal_type() const override { return "cert.updated"; }

  monad::IO<void> handle(const ::data::DeviceUpdateSignal &signal) override {
    if (!config_manager_) {
      BOOST_LOG_SEV(lg, trivial::warning)
          << "CertUpdatedHandler missing InstallConfigManager; skipping signal";
      return monad::IO<void>::pure();
    }
    BOOST_LOG_SEV(lg, trivial::info) << "Handling cert.updated signal: "
                                     << boost::json::serialize(signal.ref);
    return config_manager_->apply_copy_actions_for_signal(signal);
  }
};

} // namespace signal_handlers
} // namespace certctrl
