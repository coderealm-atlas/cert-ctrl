#pragma once

#include "customio/console_output.hpp"
#include "handlers/install_config_manager.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep
#include <boost/json.hpp>
#include <utility>

namespace certctrl {
namespace signal_handlers {

/**
 * Handler for "cert.unassigned" signals.
 * Purges cached certificate materials so detached certs stop deploying.
 */
class CertUnassignedHandler : public ISignalHandler {
private:
  std::shared_ptr<InstallConfigManager> config_manager_;
  customio::ConsoleOutput &output_hub_;

public:
  CertUnassignedHandler(std::shared_ptr<InstallConfigManager> config_manager,
                        customio::ConsoleOutput &output_hub)
      : config_manager_(std::move(config_manager)),
        output_hub_(output_hub) {}

  std::string signal_type() const override { return "cert.unassigned"; }

  monad::IO<void> handle(const ::data::DeviceUpdateSignal &signal) override {
    auto &lg = app_logger();
    auto ref = ::data::get_cert_unassigned(signal);
    if (!ref) {
      BOOST_LOG_SEV(lg, trivial::warning)
          << "cert.unassigned missing cert_id: "
          << boost::json::serialize(signal.ref);
      return monad::IO<void>::pure();
    }

    auto cert_id = ref->cert_id;
    BOOST_LOG_SEV(lg, trivial::info)
        << "cert.unassigned received; purging cache for cert " << cert_id;

    config_manager_->invalidate_resource_cache("cert", cert_id);
    BOOST_LOG_SEV(lg, trivial::info)
        << "cached materials removed for cert " << cert_id
        << "; downstream destinations must be cleaned manually until removal"
        << " workflows land";

    return monad::IO<void>::pure();
  }
};

} // namespace signal_handlers
} // namespace certctrl
