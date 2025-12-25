#pragma once

#include <memory>
#include <string>

#include <boost/json.hpp>

#include "acme/acme_http01_manager.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "my_error_codes.hpp"

namespace certctrl::signal_handlers {

class AcmeHttp01StopHandler : public ISignalHandler {
public:
  explicit AcmeHttp01StopHandler(std::shared_ptr<certctrl::acme::AcmeHttp01Manager> mgr)
      : mgr_(std::move(mgr)) {}

  std::string signal_type() const override { return "acme.http01.stop"; }

  monad::IO<void> handle(const ::data::DeviceUpdateSignal &signal) override {
    if (!mgr_) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::POINTER_IS_NULL,
          "acme.http01 handler missing manager"));
    }

    const auto *cid_v = signal.ref.if_contains("challenge_id");
    if (!cid_v || !cid_v->is_string()) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.stop ref.challenge_id must be string"));
    }

    const std::string cid = std::string(cid_v->as_string().c_str());

    auto r = mgr_->stop_if_active(cid);
    if (r.is_err()) {
      return monad::IO<void>::fail(std::move(r).error());
    }

    return monad::IO<void>::pure();
  }

private:
  std::shared_ptr<certctrl::acme::AcmeHttp01Manager> mgr_;
};

} // namespace certctrl::signal_handlers
