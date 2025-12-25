#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include <boost/json.hpp>

#include "acme/acme_http01_manager.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "my_error_codes.hpp"

namespace certctrl::signal_handlers {

class AcmeHttp01ChallengeHandler : public ISignalHandler {
public:
  explicit AcmeHttp01ChallengeHandler(std::shared_ptr<certctrl::acme::AcmeHttp01Manager> mgr)
      : mgr_(std::move(mgr)) {}

  std::string signal_type() const override { return "acme.http01.challenge"; }

  monad::IO<void> handle(const ::data::DeviceUpdateSignal &signal) override {
    if (!mgr_) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::POINTER_IS_NULL,
          "acme.http01 handler missing manager"));
    }

    certctrl::acme::AcmeHttp01ChallengeRequest req;

    const auto *cid_v = signal.ref.if_contains("challenge_id");
    if (!cid_v || !cid_v->is_string()) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.challenge ref.challenge_id must be string"));
    }
    req.challenge_id = std::string(cid_v->as_string().c_str());

    const auto *token_v = signal.ref.if_contains("token");
    if (!token_v || !token_v->is_string()) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.challenge ref.token must be string"));
    }
    req.token = std::string(token_v->as_string().c_str());

    const auto *ka_v = signal.ref.if_contains("key_authorization");
    if (!ka_v || !ka_v->is_string()) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.challenge ref.key_authorization must be string"));
    }
    req.key_authorization = std::string(ka_v->as_string().c_str());

    if (const auto *ttl_v = signal.ref.if_contains("ttl_seconds")) {
      if (ttl_v->is_int64()) {
        req.ttl_seconds = static_cast<int>(ttl_v->as_int64());
      } else if (ttl_v->is_uint64()) {
        req.ttl_seconds = static_cast<int>(ttl_v->as_uint64());
      } else if (ttl_v->is_double()) {
        req.ttl_seconds = static_cast<int>(ttl_v->as_double());
      } else {
        return monad::IO<void>::fail(monad::make_error(
            my_errors::GENERAL::TYPE_CONVERT_FAILED,
            "acme.http01.challenge ref.ttl_seconds must be number"));
      }
    }

    const auto *listen_v = signal.ref.if_contains("listen");
    if (!listen_v || !listen_v->is_object()) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.challenge ref.listen must be object"));
    }

    const auto &listen_obj = listen_v->as_object();

    const auto *http_v = listen_obj.if_contains("http");
    if (!http_v || !http_v->is_object()) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.challenge ref.listen.http must be object"));
    }

    const auto &http_obj = http_v->as_object();

    const auto *bind_v = http_obj.if_contains("bind");
    if (!bind_v || !bind_v->is_string()) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.challenge ref.listen.http.bind must be string"));
    }
    req.bind = std::string(bind_v->as_string().c_str());

    const auto *port_v = http_obj.if_contains("port");
    if (!port_v || (!port_v->is_int64() && !port_v->is_uint64() && !port_v->is_double())) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.challenge ref.listen.http.port must be number"));
    }

    std::int64_t port_i64 = 0;
    if (port_v->is_int64()) {
      port_i64 = port_v->as_int64();
    } else if (port_v->is_uint64()) {
      port_i64 = static_cast<std::int64_t>(port_v->as_uint64());
    } else {
      port_i64 = static_cast<std::int64_t>(port_v->as_double());
    }
    if (port_i64 < 0 || port_i64 > 65535) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          "acme.http01.challenge ref.listen.http.port out of range"));
    }
    req.port = static_cast<std::uint16_t>(port_i64);

    if (const auto *https_v = listen_obj.if_contains("https")) {
      if (https_v->is_object()) {
        if (const auto *enabled_v = https_v->as_object().if_contains("enabled")) {
          if (!enabled_v->is_bool()) {
            return monad::IO<void>::fail(monad::make_error(
                my_errors::GENERAL::TYPE_CONVERT_FAILED,
                "acme.http01.challenge ref.listen.https.enabled must be boolean"));
          }
          req.https_enabled = enabled_v->as_bool();
        }
      }
    }

    auto r = mgr_->start_or_update(req);
    if (r.is_err()) {
      return monad::IO<void>::fail(std::move(r).error());
    }

    return monad::IO<void>::pure();
  }

private:
  std::shared_ptr<certctrl::acme::AcmeHttp01Manager> mgr_;
};

} // namespace certctrl::signal_handlers
