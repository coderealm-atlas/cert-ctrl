#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "acme/acme_tlsalpn01_server.hpp"
#include "customio/console_output.hpp"
#include "my_error_codes.hpp"

namespace certctrl::acme {

struct AcmeTlsAlpn01ChallengeRequest {
  std::string challenge_id;

  std::string domain;
  std::string token;
  std::string key_authorization;

  std::string bind;
  std::uint16_t port{};

  std::string cert_pem;
  std::string key_pem;

  int ttl_seconds{300};
};

class AcmeTlsAlpn01Manager {
public:
  explicit AcmeTlsAlpn01Manager(customio::ConsoleOutput& output)
      : output_(output) {}

  monad::Result<void, monad::Error> start_or_update(
      const AcmeTlsAlpn01ChallengeRequest& req) {
    if (req.challenge_id.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.challenge ref.challenge_id is required"));
    }
    if (req.domain.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.challenge ref.domain is required"));
    }
    if (req.token.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.challenge ref.token is required"));
    }
    if (req.key_authorization.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.challenge ref.key_authorization is required"));
    }
    if (req.bind.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.challenge ref.listen.bind is required"));
    }
    if (req.cert_pem.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.challenge ref.certificate.cert_pem is required"));
    }
    if (req.key_pem.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.challenge ref.certificate.key_pem is required"));
    }

    const int ttl = (req.ttl_seconds > 0) ? req.ttl_seconds : 300;

    std::shared_ptr<AcmeTlsAlpn01Server> new_server;

    {
      std::lock_guard<std::mutex> lock(mu_);

      if (active_.has_value()) {
        if (active_->bind == req.bind && active_->port == req.port &&
            active_->server && !active_->server->is_stopped()) {
          active_->challenge_id = req.challenge_id;
          active_->server->update(AcmeTlsAlpn01Server::ChallengeConfig{
              req.domain, req.cert_pem, req.key_pem, std::chrono::seconds(ttl)});
          output_.logger().info()
              << "ACME TLS-ALPN-01 updated active challenge_id="
              << req.challenge_id << std::endl;
          return monad::Result<void, monad::Error>::Ok();
        }
      }

      auto started = AcmeTlsAlpn01Server::start(
          AcmeTlsAlpn01Server::ListenConfig{req.bind, req.port},
          AcmeTlsAlpn01Server::ChallengeConfig{req.domain, req.cert_pem,
                                               req.key_pem,
                                               std::chrono::seconds(ttl)});

      if (started.is_err()) {
        return monad::Result<void, monad::Error>::Err(
            std::move(started).error());
      }

      new_server = std::move(started).value();

      if (active_.has_value()) {
        active_->server->stop();
      }

      ActiveState next;
      next.challenge_id = req.challenge_id;
      next.bind = req.bind;
      next.port = req.port;
      next.server = std::move(new_server);
      active_ = std::move(next);

      output_.logger().info()
          << "ACME TLS-ALPN-01 started challenge_id=" << req.challenge_id
          << " bind=" << req.bind << " port=" << active_->server->port()
          << std::endl;
    }

    return monad::Result<void, monad::Error>::Ok();
  }

  monad::Result<void, monad::Error> stop_if_active(
      const std::string& challenge_id) {
    if (challenge_id.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.stop ref.challenge_id is required"));
    }

    std::lock_guard<std::mutex> lock(mu_);

    if (!active_.has_value()) {
      return monad::Result<void, monad::Error>::Ok();
    }

    if (active_->challenge_id != challenge_id) {
      return monad::Result<void, monad::Error>::Ok();
    }

    active_->server->stop();
    active_.reset();

    output_.logger().info() << "ACME TLS-ALPN-01 stopped challenge_id="
                            << challenge_id << std::endl;

    return monad::Result<void, monad::Error>::Ok();
  }

private:
  struct ActiveState {
    std::string challenge_id;
    std::string bind;
    std::uint16_t port{};
    std::shared_ptr<AcmeTlsAlpn01Server> server;
  };

  customio::ConsoleOutput& output_;
  std::mutex mu_;
  std::optional<ActiveState> active_;
};

} // namespace certctrl::acme
