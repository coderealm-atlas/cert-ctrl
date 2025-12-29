#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "acme/acme_http01_server.hpp"
#include "customio/console_output.hpp"
#include "my_error_codes.hpp"

namespace certctrl::acme {

struct AcmeHttp01ChallengeRequest {
  std::string challenge_id;
  std::string token;
  std::string key_authorization;
  std::string bind;
  std::uint16_t port{};
  int ttl_seconds{300};
  bool https_enabled{false};
};

class AcmeHttp01Manager {
public:
  explicit AcmeHttp01Manager(customio::ConsoleOutput &output)
      : output_(output) {}

  monad::Result<void, monad::Error>
  start_or_update(const AcmeHttp01ChallengeRequest &req) {
    if (req.challenge_id.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.start ref.challenge_id is required"));
    }
    if (req.token.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.start ref.token is required"));
    }
    if (req.key_authorization.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.start ref.key_authorization is required"));
    }
    if (req.bind.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.start ref.listen.http.bind is required"));
    }

    if (req.https_enabled) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::NOT_IMPLEMENTED,
          "acme.http01.start https.enabled=true is not supported"));
    }

    const int ttl = (req.ttl_seconds > 0) ? req.ttl_seconds : 300;

    std::shared_ptr<AcmeHttp01Server> new_server;

    {
      std::lock_guard<std::mutex> lock(mu_);

      if (active_.has_value()) {
        // Same endpoint -> update in place.
        if (active_->bind == req.bind && active_->port == req.port &&
            active_->server && !active_->server->is_stopped()) {
          active_->challenge_id = req.challenge_id;
          active_->server->update(AcmeHttp01Server::ChallengeConfig{
              req.token, req.key_authorization, std::chrono::seconds(ttl)});
          output_.logger().info()
              << "ACME HTTP-01 updated active challenge_id="
              << req.challenge_id << std::endl;
          return monad::Result<void, monad::Error>::Ok();
        }
      }

      // Different endpoint or no active.
      auto started = AcmeHttp01Server::start(
          AcmeHttp01Server::ListenConfig{req.bind, req.port},
          AcmeHttp01Server::ChallengeConfig{req.token, req.key_authorization,
                                            std::chrono::seconds(ttl)});

      if (started.is_err()) {
        return monad::Result<void, monad::Error>::Err(std::move(started).error());
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
          << "ACME HTTP-01 started challenge_id=" << req.challenge_id
          << " bind=" << req.bind << " port=" << active_->server->port()
          << std::endl;
    }

    return monad::Result<void, monad::Error>::Ok();
  }

  monad::Result<void, monad::Error> stop_if_active(const std::string &challenge_id) {
    if (challenge_id.empty()) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.stop ref.challenge_id is required"));
    }

    std::lock_guard<std::mutex> lock(mu_);

    if (!active_.has_value()) {
      return monad::Result<void, monad::Error>::Ok();
    }

    if (active_->challenge_id != challenge_id) {
      // Idempotent stop: not active -> no-op.
      return monad::Result<void, monad::Error>::Ok();
    }

    active_->server->stop();
    active_.reset();

    output_.logger().info()
        << "ACME HTTP-01 stopped challenge_id=" << challenge_id << std::endl;

    return monad::Result<void, monad::Error>::Ok();
  }

private:
  struct ActiveState {
    std::string challenge_id;
    std::string bind;
    std::uint16_t port{};
    std::shared_ptr<AcmeHttp01Server> server;
  };

  customio::ConsoleOutput &output_;
  std::mutex mu_;
  std::optional<ActiveState> active_;
};

} // namespace certctrl::acme
