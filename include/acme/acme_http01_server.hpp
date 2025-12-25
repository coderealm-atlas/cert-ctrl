#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include "result_monad.hpp"
#include "my_error_codes.hpp"
#include "util/my_logging.hpp"

namespace certctrl::acme {

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;
using tcp = boost::asio::ip::tcp;

class AcmeHttp01Server : public std::enable_shared_from_this<AcmeHttp01Server> {
public:
  struct ListenConfig {
    std::string bind;
    std::uint16_t port{};
  };

  struct ChallengeConfig {
    std::string token;
    std::string key_authorization;
    std::chrono::seconds ttl{300};
  };

  using StartResult = monad::Result<std::shared_ptr<AcmeHttp01Server>, monad::Error>;

  static StartResult start(ListenConfig listen, ChallengeConfig challenge) {
    if (listen.bind.empty()) {
      return StartResult::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.listen.http.bind is required"));
    }

    if (challenge.token.empty()) {
      return StartResult::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.token is required"));
    }

    if (challenge.key_authorization.empty()) {
      return StartResult::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.http01.key_authorization is required"));
    }

    if (challenge.ttl.count() <= 0) {
      challenge.ttl = std::chrono::seconds(300);
    }

    auto srv = std::shared_ptr<AcmeHttp01Server>(
        new AcmeHttp01Server(std::move(listen), std::move(challenge)));

    srv->weak_self_ = srv;

    auto r = srv->start_listening();
    if (r.is_err()) {
      return StartResult::Err(std::move(r).error());
    }

    srv->start_thread();
    return StartResult::Ok(std::move(srv));
  }

  ~AcmeHttp01Server() { stop(); }

  std::string bind() const { return listen_.bind; }

  std::uint16_t port() const { return actual_port_.load(); }

  bool is_stopped() const { return stopped_.load(); }

  void update(ChallengeConfig challenge) {
    if (challenge.token.empty() || challenge.key_authorization.empty()) {
      return;
    }

    if (challenge.ttl.count() <= 0) {
      challenge.ttl = std::chrono::seconds(300);
    }

    set_snapshot(std::move(challenge.token),
                 std::move(challenge.key_authorization));

    // Reschedule TTL (best-effort)
    if (auto self = weak_self_.lock()) {
      net::post(ioc_, [self = std::move(self), ttl = challenge.ttl]() {
        self->schedule_ttl(ttl);
      });
    }
  }

  void stop() {
    const bool was_already_stopped = stopped_.exchange(true);

    if (!was_already_stopped) {
      // Best-effort: cancel accept/timer and stop ioc.
      if (auto self = weak_self_.lock()) {
        net::post(ioc_, [self = std::move(self)]() {
          if (self->ttl_timer_) {
            (void)self->ttl_timer_->cancel();
          }
          try {
            self->acceptor_.cancel();
          } catch (...) {
          }
          try {
            self->acceptor_.close();
          } catch (...) {
          }
          if (self->work_guard_) {
            self->work_guard_.reset();
          }
          self->ioc_.stop();
        });
      } else {
        // Destruction path: avoid shared_from_this().
        if (ttl_timer_) {
          (void)ttl_timer_->cancel();
        }
        try {
          acceptor_.cancel();
        } catch (...) {
        }
        try {
          acceptor_.close();
        } catch (...) {
        }
        if (work_guard_) {
          work_guard_.reset();
        }
        ioc_.stop();
      }
    }

    if (thread_.joinable() && std::this_thread::get_id() != thread_.get_id()) {
      thread_.join();
    }
  }

private:
  struct Snapshot {
    std::string expected_target;
    std::string key_authorization;
  };

  class Session : public std::enable_shared_from_this<Session> {
  public:
    explicit Session(tcp::socket socket,
                     std::weak_ptr<AcmeHttp01Server> server)
        : stream_(std::move(socket)), server_(std::move(server)) {
      parser_.body_limit(0);
      parser_.header_limit(8 * 1024);
    }

    void run() { do_read(); }

  private:
    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request_parser<http::empty_body> parser_;
    std::weak_ptr<AcmeHttp01Server> server_;

    void do_read() {
      auto self = shared_from_this();
      http::async_read(stream_, buffer_, parser_,
                       [self](boost::system::error_code ec, std::size_t) {
                         self->on_read(ec);
                       });
    }

    void on_read(const boost::system::error_code &ec) {
      if (ec == http::error::end_of_stream) {
        boost::system::error_code ignored;
        self_close(ignored);
        return;
      }
      if (ec) {
        boost::system::error_code ignored;
        self_close(ignored);
        return;
      }

      auto req = parser_.release();

      auto server = server_.lock();
      if (!server) {
        boost::system::error_code ignored;
        self_close(ignored);
        return;
      }

      auto snap = server->snapshot();

      const bool method_ok = (req.method() == http::verb::get ||
                              req.method() == http::verb::head);
      const std::string target = std::string(req.target());

      // Response must outlive the async_write.
      auto res = std::make_shared<http::response<http::string_body>>();
      res->version(req.version());
      res->set(http::field::server, "cert-ctrl");
      res->keep_alive(false);

      if (method_ok && target == snap->expected_target) {
        res->result(http::status::ok);
        res->set(http::field::content_type, "text/plain");
        if (req.method() == http::verb::get) {
          res->body() = snap->key_authorization;
        } else {
          // HEAD: no body
          res->body().clear();
        }
        res->content_length(snap->key_authorization.size());
      } else {
        res->result(http::status::not_found);
        res->set(http::field::content_type, "text/plain");
        res->body() = "not found";
        res->prepare_payload();
      }

      auto self = shared_from_this();
      http::async_write(stream_, *res,
                        [self, res](boost::system::error_code, std::size_t) {
                          boost::system::error_code ignored;
                          self->self_close(ignored);
                        });
    }

    void self_close(boost::system::error_code &ec) {
      try {
        stream_.socket().shutdown(tcp::socket::shutdown_send);
      } catch (...) {
      }
      try {
        stream_.socket().close();
      } catch (...) {
      }
    }
  };

  explicit AcmeHttp01Server(ListenConfig listen, ChallengeConfig challenge)
      : listen_(std::move(listen)),
        ioc_(1),
        acceptor_(net::make_strand(ioc_)),
        lg_() {
    work_guard_ = std::make_unique<net::executor_work_guard<net::io_context::executor_type>>(
        net::make_work_guard(ioc_));

    actual_port_.store(listen_.port);

    set_snapshot(std::move(challenge.token),
                 std::move(challenge.key_authorization));

    ttl_timer_ = std::make_unique<net::steady_timer>(ioc_);
    ttl_ = challenge.ttl;
  }

  monad::Result<void, monad::Error> start_listening() {
    boost::system::error_code ec;
    auto addr = net::ip::make_address(listen_.bind, ec);
    if (ec) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          std::string("Invalid bind address: ") + ec.message()));
    }

    try {
      tcp::endpoint ep{addr, listen_.port};
      acceptor_.open(ep.protocol());
      acceptor_.set_option(net::socket_base::reuse_address(true));
      acceptor_.bind(ep);
      acceptor_.listen(net::socket_base::max_listen_connections);
    } catch (const boost::system::system_error &se) {
      return monad::Result<void, monad::Error>::Err(monad::make_error(
          my_errors::GENERAL::CREATE_FAILED,
          std::string("Failed to bind/listen ") + listen_.bind + ":" +
              std::to_string(listen_.port) + ": " + se.code().message()));
    }

    actual_port_.store(acceptor_.local_endpoint(ec).port());
    if (ec) {
      actual_port_.store(listen_.port);
    }

    do_accept();

    BOOST_LOG_SEV(lg_, trivial::info)
        << "ACME HTTP-01 server listening on " << listen_.bind << ':'
        << actual_port_.load();

    return monad::Result<void, monad::Error>::Ok();
  }

  void start_thread() {
    thread_ = std::thread([this]() {
      try {
        net::post(ioc_, [this]() { schedule_ttl(ttl_); });
        ioc_.run();
      } catch (...) {
      }
    });
  }

  void do_accept() {
    acceptor_.async_accept(
        net::make_strand(ioc_),
        [this](boost::system::error_code ec, tcp::socket socket) {
          if (ec) {
            if (ec != net::error::operation_aborted) {
              BOOST_LOG_SEV(lg_, trivial::warning)
                  << "ACME HTTP-01 accept failed: " << ec.message();
            }
            return;
          }

          std::make_shared<Session>(std::move(socket), weak_self_)->run();

          if (!stopped_.load()) {
            do_accept();
          }
        });
  }

  void schedule_ttl(std::chrono::seconds ttl) {
    if (!ttl_timer_) {
      return;
    }

    (void)ttl_timer_->cancel();

    ttl_timer_->expires_after(ttl);
    ttl_timer_->async_wait([weak = weak_self_](const boost::system::error_code &ec) {
      if (ec == net::error::operation_aborted) {
        return;
      }
      if (ec) {
        return;
      }
      if (auto self = weak.lock()) {
        BOOST_LOG_SEV(self->lg_, trivial::info)
            << "ACME HTTP-01 server TTL expired; stopping";
        // No-join stop path for callbacks running on the server thread.
        self->stop();
      }
    });
  }

  std::shared_ptr<const Snapshot> snapshot() const {
    std::lock_guard<std::mutex> lock(snapshot_mu_);
    return snapshot_;
  }

  void set_snapshot(std::string token, std::string key_authorization) {
    auto snap = std::make_shared<Snapshot>();
    snap->expected_target = "/.well-known/acme-challenge/" + token;
    snap->key_authorization = std::move(key_authorization);
    std::lock_guard<std::mutex> lock(snapshot_mu_);
    snapshot_ = std::move(snap);
  }

  ListenConfig listen_;

  net::io_context ioc_;
  tcp::acceptor acceptor_;
  std::unique_ptr<net::executor_work_guard<net::io_context::executor_type>>
      work_guard_;
  std::unique_ptr<net::steady_timer> ttl_timer_;
  std::thread thread_;

  std::atomic<std::uint16_t> actual_port_{0};
  std::atomic<bool> stopped_{false};

  mutable std::mutex snapshot_mu_;
  std::shared_ptr<const Snapshot> snapshot_;

  std::weak_ptr<AcmeHttp01Server> weak_self_;
  std::chrono::seconds ttl_{300};

  src::severity_logger<trivial::severity_level> lg_;
};

} // namespace certctrl::acme
