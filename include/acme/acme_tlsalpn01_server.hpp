#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/trivial.hpp>

#include <openssl/ssl.h>

#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace certctrl::acme {

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
namespace src = boost::log::sources;
namespace trivial = boost::log::trivial;

class AcmeTlsAlpn01Server
    : public std::enable_shared_from_this<AcmeTlsAlpn01Server> {
public:
  struct ListenConfig {
    std::string bind;
    std::uint16_t port{};
  };

  struct ChallengeConfig {
    std::string domain;
    std::string cert_pem;
    std::string key_pem;
    std::chrono::seconds ttl{300};
  };

  using StartResult =
      monad::Result<std::shared_ptr<AcmeTlsAlpn01Server>, monad::Error>;

  static StartResult start(ListenConfig listen, ChallengeConfig challenge) {
    if (listen.bind.empty()) {
      return StartResult::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.listen.bind is required"));
    }

    if (challenge.domain.empty()) {
      return StartResult::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.domain is required"));
    }

    if (challenge.cert_pem.empty()) {
      return StartResult::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.certificate.cert_pem is required"));
    }

    if (challenge.key_pem.empty()) {
      return StartResult::Err(monad::make_error(
          my_errors::GENERAL::MISSING_FIELD,
          "acme.tlsalpn01.certificate.key_pem is required"));
    }

    if (challenge.ttl.count() <= 0) {
      challenge.ttl = std::chrono::seconds(300);
    }

    // Validate that the provided cert/key parses and matches.
    auto ctx_r = make_ssl_context(challenge.domain, challenge.cert_pem,
                                  challenge.key_pem);
    if (ctx_r.is_err()) {
      return StartResult::Err(std::move(ctx_r).error());
    }

    auto srv = std::shared_ptr<AcmeTlsAlpn01Server>(
        new AcmeTlsAlpn01Server(std::move(listen), std::move(challenge),
                                std::move(ctx_r).value()));

    srv->weak_self_ = srv;

    auto r = srv->start_listening();
    if (r.is_err()) {
      return StartResult::Err(std::move(r).error());
    }

    srv->start_thread();
    return StartResult::Ok(std::move(srv));
  }

  ~AcmeTlsAlpn01Server() { stop(); }

  std::string bind() const { return listen_.bind; }

  std::uint16_t port() const { return actual_port_.load(); }

  bool is_stopped() const { return stopped_.load(); }

  void update(ChallengeConfig challenge) {
    if (challenge.domain.empty() || challenge.cert_pem.empty() ||
        challenge.key_pem.empty()) {
      return;
    }

    if (challenge.ttl.count() <= 0) {
      challenge.ttl = std::chrono::seconds(300);
    }

    auto ctx_r = make_ssl_context(challenge.domain, challenge.cert_pem,
                                  challenge.key_pem);
    if (ctx_r.is_err()) {
      // Best-effort update; keep existing challenge active.
      BOOST_LOG_SEV(lg_, trivial::warning)
          << "ACME TLS-ALPN-01 update ignored: " << ctx_r.error().what;
      return;
    }

    set_snapshot(std::move(challenge.domain), std::move(challenge.cert_pem),
                 std::move(challenge.key_pem), std::move(ctx_r).value());

    if (auto self = weak_self_.lock()) {
      net::post(ioc_, [self = std::move(self), ttl = challenge.ttl]() {
        self->schedule_ttl(ttl);
      });
    }
  }

  void stop() {
    const bool was_already_stopped = stopped_.exchange(true);

    if (!was_already_stopped) {
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
    std::string domain;
    std::string cert_pem;
    std::string key_pem;
    std::shared_ptr<ssl::context> ssl_ctx;
  };

  class Session : public std::enable_shared_from_this<Session> {
  public:
    Session(tcp::socket socket, std::shared_ptr<Snapshot> snap)
        : stream_(std::move(socket), *snap->ssl_ctx), snap_(std::move(snap)) {
      SSL_set_ex_data(stream_.native_handle(), AcmeTlsAlpn01Server::sni_ex_index(),
                      static_cast<void*>(snap_.get()));
    }

    void run() {
      auto self = shared_from_this();
      stream_.async_handshake(ssl::stream_base::server,
                              [self](boost::system::error_code ec) {
                                self->on_handshake(ec);
                              });
    }

  private:
    ssl::stream<tcp::socket> stream_;
    std::shared_ptr<Snapshot> snap_;

    void on_handshake(const boost::system::error_code& ec) {
      if (ec) {
        boost::system::error_code ignored;
        self_close(ignored);
        return;
      }

      // Enforce that ALPN negotiated acme-tls/1.
      const unsigned char* proto = nullptr;
      unsigned int proto_len = 0;
      SSL_get0_alpn_selected(stream_.native_handle(), &proto, &proto_len);
      const std::string_view selected(
          reinterpret_cast<const char*>(proto), proto_len);
      if (selected != kAlpnProto) {
        boost::system::error_code ignored;
        self_close(ignored);
        return;
      }

      boost::system::error_code ignored;
      self_close(ignored);
    }

    void self_close(boost::system::error_code&) {
      try {
        stream_.shutdown();
      } catch (...) {
      }
      try {
        stream_.lowest_layer().shutdown(tcp::socket::shutdown_both);
      } catch (...) {
      }
      try {
        stream_.lowest_layer().close();
      } catch (...) {
      }
    }

    static inline constexpr std::string_view kAlpnProto{"acme-tls/1"};
  };

  explicit AcmeTlsAlpn01Server(ListenConfig listen, ChallengeConfig challenge,
                               std::shared_ptr<ssl::context> ctx)
      : listen_(std::move(listen)),
        ioc_(1),
        acceptor_(net::make_strand(ioc_)),
        lg_() {
    work_guard_ = std::make_unique<
        net::executor_work_guard<net::io_context::executor_type>>(ioc_.get_executor());

    set_snapshot(std::move(challenge.domain), std::move(challenge.cert_pem),
                 std::move(challenge.key_pem), std::move(ctx));

    ttl_timer_ = std::make_unique<net::steady_timer>(ioc_);
    schedule_ttl(challenge.ttl);
  }

  ListenConfig listen_;
  net::io_context ioc_;
  tcp::acceptor acceptor_;
  std::unique_ptr<net::executor_work_guard<net::io_context::executor_type>>
      work_guard_;
  std::unique_ptr<net::steady_timer> ttl_timer_;
  std::thread thread_;
  std::weak_ptr<AcmeTlsAlpn01Server> weak_self_;

  std::atomic<bool> stopped_{false};
  std::atomic<std::uint16_t> actual_port_{0};

  mutable std::mutex snapshot_mu_;
  std::shared_ptr<Snapshot> snapshot_;

  src::severity_logger<trivial::severity_level> lg_;

  static inline constexpr std::string_view kAlpnProto{"acme-tls/1"};

  std::shared_ptr<Snapshot> snapshot() const {
    std::lock_guard<std::mutex> lock(snapshot_mu_);
    return snapshot_;
  }

  void set_snapshot(std::string domain, std::string cert_pem,
                    std::string key_pem, std::shared_ptr<ssl::context> ssl_ctx) {
    auto snap = std::make_shared<Snapshot>();
    snap->domain = std::move(domain);
    snap->cert_pem = std::move(cert_pem);
    snap->key_pem = std::move(key_pem);
    snap->ssl_ctx = std::move(ssl_ctx);

    std::lock_guard<std::mutex> lock(snapshot_mu_);
    snapshot_ = std::move(snap);
  }

  static bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
      return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
      unsigned char ca = static_cast<unsigned char>(a[i]);
      unsigned char cb = static_cast<unsigned char>(b[i]);
      if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
      if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
      if (ca != cb) return false;
    }
    return true;
  }

  static int sni_cb(SSL* ssl, int* ad, void*) {
    const auto* snap = static_cast<const Snapshot*>(
        SSL_get_ex_data(ssl, sni_ex_index()));
    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (!snap || snap->domain.empty() || !sni || !*sni) {
      if (ad) {
        *ad = SSL_AD_UNRECOGNIZED_NAME;
      }
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (!iequals_ascii(snap->domain, sni)) {
      if (ad) {
        *ad = SSL_AD_UNRECOGNIZED_NAME;
      }
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    return SSL_TLSEXT_ERR_OK;
  }

  static int alpn_select_cb(SSL*, const unsigned char** out,
                            unsigned char* outlen, const unsigned char* in,
                            unsigned int inlen, void*) {
    // Client ALPN list is encoded as repeated: <len><bytes...>
    const unsigned char* p = in;
    unsigned int remaining = inlen;
    while (remaining > 0) {
      const unsigned int len = *p;
      ++p;
      --remaining;
      if (len > remaining) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
      }
      if (len == kAlpnProto.size() &&
          std::memcmp(p, kAlpnProto.data(), kAlpnProto.size()) == 0) {
        *out = p;
        *outlen = static_cast<unsigned char>(len);
        return SSL_TLSEXT_ERR_OK;
      }
      p += len;
      remaining -= len;
    }

    // Enforce: only proceed for acme-tls/1.
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  static monad::Result<std::shared_ptr<ssl::context>, monad::Error>
  make_ssl_context(const std::string& domain, const std::string& cert_pem,
                   const std::string& key_pem) {
    try {
      auto ctx = std::make_shared<ssl::context>(ssl::context::tls_server);
      ctx->set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                       ssl::context::no_sslv3);

      SSL_CTX* native = ctx->native_handle();
      (void)SSL_CTX_set_min_proto_version(native, TLS1_2_VERSION);

      SSL_CTX_set_alpn_select_cb(native, &AcmeTlsAlpn01Server::alpn_select_cb,
                                nullptr);
      SSL_CTX_set_tlsext_servername_callback(native,
                                             &AcmeTlsAlpn01Server::sni_cb);

      ctx->use_certificate_chain(net::buffer(cert_pem.data(), cert_pem.size()));
      ctx->use_private_key(net::buffer(key_pem.data(), key_pem.size()),
                           ssl::context::file_format::pem);

      if (SSL_CTX_check_private_key(native) != 1) {
        return monad::Result<std::shared_ptr<ssl::context>, monad::Error>::Err(
            monad::make_error(my_errors::OPENSSL::UNEXPECTED_RESULT,
                              "ACME TLS-ALPN-01 certificate key mismatch"));
      }

      // Domain is currently only used via SNI callback (per-SSL ex_data).
      (void)domain;

      return monad::Result<std::shared_ptr<ssl::context>, monad::Error>::Ok(
          std::move(ctx));
    } catch (const std::exception& e) {
      return monad::Result<std::shared_ptr<ssl::context>, monad::Error>::Err(
          monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                            std::string("ACME TLS-ALPN-01 failed to load provided certificate/key: ") +
                                e.what()));
    }
  }

  monad::MyVoidResult start_listening() {
    boost::system::error_code ec;
    const auto addr = net::ip::make_address(listen_.bind, ec);
    if (ec) {
      return monad::MyVoidResult::Err(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          std::string("invalid bind address: ") + ec.message()));
    }

    tcp::endpoint ep{addr, listen_.port};
    [[maybe_unused]] const auto open_rc = acceptor_.open(ep.protocol(), ec);
    if (ec) {
      return monad::MyVoidResult::Err(monad::make_error(
          my_errors::GENERAL::CREATE_FAILED,
          std::string("failed to open acceptor: ") + ec.message()));
    }

    [[maybe_unused]] const auto setopt_rc =
      acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if (ec) {
      return monad::MyVoidResult::Err(monad::make_error(
        my_errors::GENERAL::CREATE_FAILED,
        std::string("failed to set reuse_address: ") + ec.message()));
    }

    [[maybe_unused]] const auto bind_rc = acceptor_.bind(ep, ec);
    if (ec) {
      return monad::MyVoidResult::Err(monad::make_error(
          my_errors::GENERAL::CREATE_FAILED,
          std::string("failed to bind: ") + ec.message()));
    }

    [[maybe_unused]] const auto listen_rc =
      acceptor_.listen(net::socket_base::max_listen_connections, ec);
    if (ec) {
      return monad::MyVoidResult::Err(monad::make_error(
          my_errors::GENERAL::CREATE_FAILED,
          std::string("failed to listen: ") + ec.message()));
    }

    actual_port_.store(acceptor_.local_endpoint().port());

    do_accept();
    return monad::MyVoidResult::Ok();
  }

  void start_thread() {
    thread_ = std::thread([this]() {
      try {
        ioc_.run();
      } catch (const std::exception& e) {
        BOOST_LOG_SEV(lg_, trivial::error)
            << "ACME TLS-ALPN-01 server io_context exception: " << e.what();
      }
    });
  }

  void do_accept() {
    if (stopped_.load()) {
      return;
    }

    acceptor_.async_accept(net::make_strand(ioc_),
                           [this](boost::system::error_code ec,
                                  tcp::socket socket) {
                             if (ec) {
                               if (!stopped_.load()) {
                                 BOOST_LOG_SEV(lg_, trivial::debug)
                                     << "ACME TLS-ALPN-01 accept error: "
                                     << ec.message();
                               }
                               return;
                             }

                             auto snap = snapshot();
                             std::make_shared<Session>(std::move(socket),
                                                       std::move(snap))
                                 ->run();

                             do_accept();
                           });
  }

  void schedule_ttl(std::chrono::seconds ttl) {
    if (!ttl_timer_) {
      return;
    }

    ttl_timer_->expires_after(ttl);
    ttl_timer_->async_wait([this](const boost::system::error_code& ec) {
      if (ec == net::error::operation_aborted) {
        return;
      }

      BOOST_LOG_SEV(lg_, trivial::info)
          << "ACME TLS-ALPN-01 server TTL expired; stopping";
      stop();
    });
  }

  static int sni_ex_index() {
    static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return idx;
  }
};

} // namespace certctrl::acme
