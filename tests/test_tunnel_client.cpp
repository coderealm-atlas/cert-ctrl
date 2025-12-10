#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "conf/tunnel_config.hpp"
#include "customio/console_output.hpp"
#include "ioc_manager_config_provider.hpp"
#include "io_context_manager.hpp"
#include "result_monad.hpp"
#include "tunnel/tunnel_client.hpp"
#include "tunnel/tunnel_messages.hpp"

using namespace std::chrono_literals;

namespace net = boost::asio;
namespace ssl = net::ssl;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace http = beast::http;
namespace json = boost::json;
using tcp = net::ip::tcp;

namespace {

unsigned short PickFreePort() {
  net::io_context ioc;
  tcp::acceptor acceptor(ioc, {net::ip::make_address("127.0.0.1"), 0});
  return acceptor.local_endpoint().port();
}

void LoadServerCertificate(ssl::context &ctx) {
  static const char kCert[] =
      "-----BEGIN CERTIFICATE-----\n"
      "MIIDCTCCAfGgAwIBAgIUO6Y9upZo8346IaHlxA1DY2zBZncwDQYJKoZIhvcNAQEL\n"
      "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MTIxMDAwMjk1MloXDTI2MTIx\n"
      "MDAwMjk1MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\n"
      "AAOCAQ8AMIIBCgKCAQEAnYGuglbkiT697EA61trcYoSxNM0X7Wjt0i7vgtpDwoWy\n"
      "vawvwetrBM68me1z4Wm/GJOm7NjtrjmvDww44bH5ZMXzo/NIV2PoWvDd9EOJAZxf\n"
      "NrSkoQS6DU8iLzWdyLjWCpi35toJKz1PDSFL/X5u5k+5HLMKKC0nbcuepIg/MmqS\n"
      "iNaCZ1nhpSo/YM91JLMlhpFZoT3AMExGUS6KwmRbeJuDwgiSkKYBK4r5ioC9gDOD\n"
      "OxpXayOkp00Yw2pHjl6F3i2Edf8BaRmoECodJhvQ4A071sT+Lz++RFvIr7813N8b\n"
      "1WoDjih4630YzNxPn/m73+XkEc610vEy67i1n85huwIDAQABo1MwUTAdBgNVHQ4E\n"
      "FgQUgxvvqfaUCuS/E1QfYUCqer1W++EwHwYDVR0jBBgwFoAUgxvvqfaUCuS/E1Qf\n"
      "YUCqer1W++EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAA9lZ\n"
      "EGFyYwYZpZnpy+d9OCO4uvZQkG4CLjcq72mNJAxpAdDuv/6mPbzGiaoA1ZEeMYBJ\n"
      "Pz8bXfd8NibioJh6RU+qjE/MVG6ZbS8hIpW1OyvjToXgzFCSGnn9Kx2j1HkBcgvM\n"
      "R+MHnSzgFdvRe6Mmugdnwk8vn6aTXgBYaoXP8j/8AxuMJnN53NDGeylxjQPMaV4v\n"
      "+znO817Ekuq/FR+IATtRttKC20BkjdIDR/l7JGxEQ1QArBvwW+8OTvGd4lg5V0YQ\n"
      "9b2WyqUieG3gV6BTkBIVdcDqTWlvHoXOvQipQ8MVlMl++di0ajHJXrPu3M5GV9FF\n"
      "0vFwbcQdLJn31g9Jdw==\n"
      "-----END CERTIFICATE-----\n";

  static const char kKey[] =
      "-----BEGIN PRIVATE KEY-----\n"
      "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdga6CVuSJPr3s\n"
      "QDrW2txihLE0zRftaO3SLu+C2kPChbK9rC/B62sEzryZ7XPhab8Yk6bs2O2uOa8\n"
      "PDDjhsflkxfOj80hXY+ha8N30Q4kBnF82tKShBLoNTyIvNZ3IuNYKmLfm2gkrPU8\n"
      "NIUv9fm7mT7kcswooLSdty56kiD8yapKI1oJnWeGlKj9gz3UksyWGkVmhPcAwTEZ\n"
      "RLorCZFt4m4PCCJKQpgErivmKgL2AM4M7GldrI6SnTRjDakeOXoXeLYR1/wFpGag\n"
      "QKh0mG9DgDTvWxP4vP75EW8ivvzXc3xvVagOOKHjrfRjM3E+f+bvf5eQRzrXS8TL\n"
      "ruLWfzmG7AgMBAAECggEAKwdylUkHxjbNy+0AJhJEguWdQ7+D+efgkLsh062tNUc\n"
      "xPX/8zA10fyu7epHURpCNFDnCMJJS3HYFzSaZo47rgwxRM0kTSkyQ/ccv27tXgok\n"
      "ludw/3X1dFqW3wQ30vRFB6EMwenC2cImfPwcJq4cO5PyCpcSD0dYEH4qxHGHcYfkt\n"
      "hJhaP5kOjlIVz1CqaL9NJ69tRYTH1kGnGnnk63fHlZydYHaF2k1H4dktMM5veotJ\n"
      "ZX80Ncn8gHZ1W49/UWBh3tSHuGNlO97IJO0WAwioTzfcOpvH0HfW3Bv3UpEVuMoE\n"
      "vzOK+4WLGP11P7VHsfqLQfuYXWt6n1PS6e6/dyM8gQKBgQC9CTzxLsKMJ/y3Wtt2\n"
      "3gPM8E0LpIoKsRrH9W8kGVJuY8uj+Q/Z/n35kxij6Q2v+S0ZI5sXmVIkh3g0zB0B\n"
      "EUA1L9icdLbO/TdZ07XZyAyMuztFD7JZK5Ggoa85TuYG0KjMwpfLmgVgLiOUHq9w\n"
      "obUiYfE3vGKWGK2ob2O4x5iGXwKBgQDVTS9uj++q8hK0nU9dT+0H9UHyLWbgznFc\n"
      "GO5PBRXFile5ZHu4GgEbSFwoMLm9jmu0qVU+mrWOndg9KOBzi4kbYzOj37jJ4aVk\n"
      "1PkGgulbIzdgb8t18LJbk8NjeW+ZhBglTfSeOtI+gjQGNTstlpm+X+Nd9qd9mZI1\n"
      "LzX39MTKJQKBgDWtFtnhDirf+9lQejqxZeDeZvIkYXIRwen/XfShIA/qVFuWEBM1\n"
      "OS4Rv5BjT5ilJ1IZEyPLTFDFCrPrNV0lOdcgY+BhH7t8mSfvfpZ9QFsBmx3MDDdX\n"
      "sL0sy+V46sYKn7OsmY+dh2M9FqsrX2Oa9yTxLJ5H5rJ6BW1rW6SPQFb/AoGAO2rU\n"
      "26ecy7HDJCzt/sBU9vKK/DtJfTYEvfLz728rMWvoI+ypyg70X/U4NrncA8G4nwrM\n"
      "hDP0f1XY9rB8VbN47fgkWnHnt9TzjbMF65psBsc4ldSOiLwT8w6mTv905v60+y9M\n"
      "BQe9qUv70f7iDUD2cuGjJHmhDovI/qe4EOpOJ0ECgYAOiSC6noNOSP9ZA+VT7FBy\n"
      "+s7GIXK/86eYlWxRWGlo5dhccplwnb/MRbSd/sB+OvfqWeEkA7Yz7As6zqd/mjli\n"
      "Q9wAhZMcQk4pAxhdMBvc9bYyPZQh1X/UrK6RFK1oT/Wb/DMEjDg3wmQ0RBBtB/oh\n"
      "2dhlPdOSE4nKCxX+9b83mA==\n"
      "-----END PRIVATE KEY-----\n";

  ctx.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                  ssl::context::single_dh_use);
  ctx.use_certificate_chain(net::buffer(kCert, sizeof(kCert)));
  ctx.use_private_key(net::buffer(kKey, sizeof(kKey)),
                      ssl::context::file_format::pem);
}

class TestIocConfigProvider : public cjj365::IIocConfigProvider {
 public:
  explicit TestIocConfigProvider(int threads = 1)
      : config_(threads, "tunnel-ioc-test") {}

  const cjj365::IocConfig &get() const override { return config_; }

 private:
  cjj365::IocConfig config_;
};

class StaticTunnelConfigProvider : public certctrl::ITunnelConfigProvider {
 public:
  explicit StaticTunnelConfigProvider(certctrl::TunnelConfig cfg)
      : config_(std::move(cfg)) {}

  const certctrl::TunnelConfig &get() const override { return config_; }
  certctrl::TunnelConfig &get() override { return config_; }

  monad::MyVoidResult save(const boost::json::object &) override {
    return monad::MyVoidResult::Ok();
  }

 private:
  certctrl::TunnelConfig config_;
};

struct RecordedRequest {
  std::string method;
  std::string target;
  std::string body;
  std::map<std::string, std::string> headers;
};

class TestLocalHttpServer {
 public:
  enum class Mode { Respond, Hang };

  TestLocalHttpServer(unsigned short port, Mode mode = Mode::Respond)
      : port_(port), mode_(mode) {}

  ~TestLocalHttpServer() { Stop(); }

  void Start() {
    running_.store(true);
    server_thread_ = std::thread([this]() { Run(); });
  }

  void Stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
      {
        std::lock_guard<std::mutex> lk(hang_mutex_);
        stop_notified_ = true;
      }
      hang_cv_.notify_all();
      WakeAccept();
      if (server_thread_.joinable()) {
        server_thread_.join();
      }
    }
  }

  void set_response(http::status status, std::string body) {
    response_status_ = status;
    response_body_ = std::move(body);
  }

  void set_hang_duration(std::chrono::milliseconds duration) {
    hang_duration_ = duration;
  }

  std::optional<RecordedRequest> WaitForRequest(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(record_mutex_);
    if (!record_cv_.wait_for(lock, timeout,
                             [this]() { return !recorded_.empty(); })) {
      return std::nullopt;
    }
    auto req = std::move(recorded_.front());
    recorded_.pop_front();
    return req;
  }

  std::size_t RecordedCount() const {
    std::lock_guard<std::mutex> lock(record_mutex_);
    return recorded_.size();
  }

 private:
  void Run() {
    try {
      net::io_context ioc;
      tcp::acceptor acceptor(ioc, {net::ip::make_address("127.0.0.1"), port_});
      while (running_.load()) {
        tcp::socket socket(ioc);
        beast::error_code ec;
        acceptor.accept(socket, ec);
        if (ec) {
          continue;
        }
        beast::flat_buffer buffer;
        http::request<http::string_body> request;
        http::read(socket, buffer, request, ec);
        if (!ec) {
          RecordRequest(request);
          if (mode_ == Mode::Respond) {
            http::response<http::string_body> response{response_status_,
                                                       request.version()};
            response.set(http::field::content_type, "text/plain");
            response.body() = response_body_;
            response.prepare_payload();
            beast::error_code write_ec;
            http::write(socket, response, write_ec);
          } else {
            std::unique_lock<std::mutex> lk(hang_mutex_);
            hang_cv_.wait_for(lk, hang_duration_, [this]() {
              return !running_.load() || stop_notified_;
            });
          }
          beast::error_code shutdown_ec;
          socket.shutdown(tcp::socket::shutdown_both, shutdown_ec);
        }
      }
    } catch (...) {
      // swallow to avoid test flake
    }
  }

  void RecordRequest(const http::request<http::string_body> &req) {
    RecordedRequest rec;
    rec.method = std::string(req.method_string());
    rec.target = std::string(req.target());
    rec.body = req.body();
    for (const auto &field : req) {
      rec.headers.emplace(std::string(field.name_string()),
                          std::string(field.value()));
    }
    {
      std::lock_guard<std::mutex> lock(record_mutex_);
      recorded_.push_back(std::move(rec));
    }
    record_cv_.notify_all();
  }

  void WakeAccept() {
    net::io_context ioc;
    tcp::socket socket(ioc);
    beast::error_code ec;
    socket.connect({net::ip::make_address("127.0.0.1"), port_}, ec);
  }

  unsigned short port_;
  Mode mode_{Mode::Respond};
  http::status response_status_{http::status::ok};
  std::string response_body_{"ok"};
  std::chrono::milliseconds hang_duration_{1500};
  std::atomic<bool> running_{false};
  std::thread server_thread_;

  mutable std::mutex record_mutex_;
  std::condition_variable record_cv_;
  std::deque<RecordedRequest> recorded_;

  std::condition_variable hang_cv_;
  std::mutex hang_mutex_;
  bool stop_notified_{false};
};

class FakeTunnelServer {
 public:
  FakeTunnelServer(unsigned short port, std::vector<certctrl::TunnelRequest> requests,
                   std::size_t expected_responses = 0)
      : port_(port),
        requests_(std::move(requests)),
        expected_responses_(expected_responses ? expected_responses
                                               : requests_.size()) {}

  ~FakeTunnelServer() { Join(); }

  void Start() { server_thread_ = std::thread([this]() { Run(); }); }

  void Join() {
    if (server_thread_.joinable()) {
      server_thread_.join();
    }
  }

  std::vector<certctrl::TunnelResponse> WaitForResponses(
      std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(response_mutex_);
    response_cv_.wait_for(lock, timeout, [this]() {
      return responses_.size() >= expected_responses_ || failed_;
    });
    return responses_;
  }

 private:
  template <typename Ws, typename Message>
  void SendJson(Ws &ws, const Message &message) {
    auto payload = json::serialize(json::value_from(message));
    ws.write(net::buffer(payload));
  }

  void Run() {
    try {
      net::io_context ioc;
      tcp::acceptor acceptor(ioc, {net::ip::make_address("127.0.0.1"), port_});
      tcp::socket socket(ioc);
      acceptor.accept(socket);
          ssl::context ssl_ctx(ssl::context::tls_server);
          LoadServerCertificate(ssl_ctx);
          beast::tcp_stream beast_stream(std::move(socket));
          ssl::stream<beast::tcp_stream> ssl_stream(std::move(beast_stream),
                              ssl_ctx);
          websocket::stream<ssl::stream<beast::tcp_stream>> ws(
            std::move(ssl_stream));
          ws.next_layer().handshake(ssl::stream_base::server);
        ws.accept();
      ws.text(true);

      certctrl::TunnelHello hello;
      hello.tunnel_id = "integration-test";
      hello.local_base_url = "http://127.0.0.1";
      SendJson(ws, hello);
      for (const auto &req : requests_) {
        SendJson(ws, req);
      }

      beast::flat_buffer buffer;
      while (responses_.size() < expected_responses_) {
        buffer.consume(buffer.size());
        beast::error_code ec;
        ws.read(buffer, ec);
        if (ec == websocket::error::closed) {
          break;
        }
        if (ec) {
          throw beast::system_error(ec);
        }
        const auto payload = beast::buffers_to_string(buffer.data());
        auto value = json::parse(payload);
        const auto *obj = value.if_object();
        if (!obj) {
          continue;
        }
        const auto *type_field = obj->if_contains("type");
        if (!type_field || !type_field->is_string()) {
          continue;
        }
        const std::string type = std::string(type_field->as_string().c_str());
        if (type == "response") {
          auto response = json::value_to<certctrl::TunnelResponse>(value);
          {
            std::lock_guard<std::mutex> lock(response_mutex_);
            responses_.push_back(response);
          }
          response_cv_.notify_all();
        } else if (type == "ping") {
          certctrl::TunnelPong pong;
          if (auto *ts = obj->if_contains("ts"); ts && ts->is_uint64()) {
            pong.ts = ts->to_number<std::uint64_t>();
          }
          SendJson(ws, pong);
        }
      }
      beast::error_code ec;
      ws.close(websocket::close_code::normal, ec);
    } catch (...) {
      failed_ = true;
      response_cv_.notify_all();
    }
  }

  unsigned short port_;
  std::vector<certctrl::TunnelRequest> requests_;
  std::size_t expected_responses_{0};
  std::thread server_thread_;

  std::mutex response_mutex_;
  std::condition_variable response_cv_;
  std::vector<certctrl::TunnelResponse> responses_;
  bool failed_{false};
};

certctrl::TunnelConfig MakeBaseConfig(unsigned short tunnel_port,
                                      unsigned short local_port) {
  certctrl::TunnelConfig cfg;
  cfg.enabled = true;
  cfg.verify_tls = false;
  cfg.remote_endpoint =
      "wss://127.0.0.1:" + std::to_string(tunnel_port) + "/api/tunnel";
  cfg.local_base_url =
      "http://127.0.0.1:" + std::to_string(local_port) + "/hooks";
  cfg.request_timeout_seconds = 1;
  cfg.ping_interval_seconds = 1;
  cfg.max_payload_bytes = 64 * 1024;
  cfg.header_allowlist = {"content-type", "stripe-signature"};
  return cfg;
}

certctrl::TunnelRequest MakeRequest(std::string id, std::string path) {
  certctrl::TunnelRequest request;
  request.type = "request";
  request.id = std::move(id);
  request.method = "POST";
  request.path = std::move(path);
  request.headers = {
      {"content-type", "application/json"},
      {"stripe-signature", "sig-v1"},
      {"x-extra", "should-drop"},
  };
  request.body = "{\"ok\":true}";
  return request;
}

} // namespace

TEST(TunnelClientIntegrationTest, ForwardsWebhookEndToEnd) {
  const auto tunnel_port = PickFreePort();
  const auto local_port = PickFreePort();

  TestLocalHttpServer local_server(local_port);
  local_server.set_response(http::status::created, "accepted");
  local_server.Start();

  std::vector<certctrl::TunnelRequest> requests;
  requests.emplace_back(MakeRequest("req-forward", "/stripe"));
  FakeTunnelServer tunnel_server(tunnel_port, requests);
  tunnel_server.Start();

  auto cfg = MakeBaseConfig(tunnel_port, local_port);
  StaticTunnelConfigProvider config_provider(cfg);
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  certctrl::TunnelClient client(io_manager, config_provider, console);
  client.Start();

  auto recorded = local_server.WaitForRequest(3s);
  ASSERT_TRUE(recorded.has_value()) << "local webhook was not observed";
  EXPECT_EQ(recorded->method, "POST");
  EXPECT_EQ(recorded->target, "/hooks/stripe");
  EXPECT_EQ(recorded->body, "{\"ok\":true}");
  EXPECT_TRUE(recorded->headers.count("content-type"));
  EXPECT_TRUE(recorded->headers.count("stripe-signature"));
  EXPECT_FALSE(recorded->headers.count("x-extra"));

  auto responses = tunnel_server.WaitForResponses(5s);
  ASSERT_EQ(responses.size(), 1u);
  EXPECT_EQ(responses[0].id, "req-forward");
  EXPECT_EQ(responses[0].status, 201);
  EXPECT_EQ(responses[0].body, "accepted");

  client.Stop();
  tunnel_server.Join();
  local_server.Stop();
}

TEST(TunnelClientIntegrationTest, ReportsTimeoutWhenLocalEndpointHangs) {
  const auto tunnel_port = PickFreePort();
  const auto local_port = PickFreePort();

  TestLocalHttpServer local_server(local_port, TestLocalHttpServer::Mode::Hang);
  local_server.set_hang_duration(1500ms);
  local_server.Start();

  std::vector<certctrl::TunnelRequest> requests;
  requests.emplace_back(MakeRequest("req-timeout", "/slow"));
  FakeTunnelServer tunnel_server(tunnel_port, requests);
  tunnel_server.Start();

  auto cfg = MakeBaseConfig(tunnel_port, local_port);
  cfg.request_timeout_seconds = 1;
  StaticTunnelConfigProvider config_provider(cfg);
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  certctrl::TunnelClient client(io_manager, config_provider, console);
  client.Start();

  auto recorded = local_server.WaitForRequest(3s);
  ASSERT_TRUE(recorded.has_value()) << "local webhook missing";

  auto responses = tunnel_server.WaitForResponses(5s);
  ASSERT_EQ(responses.size(), 1u);
  EXPECT_EQ(responses[0].id, "req-timeout");
  EXPECT_EQ(responses[0].status, 504);
  EXPECT_NE(responses[0].body.find("timeout"), std::string::npos);

  client.Stop();
  tunnel_server.Join();
  local_server.Stop();
}
