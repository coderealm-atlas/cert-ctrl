#include <gtest/gtest.h>

#include "data/data_shape.hpp"
#include "handlers/signal_handlers/config_updated_handler.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/json.hpp>

#include <jwt-cpp/jwt.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <filesystem>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "conf/certctrl_config.hpp"
#include "conf/websocket_config.hpp"
#include "customio/console_output.hpp"
#include "ioc_manager_config_provider.hpp"
#include "io_context_manager.hpp"
#include "result_monad.hpp"
#include "simple_data.hpp"
#include "state/device_state_store.hpp"
#include "websocket/websocket_client.hpp"
#include "websocket/websocket_messages.hpp"

using namespace std::chrono_literals;

namespace net = boost::asio;
namespace ssl = net::ssl;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace http = beast::http;
namespace json = boost::json;
using tcp = net::ip::tcp;

namespace {

class InMemoryDeviceStateStore : public certctrl::IDeviceStateStore {
 public:
  std::optional<std::string> get_access_token() const override {
    return access_token_;
  }
  std::optional<std::string> get_refresh_token() const override {
    return refresh_token_;
  }
  std::optional<std::string>
  save_tokens(const std::optional<std::string> &access_token,
              const std::optional<std::string> &refresh_token,
              std::optional<int> expires_in = std::nullopt) override {
    access_token_ = access_token;
    refresh_token_ = refresh_token;
    expires_in_ = expires_in;
    return std::nullopt;
  }
  std::optional<std::string> clear_tokens() override {
    access_token_.reset();
    refresh_token_.reset();
    expires_in_.reset();
    return std::nullopt;
  }

  std::optional<std::string> get_device_public_id() const override {
    return device_public_id_;
  }
  std::optional<std::string> get_device_fingerprint_hex() const override {
    return device_fingerprint_hex_;
  }
  std::optional<std::string>
  save_device_identity(const std::optional<std::string> &device_public_id,
                       const std::optional<std::string> &fingerprint_hex) override {
    device_public_id_ = device_public_id;
    device_fingerprint_hex_ = fingerprint_hex;
    return std::nullopt;
  }
  std::optional<std::string> clear_device_identity() override {
    device_public_id_.reset();
    device_fingerprint_hex_.reset();
    return std::nullopt;
  }

  std::optional<std::string> get_install_config_json() const override {
    return install_config_json_;
  }
  std::optional<std::int64_t> get_install_config_version() const override {
    return install_config_version_;
  }
  std::optional<std::string>
  save_install_config(const std::optional<std::string> &serialized_json,
                      std::optional<std::int64_t> version) override {
    install_config_json_ = serialized_json;
    install_config_version_ = version;
    return std::nullopt;
  }
  std::optional<std::string> clear_install_config() override {
    install_config_json_.reset();
    install_config_version_.reset();
    return std::nullopt;
  }

  std::optional<std::string> get_updates_cursor() const override {
    return updates_cursor_;
  }
  std::optional<std::string>
  save_updates_cursor(const std::optional<std::string> &cursor) override {
    updates_cursor_ = cursor;
    return std::nullopt;
  }

  std::optional<std::string> get_websocket_resume_token() const override {
    return websocket_resume_token_;
  }
  std::optional<std::string> save_websocket_resume_token(
      const std::optional<std::string> &resume_token) override {
    websocket_resume_token_ = resume_token;
    return std::nullopt;
  }

  std::optional<std::string> get_processed_signals_json() const override {
    return processed_signals_json_;
  }
  std::optional<std::string> save_processed_signals_json(
      const std::optional<std::string> &serialized_json) override {
    processed_signals_json_ = serialized_json;
    return std::nullopt;
  }

  std::optional<std::string> get_imported_ca_name(
      std::int64_t ca_id) const override {
    if (auto it = imported_ca_names_.find(ca_id);
        it != imported_ca_names_.end()) {
      return it->second;
    }
    return std::nullopt;
  }
  std::optional<std::string>
  set_imported_ca_name(std::int64_t ca_id,
                       const std::optional<std::string> &canonical_name) override {
    if (canonical_name) {
      imported_ca_names_[ca_id] = *canonical_name;
    } else {
      imported_ca_names_.erase(ca_id);
    }
    return std::nullopt;
  }
  std::optional<std::string> clear_imported_ca_name(std::int64_t ca_id) override {
    imported_ca_names_.erase(ca_id);
    return std::nullopt;
  }

  std::pair<bool, std::optional<std::string>>
  try_acquire_refresh_lock(const std::string &, std::chrono::milliseconds) override {
    return {true, std::nullopt};
  }
  std::optional<std::string> release_refresh_lock(const std::string &) override {
    return std::nullopt;
  }

  bool available() const override { return true; }

 private:
  std::optional<std::string> access_token_;
  std::optional<std::string> refresh_token_;
  std::optional<int> expires_in_;

  std::optional<std::string> device_public_id_;
  std::optional<std::string> device_fingerprint_hex_;

  std::optional<std::string> install_config_json_;
  std::optional<std::int64_t> install_config_version_;

  std::optional<std::string> updates_cursor_;
  std::optional<std::string> websocket_resume_token_;
  std::optional<std::string> processed_signals_json_;
  std::unordered_map<std::int64_t, std::string> imported_ca_names_;
};

// ConfigSources is designed to be instantiated once per process.
// Keep a shared instance for this test binary.
cjj365::ConfigSources &TestConfigSources() {
  static const std::filesystem::path dir = []() {
    auto base = std::filesystem::temp_directory_path() / "certctrl-test-config";
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    return base;
  }();
  static cjj365::ConfigSources sources({dir}, {});
  return sources;
}

unsigned short PickFreePort() {
  net::io_context ioc;
  tcp::acceptor acceptor(ioc, {net::ip::make_address("127.0.0.1"), 0});
  return acceptor.local_endpoint().port();
}

static const char kTestServerCertPem[] =
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

static const char kTestServerKeyPem[] =
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

static std::string TestServerCertPem() { return std::string(kTestServerCertPem); }
static std::string TestServerKeyPem() { return std::string(kTestServerKeyPem); }

void LoadServerCertificate(ssl::context &ctx) {
  ctx.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                  ssl::context::single_dh_use);
  ctx.use_certificate_chain(net::buffer(kTestServerCertPem, sizeof(kTestServerCertPem)));
  ctx.use_private_key(net::buffer(kTestServerKeyPem, sizeof(kTestServerKeyPem)),
                      ssl::context::file_format::pem);
}

class TestIocConfigProvider : public cjj365::IIocConfigProvider {
 public:
  explicit TestIocConfigProvider(int threads = 1)
      : config_(threads, "websocket-ioc-test") {}

  const cjj365::IocConfig &get() const override { return config_; }

 private:
  cjj365::IocConfig config_;
};

class StaticWebsocketConfigProvider : public certctrl::IWebsocketConfigProvider {
 public:
  explicit StaticWebsocketConfigProvider(certctrl::WebsocketConfig cfg)
      : config_(std::move(cfg)) {}

  const certctrl::WebsocketConfig &get() const override { return config_; }
  certctrl::WebsocketConfig &get() override { return config_; }

  monad::MyVoidResult save(const boost::json::object &) override {
    return monad::MyVoidResult::Ok();
  }

  monad::MyVoidResult save_replace(const boost::json::object &content) override {
    saved_replace_ = content;
    return monad::MyVoidResult::Ok();
  }

  const boost::json::object &saved_replace() const { return saved_replace_; }

 private:
  certctrl::WebsocketConfig config_;
  boost::json::object saved_replace_;
};

class StaticCertctrlConfigProvider : public certctrl::ICertctrlConfigProvider {
 public:
  explicit StaticCertctrlConfigProvider(certctrl::CertctrlConfig cfg = {})
      : config_(std::move(cfg)) {}

  const certctrl::CertctrlConfig &get() const override { return config_; }
  certctrl::CertctrlConfig &get() override { return config_; }

  monad::MyVoidResult save(const boost::json::object &content) override {
    for (const auto &kv : content) {
      saved_[kv.key()] = kv.value();
    }
    return monad::MyVoidResult::Ok();
  }

  monad::MyVoidResult save_replace(const boost::json::object &content) override {
    saved_.clear();
    for (const auto &kv : content) {
      saved_[kv.key()] = kv.value();
    }
    return monad::MyVoidResult::Ok();
  }

  const boost::json::object &saved() const { return saved_; }

 private:
  certctrl::CertctrlConfig config_;
  boost::json::object saved_;
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
        auto accepted = acceptor.accept(socket, ec);
        (void)accepted;
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
          auto shut = socket.shutdown(tcp::socket::shutdown_both, shutdown_ec);
          (void)shut;
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
    auto connected =
      socket.connect({net::ip::make_address("127.0.0.1"), port_}, ec);
    (void)connected;
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

class FakeWebsocketServer {
 public:
  FakeWebsocketServer(unsigned short port, std::vector<certctrl::WebsocketRequest> requests,
                   std::size_t expected_responses = 0)
      : port_(port),
        requests_(std::move(requests)),
        expected_responses_(expected_responses ? expected_responses
                                               : requests_.size()) {}

  ~FakeWebsocketServer() { Join(); }

  void Start() { server_thread_ = std::thread([this]() { Run(); }); }

  void Join() {
    if (server_thread_.joinable()) {
      server_thread_.join();
    }
  }

  std::vector<certctrl::WebsocketResponse> WaitForResponses(
      std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(response_mutex_);
    response_cv_.wait_for(lock, timeout, [this]() {
      return responses_.size() >= expected_responses_ || failed_;
    });
    return responses_;
  }

  void set_extra_messages(std::vector<json::value> messages) {
    extra_messages_ = std::move(messages);
  }

  void set_deferred_messages_after_hello_ack(std::vector<json::value> messages) {
    deferred_messages_after_hello_ack_ = std::move(messages);
  }

  void set_expected_message_count(std::size_t count) {
    expected_messages_ = count;
  }

  std::vector<json::value> WaitForMessages(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(response_mutex_);
    response_cv_.wait_for(lock, timeout, [this]() {
      return (expected_messages_ > 0 && messages_.size() >= expected_messages_) ||
             (expected_responses_ > 0 && responses_.size() >= expected_responses_) ||
             failed_;
    });
    return messages_;
  }

 private:
  template <typename Ws, typename Message>
  void SendJson(Ws &ws, const Message &message) {
    auto payload = json::serialize(json::value_from(message));
    ws.write(net::buffer(payload));
  }

  template <typename Ws>
  void SendJsonValue(Ws &ws, const json::value &value) {
    auto payload = json::serialize(value);
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

      certctrl::WebsocketHello hello;
      hello.connection_id = "integration-test";
      SendJson(ws, hello);

      for (const auto &msg : extra_messages_) {
        SendJsonValue(ws, msg);
      }
      for (const auto &req : requests_) {
        SendJson(ws, req);
      }

      beast::flat_buffer buffer;
      while ((expected_responses_ > 0 && responses_.size() < expected_responses_) ||
             (expected_messages_ > 0 && messages_.size() < expected_messages_)) {
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

        {
          std::lock_guard<std::mutex> lock(response_mutex_);
          messages_.push_back(value);
        }
        response_cv_.notify_all();

        const auto *type_field = obj->if_contains("type");
        if (!type_field || !type_field->is_string()) {
          continue;
        }
        const std::string type = std::string(type_field->as_string().c_str());
        if (!deferred_messages_after_hello_ack_.empty() && !deferred_sent_ &&
            type == "event") {
          const auto *name_field = obj->if_contains("name");
          if (name_field && name_field->is_string()) {
            const std::string name =
                std::string(name_field->as_string().c_str());
            if (name == "lifecycle.hello_ack") {
              for (const auto &deferred : deferred_messages_after_hello_ack_) {
                SendJsonValue(ws, deferred);
              }
              deferred_sent_ = true;
            }
          }
        }
        if (type == "response") {
          auto response = json::value_to<certctrl::WebsocketResponse>(value);
          {
            std::lock_guard<std::mutex> lock(response_mutex_);
            responses_.push_back(response);
          }
          response_cv_.notify_all();
        } else if (type == "ping") {
          certctrl::WebsocketPong pong;
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
  std::vector<certctrl::WebsocketRequest> requests_;
  std::size_t expected_responses_{0};
  std::thread server_thread_;

  std::mutex response_mutex_;
  std::condition_variable response_cv_;
  std::vector<certctrl::WebsocketResponse> responses_;
  std::vector<json::value> messages_;
  std::vector<json::value> extra_messages_;
  std::vector<json::value> deferred_messages_after_hello_ack_;
  bool deferred_sent_{false};
  std::size_t expected_messages_{0};
  bool failed_{false};
};

certctrl::WebsocketConfig MakeBaseConfig(unsigned short websocket_port,
                                      unsigned short local_port) {
  certctrl::WebsocketConfig cfg;
  cfg.enabled = true;
  cfg.verify_tls = false;
  cfg.remote_endpoint =
      "wss://127.0.0.1:" + std::to_string(websocket_port) + "/api/websocket";
  cfg.tunnel.local_base_url =
      "http://127.0.0.1:" + std::to_string(local_port) + "/hooks";
  cfg.request_timeout_seconds = 1;
  cfg.ping_interval_seconds = 1;
  cfg.max_payload_bytes = 64 * 1024;
  cfg.tunnel.header_allowlist = {"content-type", "stripe-signature"};
  return cfg;
}

certctrl::WebsocketRequest MakeRequest(std::string id, std::string path) {
  certctrl::WebsocketRequest request;
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

std::string MakeTestJwtWithDeviceId(std::int64_t device_id) {
  return jwt::create()
      .set_type("JWT")
    .set_payload_claim(
      "device_id",
      jwt::claim(jwt::traits::kazuho_picojson::value_type(
        static_cast<double>(device_id))))
      .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(24))
      .sign(jwt::algorithm::none{});
}

} // namespace

TEST(WebsocketClientIntegrationTest, ForwardsWebhookEndToEnd) {
  const auto websocket_port = PickFreePort();
  const auto local_port = PickFreePort();

  TestLocalHttpServer local_server(local_port);
  local_server.set_response(http::status::created, "accepted");
  local_server.Start();

  std::vector<certctrl::WebsocketRequest> requests;
  requests.emplace_back(MakeRequest("req-forward", "/stripe"));
  FakeWebsocketServer websocket_server(websocket_port, requests);
  websocket_server.Start();

  auto cfg = MakeBaseConfig(websocket_port, local_port);
  StaticWebsocketConfigProvider config_provider(cfg);
  StaticCertctrlConfigProvider certctrl_config_provider;
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  InMemoryDeviceStateStore state_store;
  state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;
  certctrl::WebsocketClient client(io_manager, config_provider,
                                  certctrl_config_provider, console,
                                  TestConfigSources(), state_store,
                                  install_config_manager,
                                  std::shared_ptr<certctrl::ISessionRefresher>{});
  client.Start();

  auto recorded = local_server.WaitForRequest(3s);
  ASSERT_TRUE(recorded.has_value()) << "local webhook was not observed";
  EXPECT_EQ(recorded->method, "POST");
  EXPECT_EQ(recorded->target, "/hooks/stripe");
  EXPECT_EQ(recorded->body, "{\"ok\":true}");
  EXPECT_TRUE(recorded->headers.count("content-type"));
  EXPECT_TRUE(recorded->headers.count("stripe-signature"));
  EXPECT_FALSE(recorded->headers.count("x-extra"));

  auto responses = websocket_server.WaitForResponses(5s);
  ASSERT_EQ(responses.size(), 1u);
  EXPECT_EQ(responses[0].id, "req-forward");
  EXPECT_EQ(responses[0].status, 201);
  EXPECT_EQ(responses[0].body, "accepted");

  client.Stop();
  websocket_server.Join();
  local_server.Stop();
}

TEST(WebsocketClientIntegrationTest, ReportsTimeoutWhenLocalEndpointHangs) {
  const auto websocket_port = PickFreePort();
  const auto local_port = PickFreePort();

  TestLocalHttpServer local_server(local_port, TestLocalHttpServer::Mode::Hang);
  local_server.set_hang_duration(1500ms);
  local_server.Start();

  std::vector<certctrl::WebsocketRequest> requests;
  requests.emplace_back(MakeRequest("req-timeout", "/slow"));
  FakeWebsocketServer websocket_server(websocket_port, requests);
  websocket_server.Start();

  auto cfg = MakeBaseConfig(websocket_port, local_port);
  cfg.request_timeout_seconds = 1;
  StaticWebsocketConfigProvider config_provider(cfg);
  StaticCertctrlConfigProvider certctrl_config_provider;
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  InMemoryDeviceStateStore state_store;
  state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;
  certctrl::WebsocketClient client(io_manager, config_provider,
                                  certctrl_config_provider, console,
                                  TestConfigSources(), state_store,
                                  install_config_manager,
                                  std::shared_ptr<certctrl::ISessionRefresher>{});
  client.Start();

  auto recorded = local_server.WaitForRequest(3s);
  ASSERT_TRUE(recorded.has_value()) << "local webhook missing";

  auto responses = websocket_server.WaitForResponses(5s);
  ASSERT_EQ(responses.size(), 1u);
  EXPECT_EQ(responses[0].id, "req-timeout");
  EXPECT_EQ(responses[0].status, 504);
  EXPECT_NE(responses[0].body.find("timeout"), std::string::npos);

  client.Stop();
  websocket_server.Join();
  local_server.Stop();
}

  TEST(WebsocketClientIntegrationTest, RoutesMatchStrippedButFallbackKeepsIngressPrefix) {
    const auto websocket_port = PickFreePort();
    const auto local_port = PickFreePort();

    TestLocalHttpServer local_server(local_port);
    local_server.set_response(http::status::ok, "ok");
    local_server.Start();

    std::vector<certctrl::WebsocketRequest> requests;
    requests.emplace_back(
      MakeRequest("req-route", "/hooks/integration-test/stripe/any/depth?x=1"));
    requests.emplace_back(
      MakeRequest("req-fallback", "/hooks/integration-test/unmatched?y=2"));
    FakeWebsocketServer websocket_server(websocket_port, requests);
    websocket_server.Start();

    auto cfg = MakeBaseConfig(websocket_port, local_port);
    cfg.tunnel.local_base_url =
      "http://127.0.0.1:" + std::to_string(local_port) + "/fallback";

    certctrl::WebsocketConfig::RouteRule rule;
    rule.match_prefix = "/stripe";
    rule.local_base_url =
      "http://127.0.0.1:" + std::to_string(local_port) + "/routed";
    rule.rewrite_prefix = "";
    cfg.tunnel.routes.push_back(std::move(rule));

    StaticWebsocketConfigProvider config_provider(cfg);
    StaticCertctrlConfigProvider certctrl_config_provider;
    TestIocConfigProvider ioc_provider(1);
    customio::ConsoleOutputWithColor logger(5);
    customio::ConsoleOutput console(logger);
    cjj365::IoContextManager io_manager(ioc_provider, logger);
    InMemoryDeviceStateStore state_store;
        state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
    std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;
    certctrl::WebsocketClient client(io_manager, config_provider,
            certctrl_config_provider, console,
                    TestConfigSources(), state_store,
            install_config_manager,
            std::shared_ptr<certctrl::ISessionRefresher>{});
    client.Start();

    auto rec1 = local_server.WaitForRequest(3s);
    ASSERT_TRUE(rec1.has_value()) << "first local webhook missing";
    auto rec2 = local_server.WaitForRequest(3s);
    ASSERT_TRUE(rec2.has_value()) << "second local webhook missing";

    const std::string t1 = rec1->target;
    const std::string t2 = rec2->target;

    const bool saw_routed =
      (t1 == "/routed/any/depth?x=1") || (t2 == "/routed/any/depth?x=1");
    const bool saw_fallback = (t1 == "/fallback/hooks/integration-test/unmatched?y=2") ||
                (t2 == "/fallback/hooks/integration-test/unmatched?y=2");

    EXPECT_TRUE(saw_routed) << "did not observe routed target";
    EXPECT_TRUE(saw_fallback) << "did not observe fallback target";

    auto responses = websocket_server.WaitForResponses(5s);
    ASSERT_EQ(responses.size(), 2u);

    client.Stop();
    websocket_server.Join();
    local_server.Stop();
  }

TEST(WebsocketClientIntegrationTest, SendsHelloAckAndUpdatesAckWithResumeToken) {
  const auto websocket_port = PickFreePort();
  const auto local_port = PickFreePort();

  std::vector<certctrl::WebsocketRequest> requests;
  FakeWebsocketServer websocket_server(websocket_port, requests, 0);

  certctrl::WebsocketEventEnvelope signal;
  signal.name = "updates.signal";
  signal.id = "upd-1";
  signal.resume_token = "rt-1";
  signal.payload = json::object{{"type", "install.updated"},
                               {"ts_ms", 1736900123421},
                               {"ref", json::object{}}};
  websocket_server.set_extra_messages({json::value_from(signal)});
  websocket_server.set_expected_message_count(2);
  websocket_server.Start();

  auto cfg = MakeBaseConfig(websocket_port, local_port);
  cfg.ping_interval_seconds = 60;
  StaticWebsocketConfigProvider config_provider(cfg);
  StaticCertctrlConfigProvider certctrl_config_provider;
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  InMemoryDeviceStateStore state_store;
  state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;
  certctrl::WebsocketClient client(io_manager, config_provider,
                                  certctrl_config_provider, console,
                                  TestConfigSources(), state_store,
                                  install_config_manager,
                                  std::shared_ptr<certctrl::ISessionRefresher>{});
  client.Start();

  auto messages = websocket_server.WaitForMessages(5s);

  bool saw_hello_ack = false;
  bool saw_updates_ack = false;
  for (const auto &msg : messages) {
    const auto *obj = msg.if_object();
    if (!obj) {
      continue;
    }
    const auto *type_field = obj->if_contains("type");
    if (!type_field || !type_field->is_string()) {
      continue;
    }
    if (type_field->as_string() != "event") {
      continue;
    }
    const auto *name_field = obj->if_contains("name");
    if (!name_field || !name_field->is_string()) {
      continue;
    }
    const std::string name = std::string(name_field->as_string().c_str());
    if (name == "lifecycle.hello_ack") {
      saw_hello_ack = true;
      const auto *payload = obj->if_contains("payload");
      ASSERT_TRUE(payload && payload->is_object());
      const auto &payload_obj = payload->as_object();
      const auto *conn_id = payload_obj.if_contains("connection_id");
      ASSERT_TRUE(conn_id && conn_id->is_string());
      EXPECT_EQ(std::string(conn_id->as_string().c_str()), "integration-test");
    } else if (name == "updates.ack") {
      saw_updates_ack = true;
      const auto *id_field = obj->if_contains("id");
      ASSERT_TRUE(id_field && id_field->is_string());
      EXPECT_EQ(std::string(id_field->as_string().c_str()), "upd-1");

      const auto *token_field = obj->if_contains("resume_token");
      ASSERT_TRUE(token_field && token_field->is_string());
      EXPECT_EQ(std::string(token_field->as_string().c_str()), "rt-1");
    }
  }

  EXPECT_TRUE(saw_hello_ack) << "did not observe lifecycle.hello_ack";
  EXPECT_TRUE(saw_updates_ack) << "did not observe updates.ack";

  client.Stop();
  websocket_server.Join();
}

TEST(WebsocketClientIntegrationTest, SendsHelloAckWithStoredResumeTokenAndPersistsNewToken) {
  const auto websocket_port = PickFreePort();
  const auto local_port = PickFreePort();

  std::vector<certctrl::WebsocketRequest> requests;
  FakeWebsocketServer websocket_server(websocket_port, requests, 0);
  websocket_server.set_expected_message_count(2);

  certctrl::WebsocketEventEnvelope signal;
  signal.name = "updates.signal";
  signal.id = "upd-2";
  signal.resume_token = "rt-2";
  signal.payload = json::object{{"type", "install.updated"},
                               {"ts_ms", 1736900123422},
                               {"ref", json::object{}}};
  websocket_server.set_deferred_messages_after_hello_ack({json::value_from(signal)});
  websocket_server.Start();

  auto cfg = MakeBaseConfig(websocket_port, local_port);
  cfg.ping_interval_seconds = 60;
  StaticWebsocketConfigProvider config_provider(cfg);
  StaticCertctrlConfigProvider certctrl_config_provider;
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  InMemoryDeviceStateStore state_store;
  state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
  ASSERT_FALSE(state_store.save_websocket_resume_token(std::string("rt-seed")));
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;
  certctrl::WebsocketClient client(io_manager, config_provider,
                                  certctrl_config_provider, console,
                                  TestConfigSources(), state_store,
                                  install_config_manager,
                                  std::shared_ptr<certctrl::ISessionRefresher>{});
  client.Start();

  const auto messages = websocket_server.WaitForMessages(5s);

  bool saw_hello_ack = false;
  bool saw_updates_ack = false;
  for (const auto &msg : messages) {
    const auto *obj = msg.if_object();
    if (!obj) {
      continue;
    }
    const auto *type_field = obj->if_contains("type");
    if (!type_field || !type_field->is_string() || type_field->as_string() != "event") {
      continue;
    }
    const auto *name_field = obj->if_contains("name");
    if (!name_field || !name_field->is_string()) {
      continue;
    }
    const std::string name = std::string(name_field->as_string().c_str());
    if (name == "lifecycle.hello_ack") {
      saw_hello_ack = true;
      const auto *payload = obj->if_contains("payload");
      ASSERT_TRUE(payload && payload->is_object());
      const auto &payload_obj = payload->as_object();
      const auto *conn_id = payload_obj.if_contains("connection_id");
      ASSERT_TRUE(conn_id && conn_id->is_string());
      EXPECT_EQ(std::string(conn_id->as_string().c_str()), "integration-test");

      const auto *token_field = obj->if_contains("resume_token");
      ASSERT_TRUE(token_field && token_field->is_string());
      EXPECT_EQ(std::string(token_field->as_string().c_str()), "rt-seed");
    } else if (name == "updates.ack") {
      saw_updates_ack = true;
      const auto *id_field = obj->if_contains("id");
      ASSERT_TRUE(id_field && id_field->is_string());
      EXPECT_EQ(std::string(id_field->as_string().c_str()), "upd-2");

      const auto *token_field = obj->if_contains("resume_token");
      ASSERT_TRUE(token_field && token_field->is_string());
      EXPECT_EQ(std::string(token_field->as_string().c_str()), "rt-2");
    }
  }

  EXPECT_TRUE(saw_hello_ack) << "did not observe lifecycle.hello_ack";
  EXPECT_TRUE(saw_updates_ack) << "did not observe updates.ack";

  EXPECT_EQ(state_store.get_websocket_resume_token(), std::optional<std::string>("rt-2"));

  client.Stop();
  websocket_server.Join();
}

TEST(WebsocketClientIntegrationTest, AppliesConfigUpdatedReplaceAndAcks) {
  const auto websocket_port = PickFreePort();
  const auto local_port = PickFreePort();

  std::vector<certctrl::WebsocketRequest> requests;
  FakeWebsocketServer websocket_server(websocket_port, requests, 0);
  websocket_server.set_expected_message_count(2);

  certctrl::WebsocketEventEnvelope signal;
  signal.name = "updates.signal";
  signal.id = "cfg-1";
  signal.resume_token = "rt-cfg-1";
  signal.payload = json::object{{"type", "config.updated"},
                               {"ts_ms", 1736900123999},
                               {"ref",
                                json::object{{"replace",
                                              json::array{json::object{{"file", "application"},
                                                                       {"content", json::object{{"auto_apply_config", true},
                                                                                                {"verbose", "debug"}}}}}}}}};
  websocket_server.set_deferred_messages_after_hello_ack({json::value_from(signal)});
  websocket_server.Start();

  auto cfg = MakeBaseConfig(websocket_port, local_port);
  cfg.ping_interval_seconds = 60;
  StaticWebsocketConfigProvider config_provider(cfg);

  certctrl::CertctrlConfig base;
  base.auto_apply_config = false;
  base.verbose = "info";
  StaticCertctrlConfigProvider certctrl_config_provider(base);

  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  InMemoryDeviceStateStore state_store;
  state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;

  certctrl::WebsocketClient client(io_manager, config_provider,
                                  certctrl_config_provider, console,
                                  TestConfigSources(), state_store,
                                  install_config_manager,
                                  std::shared_ptr<certctrl::ISessionRefresher>{});
  client.Start();

  auto messages = websocket_server.WaitForMessages(5s);

  bool saw_updates_ack = false;
  for (const auto &msg : messages) {
    const auto *obj = msg.if_object();
    if (!obj) {
      continue;
    }
    const auto *type_field = obj->if_contains("type");
    if (!type_field || !type_field->is_string() || type_field->as_string() != "event") {
      continue;
    }
    const auto *name_field = obj->if_contains("name");
    if (!name_field || !name_field->is_string()) {
      continue;
    }
    if (std::string(name_field->as_string().c_str()) == "updates.ack") {
      saw_updates_ack = true;
      const auto *id_field = obj->if_contains("id");
      ASSERT_TRUE(id_field && id_field->is_string());
      EXPECT_EQ(std::string(id_field->as_string().c_str()), "cfg-1");
    }
  }

  EXPECT_TRUE(saw_updates_ack) << "did not observe updates.ack";
  EXPECT_EQ(state_store.get_websocket_resume_token().value_or(""), "rt-cfg-1");
  EXPECT_TRUE(certctrl_config_provider.get().auto_apply_config);
  EXPECT_EQ(certctrl_config_provider.get().verbose, "debug");
  EXPECT_TRUE(certctrl_config_provider.saved().if_contains("auto_apply_config"));
  EXPECT_TRUE(certctrl_config_provider.saved().if_contains("verbose"));

  client.Stop();
  websocket_server.Join();
}

TEST(WebsocketClientIntegrationTest, AcksMultipleUpdateSignalsAndPersistsLatestResumeToken) {
  const auto websocket_port = PickFreePort();
  const auto local_port = PickFreePort();

  std::vector<certctrl::WebsocketRequest> requests;
  FakeWebsocketServer websocket_server(websocket_port, requests, 0);
  websocket_server.set_expected_message_count(3);

  certctrl::WebsocketEventEnvelope s1;
  s1.name = "updates.signal";
  s1.id = "upd-a";
  s1.resume_token = "rt-a";
  s1.payload = json::object{{"type", "install.updated"},
                            {"ts_ms", 1736900123430},
                            {"ref", json::object{}}};

  certctrl::WebsocketEventEnvelope s2;
  s2.name = "updates.signal";
  s2.id = "upd-b";
  s2.resume_token = "rt-b";
  s2.payload = json::object{{"type", "install.updated"},
                            {"ts_ms", 1736900123431},
                            {"ref", json::object{}}};

  websocket_server.set_deferred_messages_after_hello_ack(
      {json::value_from(s1), json::value_from(s2)});
  websocket_server.Start();

  auto cfg = MakeBaseConfig(websocket_port, local_port);
  cfg.ping_interval_seconds = 60;
  StaticWebsocketConfigProvider config_provider(cfg);
  StaticCertctrlConfigProvider certctrl_config_provider;
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  InMemoryDeviceStateStore state_store;
  state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;
  certctrl::WebsocketClient client(io_manager, config_provider,
                                  certctrl_config_provider, console,
                                  TestConfigSources(), state_store,
                                  install_config_manager,
                                  std::shared_ptr<certctrl::ISessionRefresher>{});
  client.Start();

  auto messages = websocket_server.WaitForMessages(5s);

  std::unordered_map<std::string, std::string> acks;
  bool saw_hello_ack = false;

  for (const auto &msg : messages) {
    const auto *obj = msg.if_object();
    if (!obj) {
      continue;
    }
    const auto *type_field = obj->if_contains("type");
    if (!type_field || !type_field->is_string() || type_field->as_string() != "event") {
      continue;
    }
    const auto *name_field = obj->if_contains("name");
    if (!name_field || !name_field->is_string()) {
      continue;
    }
    const std::string name = std::string(name_field->as_string().c_str());
    if (name == "lifecycle.hello_ack") {
      saw_hello_ack = true;
      continue;
    }
    if (name == "updates.ack") {
      const auto *id_field = obj->if_contains("id");
      const auto *token_field = obj->if_contains("resume_token");
      if (!id_field || !id_field->is_string() || !token_field ||
          !token_field->is_string()) {
        continue;
      }
      acks.emplace(std::string(id_field->as_string().c_str()),
                   std::string(token_field->as_string().c_str()));
    }
  }

  EXPECT_TRUE(saw_hello_ack) << "did not observe lifecycle.hello_ack";
  ASSERT_EQ(acks.size(), 2u) << "did not observe both updates.ack";
  EXPECT_EQ(acks.at("upd-a"), "rt-a");
  EXPECT_EQ(acks.at("upd-b"), "rt-b");
  EXPECT_EQ(state_store.get_websocket_resume_token(),
            std::optional<std::string>("rt-b"));

  client.Stop();
  websocket_server.Join();
}

TEST(ConfigUpdatedHandlerTest, AppliesWebsocketReplacePersistsSnapshotAndCallsCallback) {
  certctrl::CertctrlConfig base;
  StaticCertctrlConfigProvider certctrl_config_provider(base);

  auto ws_cfg = certctrl::WebsocketConfig{};
  StaticWebsocketConfigProvider websocket_config_provider(ws_cfg);

  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);

  int callback_calls = 0;
  auto on_ws_updated = [&]() { callback_calls++; };

    certctrl::signal_handlers::ConfigUpdatedHandler handler(
    certctrl_config_provider, console, &websocket_config_provider,
    on_ws_updated);

    json::object websocket_content;
    websocket_content["enabled"] = true;
    websocket_content["verify_tls"] = false;
    websocket_content["remote_endpoint"] = "wss://127.0.0.1:443/api/websocket";
    json::object tunnel;
    tunnel["local_base_url"] = "http://127.0.0.1:8080/hooks";
    tunnel["header_allowlist"] = json::array{"content-type"};
    tunnel["routes"] = json::array{json::object{{"match_prefix", "/stripe"}}};
    websocket_content["tunnel"] = std::move(tunnel);

    ::data::DeviceUpdateSignal signal;
  signal.type = "config.updated";
  signal.ts_ms = 1736900123999;
    signal.ref = json::object{{
      "replace",
      json::array{json::object{{"file", "websocket"},
                   {"content", std::move(websocket_content)}}}}};

    using IOResult = decltype(handler.handle(signal))::IOResult;
    std::optional<IOResult> result;
    handler.handle(signal).run([&](auto r) { result = std::move(r); });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_ok()) << "handler should succeed";
  EXPECT_EQ(callback_calls, 1);
  EXPECT_TRUE(websocket_config_provider.saved_replace().if_contains("enabled"));
  EXPECT_TRUE(websocket_config_provider.get().enabled);
}

TEST(ConfigUpdatedHandlerTest, RejectsRefSetCompletely) {
  certctrl::CertctrlConfig base;
  StaticCertctrlConfigProvider certctrl_config_provider(base);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);

  certctrl::signal_handlers::ConfigUpdatedHandler handler(
    certctrl_config_provider, console, nullptr);

  ::data::DeviceUpdateSignal signal;
  signal.type = "config.updated";
  signal.ts_ms = 1736900123999;
  signal.ref = json::object{{"set", json::object{{"auto_apply_config", true}}}};

  using IOResult = decltype(handler.handle(signal))::IOResult;
  std::optional<IOResult> result;
  handler.handle(signal).run([&](auto r) { result = std::move(r); });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_err());
}

TEST(WebsocketClientIntegrationTest, AcksUnknownUpdateSignalAndPersistsResumeToken) {
  const auto websocket_port = PickFreePort();
  const auto local_port = PickFreePort();

  std::vector<certctrl::WebsocketRequest> requests;
  FakeWebsocketServer websocket_server(websocket_port, requests, 0);
  websocket_server.set_expected_message_count(2);

  certctrl::WebsocketEventEnvelope signal;
  signal.name = "updates.signal";
  signal.id = "upd-unknown";
  signal.resume_token = "rt-unknown";
  signal.payload = json::object{{"type", "future.unknown.signal"},
                               {"ts_ms", 1736900123999},
                               {"ref", json::object{}}};
  websocket_server.set_deferred_messages_after_hello_ack(
      {json::value_from(signal)});
  websocket_server.Start();

  auto cfg = MakeBaseConfig(websocket_port, local_port);
  cfg.ping_interval_seconds = 60;
  StaticWebsocketConfigProvider config_provider(cfg);
  StaticCertctrlConfigProvider certctrl_config_provider;
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  InMemoryDeviceStateStore state_store;
  state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;
  certctrl::WebsocketClient client(io_manager, config_provider,
                                  certctrl_config_provider, console,
                                  TestConfigSources(), state_store,
                                  install_config_manager,
                                  std::shared_ptr<certctrl::ISessionRefresher>{});
  client.Start();

  auto messages = websocket_server.WaitForMessages(5s);

  bool saw_hello_ack = false;
  bool saw_updates_ack = false;
  for (const auto &msg : messages) {
    const auto *obj = msg.if_object();
    if (!obj) {
      continue;
    }
    const auto *type_field = obj->if_contains("type");
    if (!type_field || !type_field->is_string() ||
        type_field->as_string() != "event") {
      continue;
    }
    const auto *name_field = obj->if_contains("name");
    if (!name_field || !name_field->is_string()) {
      continue;
    }
    const std::string name = std::string(name_field->as_string().c_str());
    if (name == "lifecycle.hello_ack") {
      saw_hello_ack = true;
      continue;
    }
    if (name == "updates.ack") {
      saw_updates_ack = true;
      const auto *id_field = obj->if_contains("id");
      ASSERT_TRUE(id_field && id_field->is_string());
      EXPECT_EQ(std::string(id_field->as_string().c_str()), "upd-unknown");

      const auto *token_field = obj->if_contains("resume_token");
      ASSERT_TRUE(token_field && token_field->is_string());
      EXPECT_EQ(std::string(token_field->as_string().c_str()), "rt-unknown");
    }
  }

  EXPECT_TRUE(saw_hello_ack) << "did not observe lifecycle.hello_ack";
  EXPECT_TRUE(saw_updates_ack) << "did not observe updates.ack";
  EXPECT_EQ(state_store.get_websocket_resume_token(),
            std::optional<std::string>("rt-unknown"));

  client.Stop();
  websocket_server.Join();
}

TEST(WebsocketClientIntegrationTest,
     DoesNotAckTlsAlpn01ChallengeWhenHandlerValidationFails) {
  const auto websocket_port = PickFreePort();
  const auto local_port = PickFreePort();

  std::vector<certctrl::WebsocketRequest> requests;
  FakeWebsocketServer websocket_server(websocket_port, requests, 0);
  websocket_server.set_expected_message_count(10);

  certctrl::WebsocketEventEnvelope signal;
  signal.name = "updates.signal";
  signal.id = "acme-bad";
  signal.resume_token = "rt-bad";
  signal.payload = json::object{
      {"type", "acme.tlsalpn01.challenge"},
      {"ts_ms", 1736900125001},
      {"ref",
       json::object{{"challenge_id", "ch-bad"},
                    {"domain", "example.com"},
                    {"token", "tok"},
                    {"key_authorization", "tok.thumb"},
                    {"listen",
                     json::object{{"bind", "127.0.0.1"},
                                  {"port", "not-a-number"}}},
                    {"certificate",
                     json::object{{"cert_pem", TestServerCertPem()},
                                  {"key_pem", TestServerKeyPem()}}}}}};

  websocket_server.set_deferred_messages_after_hello_ack({json::value_from(signal)});
  websocket_server.Start();

  auto cfg = MakeBaseConfig(websocket_port, local_port);
  cfg.ping_interval_seconds = 60;
  StaticWebsocketConfigProvider config_provider(cfg);
  StaticCertctrlConfigProvider certctrl_config_provider;
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  InMemoryDeviceStateStore state_store;
  state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
  ASSERT_FALSE(state_store.save_websocket_resume_token(std::string("rt-seed")));
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;

  certctrl::WebsocketClient client(
      io_manager, config_provider, certctrl_config_provider, console,
      TestConfigSources(), state_store, install_config_manager,
      std::shared_ptr<certctrl::ISessionRefresher>{});
  client.Start();

  const auto messages = websocket_server.WaitForMessages(1500ms);

  bool saw_updates_ack_for_bad = false;
  for (const auto& msg : messages) {
    const auto* obj = msg.if_object();
    if (!obj) {
      continue;
    }
    const auto* type_field = obj->if_contains("type");
    if (!type_field || !type_field->is_string() ||
        type_field->as_string() != "event") {
      continue;
    }
    const auto* name_field = obj->if_contains("name");
    if (!name_field || !name_field->is_string()) {
      continue;
    }
    if (std::string(name_field->as_string().c_str()) != "updates.ack") {
      continue;
    }
    const auto* id_field = obj->if_contains("id");
    if (id_field && id_field->is_string() &&
        std::string(id_field->as_string().c_str()) == "acme-bad") {
      saw_updates_ack_for_bad = true;
      break;
    }
  }

  EXPECT_FALSE(saw_updates_ack_for_bad)
      << "should not ack when acme.tlsalpn01.challenge handler fails";
  EXPECT_EQ(state_store.get_websocket_resume_token(),
            std::optional<std::string>("rt-seed"));

  client.Stop();
  websocket_server.Join();
}

TEST(WebsocketClientIntegrationTest, AcksTlsAlpn01ChallengeAndPersistsResumeToken) {
  const auto websocket_port = PickFreePort();
  const auto local_port = PickFreePort();

  std::vector<certctrl::WebsocketRequest> requests;
  FakeWebsocketServer websocket_server(websocket_port, requests, 0);
  websocket_server.set_expected_message_count(10);

  certctrl::WebsocketEventEnvelope signal;
  signal.name = "updates.signal";
  signal.id = "acme-1";
  signal.resume_token = "rt-acme-1";
  signal.payload = json::object{
      {"type", "acme.tlsalpn01.challenge"},
      {"ts_ms", 1736900125002},
      {"ref",
       json::object{{"challenge_id", "ch-1"},
                    {"domain", "example.com"},
                    {"token", "tok"},
                    {"key_authorization", "tok.thumb"},
                    {"ttl_seconds", 1},
                    {"listen",
                     json::object{{"bind", "127.0.0.1"}, {"port", 0}}},
                    {"certificate",
                     json::object{{"cert_pem", TestServerCertPem()},
                                  {"key_pem", TestServerKeyPem()}}}}}};

  websocket_server.set_deferred_messages_after_hello_ack({json::value_from(signal)});
  websocket_server.Start();

  auto cfg = MakeBaseConfig(websocket_port, local_port);
  cfg.ping_interval_seconds = 60;
  StaticWebsocketConfigProvider config_provider(cfg);
  StaticCertctrlConfigProvider certctrl_config_provider;
  TestIocConfigProvider ioc_provider(1);
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput console(logger);
  cjj365::IoContextManager io_manager(ioc_provider, logger);
  InMemoryDeviceStateStore state_store;
  state_store.save_tokens(MakeTestJwtWithDeviceId(1), std::nullopt);
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager;

  certctrl::WebsocketClient client(
      io_manager, config_provider, certctrl_config_provider, console,
      TestConfigSources(), state_store, install_config_manager,
      std::shared_ptr<certctrl::ISessionRefresher>{});
  client.Start();

  const auto messages = websocket_server.WaitForMessages(1500ms);

  bool saw_updates_ack = false;
  for (const auto& msg : messages) {
    const auto* obj = msg.if_object();
    if (!obj) {
      continue;
    }
    const auto* type_field = obj->if_contains("type");
    if (!type_field || !type_field->is_string() ||
        type_field->as_string() != "event") {
      continue;
    }
    const auto* name_field = obj->if_contains("name");
    if (!name_field || !name_field->is_string()) {
      continue;
    }
    if (std::string(name_field->as_string().c_str()) != "updates.ack") {
      continue;
    }

    const auto* id_field = obj->if_contains("id");
    const auto* token_field = obj->if_contains("resume_token");
    if (!id_field || !id_field->is_string() || !token_field ||
        !token_field->is_string()) {
      continue;
    }
    if (std::string(id_field->as_string().c_str()) == "acme-1") {
      saw_updates_ack = true;
      EXPECT_EQ(std::string(token_field->as_string().c_str()), "rt-acme-1");
      break;
    }
  }

  EXPECT_TRUE(saw_updates_ack) << "did not observe updates.ack for acme-1";
  EXPECT_EQ(state_store.get_websocket_resume_token(),
            std::optional<std::string>("rt-acme-1"));

  client.Stop();
  websocket_server.Join();
}
