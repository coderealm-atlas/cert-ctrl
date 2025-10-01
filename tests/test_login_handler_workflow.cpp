#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <boost/system/error_code.hpp>
#include <jwt-cpp/jwt.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "boost/di.hpp"
#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "handlers/login_handler.hpp"
#include "http_client_config_provider.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "log_stream.hpp"
#include "misc_util.hpp"
#include "result_monad.hpp"

namespace {
namespace di = boost::di;
namespace fs = std::filesystem;
namespace asio = boost::asio;
namespace http = boost::beast::http;
namespace json = boost::json;

std::string make_unique_dir_name() {
  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist;
  std::ostringstream oss;
  oss << std::hex << now << '-' << dist(gen);
  return oss.str();
}

struct TempDir {
  fs::path path;
  TempDir() {
    auto base = fs::temp_directory_path() / "certctrl-tests";
    fs::create_directories(base);
    path = base / make_unique_dir_name();
    fs::create_directories(path);
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
};

void write_json_file(const fs::path &file, const json::value &jv) {
  std::ofstream ofs(file);
  ofs << json::serialize(jv);
}

class TestDeviceServer {
public:
  struct RegistrationRecord {
    json::object payload;
    std::string authorization;
    std::string target;
  };

  TestDeviceServer(cjj365::IIoContextManager &io_manager)
      : acceptor_(io_manager.ioc()), access_token_("access-token-123"),
        refresh_token_(issue_refresh_token("12345")) {
    using tcp = asio::ip::tcp;
    tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), 0);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
    port_ = acceptor_.local_endpoint().port();
    server_thread_ = std::thread([this] { this->run(); });
  }

  ~TestDeviceServer() {
    stop();
    if (server_thread_.joinable()) {
      server_thread_.join();
    }
  }

  TestDeviceServer(const TestDeviceServer &) = delete;
  TestDeviceServer &operator=(const TestDeviceServer &) = delete;

  std::string base_url() const {
    return std::string("http://127.0.0.1:") + std::to_string(port_);
  }

  const std::string &access_token() const { return access_token_; }
  const std::string &refresh_token() const { return refresh_token_; }
  std::string expected_user_id() const { return "12345"; }

  int start_calls() const { return start_calls_.load(); }
  int poll_calls() const { return poll_calls_.load(); }
  int registration_calls() const { return registration_calls_.load(); }

  std::optional<RegistrationRecord>
  wait_for_registration(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    if (!cv_.wait_for(lock, timeout,
                      [&] { return registration_calls_.load() > 0; })) {
      return std::nullopt;
    }
    return last_registration_;
  }

  void stop() {
    bool expected = false;
    if (!stopped_.compare_exchange_strong(expected, true))
      return;
    try {
      asio::io_context tmp_ioc;
      asio::ip::tcp::socket poke(tmp_ioc);
      auto endpoint = asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port_);
      try {
        poke.connect(endpoint);
        poke.close();
      } catch (...) {
        // ignore
      }
      acceptor_.close();
    } catch (...) {
      // ignore shutdown errors during teardown
    }
  }

private:
  static std::string issue_refresh_token(const std::string &sub) {
    return jwt::create()
        .set_type("JWT")
        .set_payload_claim("sub", jwt::claim(sub))
        .sign(jwt::algorithm::hs256{"secret"});
  }

  void run() {
    while (!stopped_.load()) {
      boost::system::error_code ec;
      auto socket = acceptor_.accept(ec);
      if (ec) {
        if (stopped_.load())
          break;
        continue;
      }
      if (stopped_.load()) {
        boost::system::error_code ignore;
        try {
          socket.shutdown(asio::ip::tcp::socket::shutdown_both);
          socket.close();
        } catch (...) {
        }
        break;
      }
      handle_session(std::move(socket));
    }
  }

  void handle_session(asio::ip::tcp::socket socket) {
    boost::beast::flat_buffer buffer;
    http::request<http::string_body> req;
    boost::system::error_code read_ec;
    http::read(socket, buffer, req, read_ec);
    if (read_ec)
      return;

    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, "TestDeviceServer");
    res.set(http::field::content_type, "application/json");
    res.keep_alive(false);

    if (req.method() == http::verb::post && req.target() == "/auth/device") {
      handle_device_auth(std::move(req), res);
    } else if (req.method() == http::verb::post &&
               req.target().starts_with("/apiv1/users/")) {
      handle_registration(std::move(req), res);
    } else {
      res.result(http::status::not_found);
      res.body() = "{}";
      res.prepare_payload();
    }

    boost::system::error_code write_ec;
    http::write(socket, res, write_ec);
    (void)write_ec;
  }

  void handle_device_auth(http::request<http::string_body> &&req,
                          http::response<http::string_body> &res) {
    json::value parsed = json::parse(req.body());
    auto action = parsed.as_object().at("action").as_string();
    if (action == "device_start") {
      ++start_calls_;
      json::object body{{"device_code", device_code_},
                        {"user_code", "ABCD-EFGH"},
                        {"verification_uri", base_url() + "/device"},
                        {"verification_uri_complete",
                         base_url() + "/device?user_code=ABCD-EFGH"},
                        {"interval", 5},
                        {"expires_in", 600}};
      res.body() = json::serialize(body);
    } else if (action == "device_poll") {
      ++poll_calls_;
      json::object body{{"status", "approved"},
                        {"access_token", access_token_},
                        {"refresh_token", refresh_token_},
                        {"expires_in", 600}};
      res.body() = json::serialize(body);
    } else {
      res.result(http::status::bad_request);
      res.body() = json::serialize(json::object{{"error", "unsupported"}});
    }
    res.prepare_payload();
  }

  void handle_registration(http::request<http::string_body> &&req,
                           http::response<http::string_body> &res) {
    json::value parsed = json::parse(req.body());
    if (!parsed.is_object()) {
      res.result(http::status::bad_request);
      res.body() = json::serialize(json::object{{"error", "invalid"}});
      res.prepare_payload();
      return;
    }

    RegistrationRecord record;
    record.payload = parsed.as_object();
    if (auto it = req.find(http::field::authorization); it != req.end()) {
      record.authorization = it->value();
    }
    record.target = std::string(req.target());

    {
      std::lock_guard lock(mutex_);
      last_registration_ = record;
      registration_calls_.fetch_add(1);
    }
    cv_.notify_all();

    res.body() = json::serialize(json::object{{"status", "ok"}});
    res.prepare_payload();
  }

  asio::ip::tcp::acceptor acceptor_;
  std::thread server_thread_;
  std::atomic<bool> stopped_{false};

  std::atomic<int> start_calls_{0};
  std::atomic<int> poll_calls_{0};
  std::atomic<int> registration_calls_{0};

  std::mutex mutex_;
  std::condition_variable cv_;
  std::optional<RegistrationRecord> last_registration_;

  unsigned short port_{0};
  std::string device_code_{"device-code-xyz"};
  std::string access_token_;
  std::string refresh_token_;
};

// Regex to validate device_public_id format 8-4-4-4-12 hex digits.
bool is_valid_device_id(std::string_view value) {
  static const std::regex pattern(
      R"(^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)",
      std::regex::icase);
  return std::regex_match(value.begin(), value.end(), pattern);
}

} // namespace

static cjj365::IIoContextManager *io_context_manager = nullptr;
static client_async::HttpClientManager *http_client_manager = nullptr;

class LoginHandlerWorkflowTest : public ::testing::Test {
protected:
  std::shared_ptr<void> injector_holder_;
  std::shared_ptr<certctrl::LoginHandler> handler_;
  TestDeviceServer *server_;
  TempDir temp_dir;
  certctrl::ICertctrlConfigProvider *config_provider_;
  void SetUp() override {

    json::object app_json{{"auto_fetch_config", false},
                          {"verbose", "info"},
                          {"url_base", "to_set"}};
    write_json_file(temp_dir.path / "application.json", app_json);

    json::object httpclient_json{{"threads_num", 1},
                                 {"ssl_method", "tlsv12_client"},
                                 {"insecure_skip_verify", true},
                                 {"verify_paths", json::array{}},
                                 {"certificates", json::array{}},
                                 {"certificate_files", json::array{}},
                                 {"proxy_pool", json::array{}}};
    write_json_file(temp_dir.path / "httpclient_config.json", httpclient_json);

    json::object ioc_json{{"threads_num", 1}, {"name", "test-ioc"}};
    write_json_file(temp_dir.path / "ioc_config.json", ioc_json);

    certctrl::CliParams params;
    params.subcmd = "login";
    params.config_dirs = {temp_dir.path};

    boost::program_options::variables_map vm;
    std::vector<std::string> positionals{"login"};
    std::vector<std::string> unrecognized;
    static certctrl::CliCtx cli_ctx(std::move(vm), std::move(positionals),
                                    std::move(unrecognized), std::move(params));

    std::vector<fs::path> config_paths{temp_dir.path};
    std::vector<std::string> profiles;

    static cjj365::ConfigSources config_sources(config_paths, profiles);
    static customio::ConsoleOutputWithColor output(5);

    auto injector = di::make_injector(
        di::bind<cjj365::ConfigSources>().to(config_sources),
        di::bind<cjj365::IHttpclientConfigProvider>()
            .to<cjj365::HttpclientConfigProviderFile>(),
        di::bind<cjj365::IIocConfigProvider>()
            .to<cjj365::IocConfigProviderFile>(),
        di::bind<customio::IOutput>().to(output),
        di::bind<certctrl::CliCtx>().to(cli_ctx),
        di::bind<certctrl::ICertctrlConfigProvider>()
            .to<certctrl::CertctrlConfigProviderFile>()
            .in(di::singleton),
        di::bind<cjj365::IIoContextManager>().to<cjj365::IoContextManager>().in(
            di::singleton));
    using InjT = decltype(injector);
    auto real_inj = std::make_shared<InjT>(std::move(injector));
    injector_holder_ = real_inj;
    auto &inj = *real_inj;
    server_ = &inj.create<TestDeviceServer &>();
    config_provider_ = &inj.create<certctrl::ICertctrlConfigProvider &>();
    config_provider_->get().base_url = server_->base_url();
    handler_ = inj.create<std::shared_ptr<certctrl::LoginHandler>>();
    io_context_manager = &inj.create<cjj365::IIoContextManager &>();
    http_client_manager = &inj.create<client_async::HttpClientManager &>();
  }
  void TearDown() override {}
};

TEST_F(LoginHandlerWorkflowTest, EndToEndDeviceRegistration) {
  misc::ThreadNotifier notifier(5000);

  std::optional<monad::MyVoidResult> start_result;
  handler_->start().run([&](auto r) {
    start_result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();
  ASSERT_TRUE(start_result.has_value());
  ASSERT_FALSE(start_result->is_err()) << start_result->error();

  EXPECT_GE(server_->poll_calls(), 1);
  EXPECT_EQ(server_->registration_calls(), 0);

  std::optional<monad::MyVoidResult> reg_result;
  handler_->register_device().run([&](auto r) {
    reg_result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();
  ASSERT_TRUE(reg_result.has_value());
  ASSERT_FALSE(reg_result->is_err()) << reg_result->error();

  auto record = server_->wait_for_registration(std::chrono::seconds(2));
  ASSERT_TRUE(record.has_value()) << "registration payload missing";
  EXPECT_EQ(server_->registration_calls(), 1);
  EXPECT_EQ(server_->start_calls(), 1);
  EXPECT_EQ(record->authorization,
            std::string("Bearer ") + server_->access_token());

  EXPECT_EQ(record->target,
            "/apiv1/users/" + server_->expected_user_id() + "/devices");
  ASSERT_TRUE(record->payload.if_contains("device_public_id"));
  auto device_id = record->payload.at("device_public_id").as_string();
  EXPECT_TRUE(is_valid_device_id(device_id)) << device_id;

  ASSERT_TRUE(record->payload.if_contains("dev_pk"));
  auto dev_pk_b64 = record->payload.at("dev_pk").as_string();
  EXPECT_FALSE(dev_pk_b64.empty());

  EXPECT_FALSE(record->payload.if_contains("access_token"));
  EXPECT_FALSE(record->payload.if_contains("refresh_token"));

  auto pk_path = temp_dir.path / "dev_pk.bin";
  auto sk_path = temp_dir.path / "dev_sk.bin";
  EXPECT_TRUE(fs::exists(pk_path));
  EXPECT_TRUE(fs::exists(sk_path));

  auto access_path = temp_dir.path / "access_token.txt";
  auto refresh_path = temp_dir.path / "refresh_token.txt";
  EXPECT_TRUE(fs::exists(access_path));
  EXPECT_TRUE(fs::exists(refresh_path));

  //   auto &http_manager = injector.create<client_async::HttpClientManager
  //   &>(); auto &io_manager = injector.create<cjj365::IoContextManager &>();
  //   http_manager.stop();
  //   io_manager.stop();
  //   server.stop();
  //   cjj365::ConfigSources::instance_count.store(0);
}

// int main(int argc, char **argv) {
//   ::testing::InitGoogleTest(&argc, argv);
//   int code = RUN_ALL_TESTS();
//   io_context_manager->stop();
//   http_client_manager->stop();
//   // ✅ Global teardown: runs exactly once after all tests
//   // e.g., close logs, stop servers, free singletons, etc.
//   // my_global_cleanup();

//   return code;
// }