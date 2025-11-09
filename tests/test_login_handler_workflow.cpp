#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <boost/system/error_code.hpp>
#include <jwt-cpp/jwt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iterator>
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
      : acceptor_(io_manager.ioc()),
        access_token_(issue_access_token("12345", device_code_)),
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
  const std::string &registration_code() const { return registration_code_; }
  std::string expected_user_id() const { return "12345"; }

  const std::string &refreshed_access_token() const {
    return refreshed_access_token_;
  }
  const std::string &refreshed_refresh_token() const {
    return refreshed_refresh_token_;
  }

  int start_calls() const { return start_calls_.load(); }
  int poll_calls() const { return poll_calls_.load(); }
  int registration_calls() const { return registration_calls_.load(); }
  int refresh_calls() const { return refresh_calls_.load(); }
  void set_pending_before_approve(int attempts) {
    pending_before_approve_.store(std::max(0, attempts));
  }

  void set_refresh_response_tokens(std::string new_access,
                                   std::string new_refresh) {
    refreshed_access_token_ = std::move(new_access);
    refreshed_refresh_token_ = std::move(new_refresh);
  }

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
      auto endpoint =
          asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port_);
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
  static std::string issue_access_token(const std::string &sub,
                                        const std::string &device_id) {
    return jwt::create()
        .set_type("JWT")
        .set_payload_claim("sub", jwt::claim(sub))
        .set_payload_claim("device_id", jwt::claim(device_id))
        .sign(jwt::algorithm::hs256{"secret"});
  }

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
               req.target() == "/auth/refresh") {
      handle_refresh(std::move(req), res);
    } else if (req.method() == http::verb::post &&
               req.target() == "/apiv1/device/registration") {
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
      std::cerr << "device_start" << std::endl;
      json::object body{{"device_code", device_code_},
                        {"user_code", "ABCD-EFGH"},
                        {"verification_uri", base_url() + "/device"},
                        {"verification_uri_complete",
                         base_url() + "/device?user_code=ABCD-EFGH"},
                        {"interval", 1},
                        {"expires_in", 600}};
      res.body() = json::serialize(json::object{{"data", body}});
    } else if (action == "device_poll") {
      ++poll_calls_;
      std::cerr << "device_poll #" << poll_calls_.load() << std::endl;
      if (poll_calls_.load() <= pending_before_approve_.load()) {
        json::object body{{"status", "authorization_pending"}};
        res.body() = json::serialize(json::object{{"data", body}});
      } else {
        json::object body{{"status", "ready"},
                          {"registration_code", registration_code_},
                          {"registration_code_ttl", 600},
                          {"user_id", expected_user_id()}};
        res.body() = json::serialize(json::object{{"data", body}});
      }
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

    json::object device_obj{{"id", device_numeric_id_}};
    if (auto *p = record.payload.if_contains("device_public_id");
        p && p->is_string()) {
      device_obj["device_public_id"] = p->as_string();
    }
    json::object session_obj{{"access_token", access_token_},
                             {"refresh_token", refresh_token_},
                             {"expires_in", 600}};

    json::object data_obj{{"status", "ok"},
                          {"device", std::move(device_obj)},
                          {"session", std::move(session_obj)}};

    res.body() = json::serialize(json::object{{"data", std::move(data_obj)}});
    res.prepare_payload();
  }

  void handle_refresh(http::request<http::string_body> &&req,
                      http::response<http::string_body> &res) {
    json::value parsed;
    try {
      parsed = json::parse(req.body());
    } catch (...) {
      res.result(http::status::bad_request);
      res.body() = json::serialize(json::object{{"error", "invalid"}});
      res.prepare_payload();
      return;
    }
    std::string provided_refresh;
    if (auto *obj = parsed.if_object()) {
      if (auto *token = obj->if_contains("refresh_token");
          token && token->is_string()) {
        provided_refresh =
            std::string(token->as_string().c_str(), token->as_string().size());
      }
    }
    if (provided_refresh.empty()) {
      res.result(http::status::bad_request);
      res.body() = json::serialize(json::object{{"error", "missing_token"}});
      res.prepare_payload();
      return;
    }
    refresh_calls_.fetch_add(1);

    json::object session_obj{{"access_token", refreshed_access_token_},
                             {"refresh_token", refreshed_refresh_token_},
                             {"expires_in", 600}};
    json::object data_obj{{"session", std::move(session_obj)}};
    res.body() = json::serialize(json::object{{"data", std::move(data_obj)}});
    res.prepare_payload();
  }

  asio::ip::tcp::acceptor acceptor_;
  std::thread server_thread_;
  std::atomic<bool> stopped_{false};

  std::atomic<int> start_calls_{0};
  std::atomic<int> poll_calls_{0};
  std::atomic<int> registration_calls_{0};
  std::atomic<int> refresh_calls_{0};
  std::atomic<int> pending_before_approve_{0};

  std::mutex mutex_;
  std::condition_variable cv_;
  std::optional<RegistrationRecord> last_registration_;

  unsigned short port_{0};
  std::string device_code_{"device-code-xyz"};
  std::string access_token_;
  std::string refresh_token_;
  std::string registration_code_{"mock-registration-code"};
  std::string device_numeric_id_{"4242"};
  std::string refreshed_access_token_{
      issue_access_token("12345", device_code_ + "-refresh")};
  std::string refreshed_refresh_token_{issue_refresh_token("12345-refresh")};
};

// Regex to validate device_public_id format 8-4-4-4-12 hex digits.
bool is_valid_device_id(std::string_view value) {
  static const std::regex pattern(
      R"(^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)",
      std::regex::icase);
  return std::regex_match(value.begin(), value.end(), pattern);
}

} // namespace

class LoginHandlerWorkflowTest : public ::testing::Test {
protected:
  std::shared_ptr<void> injector_holder_;
  std::shared_ptr<certctrl::LoginHandler> handler_;
  std::unique_ptr<TestDeviceServer> server_;
  TempDir temp_dir;
  certctrl::ICertctrlConfigProvider *config_provider_;
  cjj365::IIoContextManager *io_context_manager_{nullptr};
  client_async::HttpClientManager *http_client_manager_{nullptr};
  std::unique_ptr<cjj365::ConfigSources> config_sources_ptr_;
  std::shared_ptr<customio::ConsoleOutputWithColor> output_ptr_;
  static std::shared_ptr<customio::ConsoleOutputWithColor> shared_output_;
  std::unique_ptr<certctrl::CliCtx> cli_ctx_ptr_;
  void SetUp() override {

    json::object app_json{{"auto_apply_config", false},
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

    auto vm = boost::program_options::variables_map{};
    auto positionals = std::vector<std::string>{"login"};
    auto unrecognized = std::vector<std::string>{};
    cli_ctx_ptr_ = std::make_unique<certctrl::CliCtx>(
        std::move(vm), std::move(positionals), std::move(unrecognized),
        std::move(params));

    std::vector<fs::path> config_paths{temp_dir.path};
    std::vector<std::string> profiles;

    config_sources_ptr_ =
        std::make_unique<cjj365::ConfigSources>(config_paths, profiles);
    if (!shared_output_) {
      shared_output_ = std::make_shared<customio::ConsoleOutputWithColor>(5);
    }
    output_ptr_ = shared_output_;

    auto injector = di::make_injector(
        di::bind<cjj365::ConfigSources>().to(*config_sources_ptr_),
        di::bind<cjj365::IHttpclientConfigProvider>()
            .to<cjj365::HttpclientConfigProviderFile>(),
        di::bind<cjj365::IIocConfigProvider>()
            .to<cjj365::IocConfigProviderFile>(),
        di::bind<customio::IOutput>().to(*output_ptr_),
        di::bind<certctrl::CliCtx>().to(*cli_ctx_ptr_),
        di::bind<certctrl::LoginHandler>().in(di::unique),
        di::bind<certctrl::ICertctrlConfigProvider>()
            .to<certctrl::CertctrlConfigProviderFile>()
            .in(di::singleton),
        di::bind<cjj365::IIoContextManager>().to<cjj365::IoContextManager>().in(
            di::singleton));
    using InjT = decltype(injector);
    auto real_inj = std::make_shared<InjT>(std::move(injector));
    injector_holder_ = real_inj;
    auto &inj = *real_inj;
    server_ = inj.create<std::unique_ptr<TestDeviceServer>>();
    config_provider_ = &inj.create<certctrl::ICertctrlConfigProvider &>();
    config_provider_->get().base_url = server_->base_url();
    // if you obtain a shared_ptr from injector, the instance will be in
    // singleton static scope. only if you explicitly bind to unique, you can
    // get a new instance each time.
    handler_ = inj.create<std::shared_ptr<certctrl::LoginHandler>>();
    io_context_manager_ = &inj.create<cjj365::IIoContextManager &>();
    http_client_manager_ = &inj.create<client_async::HttpClientManager &>();
  }
  void TearDown() override {
    handler_.reset();

    if (server_ != nullptr) {
      server_->stop();
      server_ = nullptr;
    }

    // because io_context_manager_ and http_client_manager_ are singletons(aka static allocated),
    // so you shouldn't stop them here in TearDown. or else other tests that use the same
    // singletons will fail.
    // if (http_client_manager_ != nullptr) {
    //   http_client_manager_->stop();
    //   http_client_manager_ = nullptr;
    // }

    // if (io_context_manager_ != nullptr) {
    //   io_context_manager_->stop();
    //   io_context_manager_ = nullptr;
    // }

    injector_holder_.reset();
    config_provider_ = nullptr;
    config_sources_ptr_.reset();
    cli_ctx_ptr_.reset();
    output_ptr_.reset();
  }
};

TEST_F(LoginHandlerWorkflowTest, EndToEndDeviceRegistration) {
  misc::ThreadNotifier notifier(15000);

  std::optional<monad::MyVoidResult> start_result;
  handler_->start().run([&](auto r) {
    start_result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();
  int start_calls = server_->start_calls();
  int poll_calls = server_->poll_calls();
  std::cerr << "start_calls=" << start_calls << " poll_calls=" << poll_calls
            << std::endl;
  ASSERT_TRUE(start_result.has_value())
      << "start_calls=" << start_calls << " poll_calls=" << poll_calls;
  ASSERT_FALSE(start_result->is_err()) << start_result->error();

  EXPECT_GE(server_->poll_calls(), 1);
  auto record = server_->wait_for_registration(std::chrono::seconds(2));
  ASSERT_TRUE(record.has_value()) << "registration payload missing";
  EXPECT_EQ(server_->registration_calls(), 1);
  EXPECT_EQ(server_->start_calls(), 1);
  EXPECT_TRUE(record->authorization.empty());

  std::optional<monad::MyVoidResult> reg_result;
  handler_->register_device().run([&](auto r) {
    reg_result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();
  ASSERT_TRUE(reg_result.has_value());
  ASSERT_FALSE(reg_result->is_err()) << reg_result->error();
  EXPECT_EQ(server_->registration_calls(), 1);

  EXPECT_EQ(record->target, "/apiv1/device/registration");
  ASSERT_TRUE(record->payload.if_contains("user_id"));
  const auto &user_id_value = record->payload.at("user_id");
  if (user_id_value.is_string()) {
    EXPECT_EQ(user_id_value.as_string(), server_->expected_user_id());
  } else if (user_id_value.is_int64()) {
    EXPECT_EQ(user_id_value.as_int64(),
              std::stoll(server_->expected_user_id()));
  } else {
    ADD_FAILURE() << "user_id has unexpected type";
  }
  ASSERT_TRUE(record->payload.if_contains("device_public_id"));
  auto device_id = record->payload.at("device_public_id").as_string();
  EXPECT_TRUE(is_valid_device_id(device_id)) << device_id;

  ASSERT_TRUE(record->payload.if_contains("dev_pk"));
  auto dev_pk_b64 = record->payload.at("dev_pk").as_string();
  EXPECT_FALSE(dev_pk_b64.empty());

  EXPECT_FALSE(record->payload.if_contains("access_token"));
  EXPECT_FALSE(record->payload.if_contains("refresh_token"));
  ASSERT_TRUE(record->payload.if_contains("registration_code"));
  EXPECT_EQ(record->payload.at("registration_code").as_string(),
            server_->registration_code());

  auto key_dir = temp_dir.path / "keys";
  auto pk_path = key_dir / "dev_pk.bin";
  auto sk_path = key_dir / "dev_sk.bin";
  EXPECT_TRUE(fs::exists(pk_path));
  EXPECT_TRUE(fs::exists(sk_path));

  auto state_dir = temp_dir.path / "state";
  auto access_path = state_dir / "access_token.txt";
  auto refresh_path = state_dir / "refresh_token.txt";
  ASSERT_TRUE(fs::exists(access_path));
  ASSERT_TRUE(fs::exists(refresh_path));

  {
    std::ifstream ifs(access_path);
    std::string stored_access((std::istreambuf_iterator<char>(ifs)), {});
    EXPECT_EQ(stored_access, server_->access_token());
  }
  {
    std::ifstream ifs(refresh_path);
    std::string stored_refresh((std::istreambuf_iterator<char>(ifs)), {});
    EXPECT_EQ(stored_refresh, server_->refresh_token());
  }
}

TEST_F(LoginHandlerWorkflowTest, PollRetriesBeforeApproval) {
  server_->set_pending_before_approve(3);

  misc::ThreadNotifier notifier(30000);

  std::optional<monad::MyVoidResult> start_result;
  handler_->start().run([&](auto r) {
    start_result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();
  ASSERT_TRUE(start_result.has_value());
  ASSERT_FALSE(start_result->is_err()) << start_result->error();

  EXPECT_GE(server_->poll_calls(), 4);
  auto record = server_->wait_for_registration(std::chrono::seconds(20));
  ASSERT_TRUE(record.has_value()) << "registration payload missing";
  EXPECT_EQ(server_->registration_calls(), 1);
  EXPECT_EQ(server_->start_calls(), 1);
  EXPECT_TRUE(record->authorization.empty());

  std::optional<monad::MyVoidResult> reg_result;
  handler_->register_device().run([&](auto r) {
    reg_result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();
  ASSERT_TRUE(reg_result.has_value());
  ASSERT_FALSE(reg_result->is_err()) << reg_result->error();
  EXPECT_EQ(server_->registration_calls(), 1);

  EXPECT_EQ(record->target, "/apiv1/device/registration");
}

TEST_F(LoginHandlerWorkflowTest, ReusesExistingValidTokens) {
  auto state_dir = temp_dir.path / "state";
  fs::create_directories(state_dir);

  const auto now = std::chrono::system_clock::now();
  auto access_token =
      jwt::create()
          .set_type("JWT")
          .set_payload_claim("sub", jwt::claim(server_->expected_user_id()))
          .set_payload_claim("device_id",
                             jwt::claim(std::string{"device-code-xyz"}))
          .set_expires_at(now + std::chrono::hours(1))
          .sign(jwt::algorithm::hs256{"secret"});
  auto refresh_token = server_->refresh_token();

  {
    std::ofstream ofs(state_dir / "access_token.txt");
    ofs << access_token;
  }
  {
    std::ofstream ofs(state_dir / "refresh_token.txt");
    ofs << refresh_token;
  }

  misc::ThreadNotifier notifier(5000);
  std::optional<monad::MyVoidResult> start_result;
  handler_->start().run([&](auto r) {
    start_result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();

  ASSERT_TRUE(start_result.has_value());
  ASSERT_FALSE(start_result->is_err()) << start_result->error();
  EXPECT_EQ(server_->start_calls(), 0);
  EXPECT_EQ(server_->poll_calls(), 0);
  EXPECT_EQ(server_->registration_calls(), 0);

  {
    std::ifstream ifs(state_dir / "access_token.txt");
    std::string stored((std::istreambuf_iterator<char>(ifs)), {});
    EXPECT_EQ(stored, access_token);
  }
  {
    std::ifstream ifs(state_dir / "refresh_token.txt");
    std::string stored((std::istreambuf_iterator<char>(ifs)), {});
    EXPECT_EQ(stored, refresh_token);
  }

  const char *env_access = std::getenv("DEVICE_ACCESS_TOKEN");
  EXPECT_TRUE(env_access == nullptr || std::string_view(env_access).empty());
  const char *env_refresh = std::getenv("DEVICE_REFRESH_TOKEN");
  EXPECT_TRUE(env_refresh == nullptr || std::string_view(env_refresh).empty());

  misc::ThreadNotifier register_notifier(2000);
  std::optional<monad::MyVoidResult> register_result;
  handler_->register_device().run([&](auto r) {
    register_result = std::move(r);
    register_notifier.notify();
  });
  register_notifier.waitForNotification();

  ASSERT_TRUE(register_result.has_value());
  ASSERT_FALSE(register_result->is_err()) << register_result->error();
  EXPECT_EQ(server_->registration_calls(), 0);
}

TEST_F(LoginHandlerWorkflowTest, RefreshesUsingStoredRefreshToken) {
  auto state_dir = temp_dir.path / "state";
  fs::create_directories(state_dir);

  const auto now = std::chrono::system_clock::now();
  auto expired_access =
      jwt::create()
          .set_type("JWT")
          .set_payload_claim("sub", jwt::claim(server_->expected_user_id()))
          .set_expires_at(now - std::chrono::minutes(5))
          .sign(jwt::algorithm::hs256{"secret"});
  auto stored_refresh = server_->refresh_token();

  {
    std::ofstream ofs(state_dir / "access_token.txt");
    ofs << expired_access;
  }
  {
    std::ofstream ofs(state_dir / "refresh_token.txt");
    ofs << stored_refresh;
  }

  auto refreshed_access =
      jwt::create()
          .set_type("JWT")
          .set_payload_claim("sub", jwt::claim(server_->expected_user_id()))
          .set_payload_claim("device_id",
                             jwt::claim(std::string{"device-code-xyz"}))
          .set_expires_at(now + std::chrono::hours(1))
          .sign(jwt::algorithm::hs256{"secret"});
  auto refreshed_refresh = server_->refresh_token() + "-rotated";
  server_->set_refresh_response_tokens(refreshed_access, refreshed_refresh);

  misc::ThreadNotifier notifier(5000);
  std::optional<monad::MyVoidResult> start_result;
  handler_->start().run([&](auto r) {
    start_result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();

  ASSERT_TRUE(start_result.has_value());
  ASSERT_FALSE(start_result->is_err()) << start_result->error();
  EXPECT_EQ(server_->start_calls(), 0);
  EXPECT_EQ(server_->poll_calls(), 0);
  EXPECT_EQ(server_->registration_calls(), 0);
  EXPECT_EQ(server_->refresh_calls(), 1);

  const char *env_access = std::getenv("DEVICE_ACCESS_TOKEN");
  EXPECT_TRUE(env_access == nullptr || std::string_view(env_access).empty());
  const char *env_refresh = std::getenv("DEVICE_REFRESH_TOKEN");
  EXPECT_TRUE(env_refresh == nullptr || std::string_view(env_refresh).empty());

  {
    std::ifstream ifs(state_dir / "access_token.txt");
    std::string stored((std::istreambuf_iterator<char>(ifs)), {});
    EXPECT_EQ(stored, refreshed_access);
  }
  {
    std::ifstream ifs(state_dir / "refresh_token.txt");
    std::string stored((std::istreambuf_iterator<char>(ifs)), {});
    EXPECT_EQ(stored, refreshed_refresh);
  }

  misc::ThreadNotifier register_notifier(2000);
  std::optional<monad::MyVoidResult> register_result;
  handler_->register_device().run([&](auto r) {
    register_result = std::move(r);
    register_notifier.notify();
  });
  register_notifier.waitForNotification();

  ASSERT_TRUE(register_result.has_value());
  ASSERT_FALSE(register_result->is_err()) << register_result->error();
  EXPECT_EQ(server_->registration_calls(), 0);
}

std::shared_ptr<customio::ConsoleOutputWithColor>
    LoginHandlerWorkflowTest::shared_output_;

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