#include <gtest/gtest.h>

#include <algorithm>
#include <boost/di.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "data/device_auth_types.hpp"
#include "handlers/login_handler.hpp"
#include "http_client_config_provider.hpp"
#include "http_client_manager.hpp"
#include "include/awaitable_test_helper.hpp"
#include "include/login_helper.hpp"
#include "io_context_manager.hpp"
#include "log_stream.hpp"
#include "misc_util.hpp"
#include "state/device_state_store.hpp"

namespace di = boost::di;
namespace fs = std::filesystem;
namespace json = boost::json;

namespace {

bool real_server_tests_enabled() {
  const char *flag = std::getenv("CERTCTRL_REAL_SERVER_TESTS");
  return flag && flag[0] != '\0' && flag[0] != '0';
}

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
    auto base = fs::temp_directory_path() / "certctrl-real-handler";
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

class RealServerLoginHandlerFixture : public ::testing::Test {
protected:
  TempDir temp_dir_{};
  std::shared_ptr<void> injector_holder_;
  std::shared_ptr<certctrl::LoginHandler> handler_;
  certctrl::ICertctrlConfigProvider *config_provider_{};
  cjj365::IIoContextManager *io_context_manager_{};
  client_async::HttpClientManager *http_client_manager_{};
  std::string base_url_;
  std::string session_cookie_;
  int64_t user_id_{};

  void SetUp() override {
    if (!real_server_tests_enabled()) {
      GTEST_SKIP() << "Set CERTCTRL_REAL_SERVER_TESTS=1 to enable real server "
                      "end-to-end tests.";
    }

    base_url_ = testutil::url_base();

    json::object app_json{{"auto_apply_config", false},
                          {"verbose", "info"},
                          {"url_base", base_url_}};
    write_json_file(temp_dir_.path / "application.json", app_json);

    json::object httpclient_json{{"threads_num", 1},
                                 {"ssl_method", "tlsv12_client"},
                                 {"insecure_skip_verify", true},
                                 {"verify_paths", json::array{}},
                                 {"certificates", json::array{}},
                                 {"certificate_files", json::array{}},
                                 {"proxy_pool", json::array{}}};
    write_json_file(temp_dir_.path / "httpclient_config.json", httpclient_json);

    json::object ioc_json{{"threads_num", 1}, {"name", "real-handler-ioc"}};
    write_json_file(temp_dir_.path / "ioc_config.json", ioc_json);

    certctrl::CliParams params;
    params.subcmd = "login";
    params.config_dirs = {temp_dir_.path};

    boost::program_options::variables_map vm;
    std::vector<std::string> positionals{"login"};
    std::vector<std::string> unrecognized;
    static certctrl::CliCtx cli_ctx(std::move(vm), std::move(positionals),
                                    std::move(unrecognized), std::move(params));

    std::vector<fs::path> config_paths{temp_dir_.path};
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
        di::bind<certctrl::IDeviceStateStore>()
            .to<certctrl::SqliteDeviceStateStore>()
            .in(di::singleton),
        di::bind<cjj365::IIoContextManager>().to<cjj365::IoContextManager>().in(
            di::singleton));

    using InjT = decltype(injector);
    auto real_inj = std::make_shared<InjT>(std::move(injector));
    injector_holder_ = real_inj;
    auto &inj = *real_inj;

    config_provider_ = &inj.create<certctrl::ICertctrlConfigProvider &>();
    config_provider_->get().base_url = base_url_;
    handler_ = inj.create<std::shared_ptr<certctrl::LoginHandler>>();
    io_context_manager_ = &inj.create<cjj365::IIoContextManager &>();
    http_client_manager_ = &inj.create<client_async::HttpClientManager &>();

    auto login_result = testinfra::run_result_awaitable(
        io_context_manager_->ioc(),
        testutil::login_awaitable(*http_client_manager_, base_url_,
                                  testutil::login_email(),
                                  testutil::login_password()),
        std::chrono::seconds(60));
    ASSERT_FALSE(login_result.is_err())
        << "login failed: " << login_result.error().what;
    session_cookie_ = login_result.value().session_cookie;
    user_id_ = login_result.value().user.id;
    ASSERT_FALSE(session_cookie_.empty()) << "login returned empty cookie";
    ASSERT_GT(user_id_, 0) << "login returned invalid user_id";

#ifdef _WIN32
    _putenv_s("DEVICE_ACCESS_TOKEN", "");
    _putenv_s("DEVICE_REFRESH_TOKEN", "");
#else
    ::unsetenv("DEVICE_ACCESS_TOKEN");
    ::unsetenv("DEVICE_REFRESH_TOKEN");
#endif
  }

  void TearDown() override {}
};

} // namespace

TEST(DeviceAuthTypes, PollRespParsesNumericUserId) {
  const std::string payload =
      R"({"status":"ready","user_id":1,"registration_code":"code"})";
  auto value = json::parse(payload);
  auto resp = json::value_to<data::deviceauth::PollResp>(value);
  ASSERT_TRUE(resp.user_id.has_value());
  EXPECT_EQ(*resp.user_id, "1");
  EXPECT_EQ(resp.status, "ready");
}

TEST_F(RealServerLoginHandlerFixture, StartAndPollOnceRealServer) {
  auto start_result =
      testinfra::run_result_awaitable<data::deviceauth::StartResp>(
          io_context_manager_->ioc(),
          handler_->start_device_authorization_awaitable(),
          std::chrono::seconds(180));
  ASSERT_FALSE(start_result.is_err())
      << "device_start failed: " << start_result.error().what;

  const auto start_resp = start_result.value();
  ASSERT_FALSE(start_resp.device_code.empty()) << "missing device_code";
  ASSERT_FALSE(start_resp.user_code.empty()) << "missing user_code";
  ASSERT_FALSE(start_resp.verification_uri.empty())
      << "missing verification_uri";
  ASSERT_GT(start_resp.interval, 0);
  ASSERT_GT(start_resp.expires_in, 0);

  // Log the session cookie for debugging
  std::cerr << "Session cookie: " << session_cookie_ << std::endl;
  std::cerr << "User code: " << start_resp.user_code << std::endl;
  std::cerr << "Verification URI: " << start_resp.verification_uri << std::endl;

  auto verify_result = testinfra::run_result_awaitable(
      io_context_manager_->ioc(),
      testutil::device_verify_awaitable(*http_client_manager_, base_url_,
                                        session_cookie_, start_resp.user_code),
      std::chrono::seconds(60));

  if (verify_result.is_err()) {
    std::cerr << "Verify error code: " << verify_result.error().code
              << std::endl;
    std::cerr << "Verify error what: " << verify_result.error().what
              << std::endl;
    std::cerr << "Verify error response_status: "
              << verify_result.error().response_status << std::endl;
    if (verify_result.error().params.contains("response_body_preview")) {
      std::cerr << "Response body preview: "
                << verify_result.error().params.at("response_body_preview")
                << std::endl;
    }
  }
  ASSERT_FALSE(verify_result.is_err())
      << "device_verify failed: " << verify_result.error().what;
  EXPECT_EQ(verify_result.value().status, "approved");

  const auto poll_sleep =
      std::chrono::seconds(std::clamp(start_resp.interval, 1, 10));
  const int max_attempts =
      std::clamp(start_resp.expires_in / start_resp.interval, 1, 12);
  std::cerr << "max_attemps: " << max_attempts << std::endl;
  std::optional<data::deviceauth::PollResp> successful_poll;
  std::string last_status;

  for (int attempt = 0; attempt < max_attempts; ++attempt) {
    auto poll_result =
        testinfra::run_result_awaitable<data::deviceauth::PollResp>(
            io_context_manager_->ioc(), handler_->poll_device_once_awaitable(),
            std::chrono::seconds(60));
    ASSERT_FALSE(poll_result.is_err())
        << "device_poll failed: " << poll_result.error().what;

    const auto poll_resp = poll_result.value();
    ASSERT_FALSE(poll_resp.status.empty())
        << "device_poll returned empty status";
    last_status = poll_resp.status;

    if (last_status == "approved" || last_status == "ready") {
      ASSERT_TRUE(poll_resp.user_id.has_value())
          << "ready poll response missing user_id";
      ASSERT_FALSE(poll_resp.user_id->empty())
          << "ready poll response contained empty user_id";
      if (poll_resp.registration_code &&
          !poll_resp.registration_code->empty()) {
        successful_poll = poll_resp;
        break;
      }
      if (poll_resp.access_token && !poll_resp.access_token->empty()) {
        successful_poll = poll_resp;
        break;
      }
      FAIL() << "ready status missing registration_code or access_token";
    }

    if (last_status == "authorization_pending" || last_status == "slow_down" ||
        last_status == "pending") {
      std::this_thread::sleep_for(poll_sleep);
      continue;
    }

    FAIL() << "device_poll returned terminal status '" << last_status << "'";
  }

  ASSERT_TRUE(successful_poll.has_value())
      << "device authorization did not complete; last status=" << last_status;
  EXPECT_TRUE(successful_poll->registration_code.has_value())
      << "ready poll response missing registration_code";
  if (successful_poll->registration_code.has_value()) {
    EXPECT_FALSE(successful_poll->registration_code->empty())
        << "registration_code should not be empty";
  }
  ASSERT_TRUE(successful_poll->user_id.has_value())
      << "ready poll response missing user_id";
  EXPECT_FALSE(successful_poll->user_id->empty())
      << "ready poll response contained empty user_id";

  auto register_result = testinfra::run_result_awaitable<void>(
      io_context_manager_->ioc(), handler_->register_device_awaitable(),
      std::chrono::seconds(60));
  ASSERT_FALSE(register_result.is_err())
      << "device_register failed: " << register_result.error().what;

  // Verify the device was registered by querying the user's devices
  std::cerr << "Verifying device registration by querying devices list..."
            << std::endl;
  auto devices_result = testinfra::run_result_awaitable(
      io_context_manager_->ioc(),
      testutil::list_user_devices_awaitable(*http_client_manager_, base_url_,
                                            session_cookie_, user_id_),
      std::chrono::seconds(60));
  ASSERT_FALSE(devices_result.is_err())
      << "list_user_devices failed: " << devices_result.error().what;

  const auto &devices = devices_result.value();
  std::cerr << "Found " << devices.size() << " device(s) for user " << user_id_
            << std::endl;

  // Print device details for debugging
  for (const auto &device : devices) {
    std::cerr << "Device: " << json::serialize(device) << std::endl;
  }

  // Verify we have at least one device (the one we just registered)
  ASSERT_GT(devices.size(), 0)
      << "Expected at least one registered device, but found none";

  std::cerr << "Device registration verified successfully!" << std::endl;
}
