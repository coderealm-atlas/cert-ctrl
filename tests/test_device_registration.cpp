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
#include "handlers/login_handler.hpp"
#include "http_client_config_provider.hpp"
#include "http_client_manager.hpp"
#include "include/login_helper.hpp"
#include "io_context_manager.hpp"
#include "log_stream.hpp"
#include "misc_util.hpp"

namespace di = boost::di;
namespace fs = std::filesystem;
namespace json = boost::json;

namespace {

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

    misc::ThreadNotifier login_notifier(60000);
    std::optional<testutil::loginSuccessResult> login_result;
    testutil::login_io(*http_client_manager_, base_url_,
                       testutil::login_email(), testutil::login_password())
        .run([&](auto r) {
          login_result = std::move(r);
          login_notifier.notify();
        });
    login_notifier.waitForNotification();
    ASSERT_TRUE(login_result.has_value()) << "login_io produced no result";
    ASSERT_FALSE(login_result->is_err())
        << "login failed: " << login_result->error().what;
    session_cookie_ = login_result->value().session_cookie;
    user_id_ = login_result->value().user.id;
    ASSERT_FALSE(session_cookie_.empty()) << "login returned empty cookie";
    ASSERT_GT(user_id_, 0) << "login returned invalid user_id";

#ifdef _WIN32
  _putenv_s("CERT_CTRL_SESSION_COOKIE", session_cookie_.c_str());
  _putenv_s("CERT_CTRL_USER_ID", std::to_string(user_id_).c_str());
  _putenv_s("DEVICE_ACCESS_TOKEN", "");
  _putenv_s("DEVICE_REFRESH_TOKEN", "");
#else
  ::setenv("CERT_CTRL_SESSION_COOKIE", session_cookie_.c_str(), 1);
  ::setenv("CERT_CTRL_USER_ID", std::to_string(user_id_).c_str(), 1);
  ::unsetenv("DEVICE_ACCESS_TOKEN");
  ::unsetenv("DEVICE_REFRESH_TOKEN");
#endif
  }

  void TearDown() override {}
};

} // namespace

TEST_F(RealServerLoginHandlerFixture, StartAndPollOnceRealServer) {
  using StartRespResult = monad::MyResult<data::deviceauth::StartResp>;
  using PollRespResult = monad::MyResult<data::deviceauth::PollResp>;

  misc::ThreadNotifier start_notifier(180000);
  std::optional<StartRespResult> start_result;
  handler_->start_device_authorization().run([&](auto r) {
    start_result = std::move(r);
    start_notifier.notify();
  });
  start_notifier.waitForNotification();

  ASSERT_TRUE(start_result.has_value())
      << "start_device_authorization yielded no result";
  ASSERT_FALSE(start_result->is_err())
      << "device_start failed: " << start_result->error().what;

  const auto start_resp = start_result->value();
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

  misc::ThreadNotifier verify_notifier(60000);
  std::optional<monad::MyResult<data::deviceauth::VerifyResp>> verify_result;
  testutil::device_verify_io(*http_client_manager_, base_url_, session_cookie_,
               start_resp.user_code)
    .run([&](auto r) {
    verify_result = std::move(r);
    verify_notifier.notify();
    });
  verify_notifier.waitForNotification();

  ASSERT_TRUE(verify_result.has_value())
    << "device_verify produced no result";
  if (verify_result->is_err()) {
    std::cerr << "Verify error code: " << verify_result->error().code << std::endl;
    std::cerr << "Verify error what: " << verify_result->error().what << std::endl;
    std::cerr << "Verify error response_status: " << verify_result->error().response_status << std::endl;
    if (verify_result->error().params.contains("response_body_preview")) {
      std::cerr << "Response body preview: " 
                << verify_result->error().params.at("response_body_preview") << std::endl;
    }
  }
  ASSERT_FALSE(verify_result->is_err())
    << "device_verify failed: " << verify_result->error().what;
  EXPECT_EQ(verify_result->value().status, "approved");

  const auto poll_sleep =
      std::chrono::seconds(std::clamp(start_resp.interval, 1, 10));
  const int max_attempts =
      std::clamp(start_resp.expires_in / start_resp.interval, 1, 12);
  std::cerr << "max_attemps: " << max_attempts << std::endl;
  std::optional<data::deviceauth::PollResp> successful_poll;
  std::string last_status;

  for (int attempt = 0; attempt < max_attempts; ++attempt) {
    misc::ThreadNotifier poll_notifier(60000);
    std::optional<PollRespResult> poll_result;
    handler_->poll_device_once().run([&](auto r) {
      poll_result = std::move(r);
      poll_notifier.notify();
    });
    poll_notifier.waitForNotification();

    ASSERT_TRUE(poll_result.has_value())
        << "device_poll attempt " << attempt << " produced no result";
    ASSERT_FALSE(poll_result->is_err())
        << "device_poll failed: " << poll_result->error().what;

    const auto poll_resp = poll_result->value();
    ASSERT_FALSE(poll_resp.status.empty())
        << "device_poll returned empty status";
    last_status = poll_resp.status;

    if (last_status == "approved" || last_status == "ready") {
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

    if (last_status == "authorization_pending" ||
        last_status == "slow_down" || last_status == "pending") {
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

  misc::ThreadNotifier register_notifier(60000);
  std::optional<monad::MyVoidResult> register_result;
  handler_->register_device().run([&](auto r) {
    register_result = std::move(r);
    register_notifier.notify();
  });
  register_notifier.waitForNotification();

  ASSERT_TRUE(register_result.has_value())
      << "register_device produced no result";
  ASSERT_FALSE(register_result->is_err())
      << "device_register failed: " << register_result->error().what;

  // Verify the device was registered by querying the user's devices
  std::cerr << "Verifying device registration by querying devices list..." << std::endl;
  misc::ThreadNotifier devices_notifier(60000);
  std::optional<monad::MyResult<json::array>> devices_result;
  testutil::list_user_devices_io(*http_client_manager_, base_url_, session_cookie_, user_id_)
      .run([&](auto r) {
        devices_result = std::move(r);
        devices_notifier.notify();
      });
  devices_notifier.waitForNotification();

  ASSERT_TRUE(devices_result.has_value())
      << "list_user_devices produced no result";
  ASSERT_FALSE(devices_result->is_err())
      << "list_user_devices failed: " << devices_result->error().what;

  const auto& devices = devices_result->value();
  std::cerr << "Found " << devices.size() << " device(s) for user " << user_id_ << std::endl;
  
  // Print device details for debugging
  for (const auto& device : devices) {
    std::cerr << "Device: " << json::serialize(device) << std::endl;
  }

  // Verify we have at least one device (the one we just registered)
  ASSERT_GT(devices.size(), 0)
      << "Expected at least one registered device, but found none";

  std::cerr << "Device registration verified successfully!" << std::endl;
}
