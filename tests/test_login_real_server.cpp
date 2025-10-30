#include <boost/di.hpp>
#include <boost/json.hpp>
#include <boost/url.hpp>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "client_ssl_ctx.hpp"
#include "http_client_config_provider.hpp"
#include "http_client_manager.hpp"
#include "include/api_test_helper.hpp"
#include "include/login_helper.hpp"
#include "login_helper.hpp"
#include "misc_util.hpp"
#include "test_injector.hpp"


// $env:CERTCTRL_REAL_SERVER_TESTS='1';$env:CERT_CTRL_TEST_EMAIL='jianglibo@hotmail.com';$env:CERT_CTRL_TEST_PASSWORD='StrongPass1!'; ctest --build-config Debug -R RealServerLoginFixture.ApiKeyRegistersDevice --test-dir build/windows-debug/tests --output-on-failure

namespace di = boost::di;
namespace fs = std::filesystem;
namespace json = boost::json;

namespace {

bool real_server_tests_enabled() {
  const char *flag = std::getenv("CERTCTRL_REAL_SERVER_TESTS");
  return flag && *flag;
}

} // namespace

class RealServerLoginFixture : public ::testing::Test {
protected:
  client_async::HttpClientManager *http_client_mgr_;
  std::shared_ptr<cjj365::HttpclientConfigProviderFile> http_config_provider_;
  std::unique_ptr<cjj365::ClientSSLContext> client_ssl_ctx_;
  std::string base_url_;
  std::shared_ptr<void> injector_holder_;
  misc::ThreadNotifier notifier_{180000};
  std::string session_cookie_;
  int64_t user_id_{};
  std::vector<int64_t> cleanup_api_key_ids_;
  std::vector<int64_t> cleanup_device_ids_;

  void SetUp() override {
    if (!real_server_tests_enabled()) {
      GTEST_SKIP() << "Set CERTCTRL_REAL_SERVER_TESTS=1 to enable real server end-to-end tests.";
    }

    // Minimal inline config provider using a temp directory config file pattern
    // similar to existing tests We'll create a temporary directory with
    // httpclient_config.json if needed.
    base_url_ = testutil::url_base();
    static fs::path tmp_root =
        fs::temp_directory_path() / "certctrl-integration";
    fs::create_directories(tmp_root);
    fs::path http_cfg = tmp_root / "httpclient_config.json";
    if (!fs::exists(http_cfg)) {
      json::object httpclient_json{{"threads_num", 1},
                                   {"ssl_method", "tlsv12_client"},
                                   {"insecure_skip_verify", true},
                                   {"verify_paths", json::array{}},
                                   {"certificates", json::array{}},
                                   {"certificate_files", json::array{}},
                                   {"proxy_pool", json::array{}}};
      std::ofstream ofs(http_cfg);
      ofs << json::serialize(httpclient_json);
    }

    std::vector<fs::path> config_paths{tmp_root};
    std::vector<std::string> profiles;
    static cjj365::ConfigSources config_sources(config_paths, profiles);

    auto injector =
        di::make_injector(testinfra::build_base_injector(config_sources));

    using InjT = decltype(injector);
    auto real_inj = std::make_shared<InjT>(std::move(injector));
    injector_holder_ = real_inj;
    auto &inj = *real_inj;

    http_client_mgr_ = &inj.create<client_async::HttpClientManager &>();
    std::optional<monad::Result<data::LoginSuccess, monad::Error>> login_r;
    testutil::login_io(*http_client_mgr_, base_url_, testutil::login_email(),
                       testutil::login_password())
        .run([&](auto r) {
          login_r = std::move(r);
          notifier_.notify();
        });
    notifier_.waitForNotification();
    ASSERT_FALSE(login_r->is_err()) << "login failed: " << login_r->error();
    session_cookie_ = login_r->value().session_cookie;
    ASSERT_FALSE(session_cookie_.empty()) << "missing session cookie";
    user_id_ = login_r->value().user.id;
    ASSERT_GT(user_id_, 0) << "login returned invalid user_id";
  }
  void TearDown() override {
    for (auto device_id : cleanup_device_ids_) {
      misc::ThreadNotifier del_notifier(60000);
      std::optional<monad::MyVoidResult> del_result;
      testutil::delete_device_io(*http_client_mgr_, base_url_, session_cookie_,
                                 user_id_, device_id)
          .run([&](auto r) {
            del_result = std::move(r);
            del_notifier.notify();
          });
      del_notifier.waitForNotification();
      if (!del_result || del_result->is_err()) {
        std::cerr << "Failed to delete test device id=" << device_id << ": "
                  << (del_result ? del_result->error().what
                                 : "delete_device_io produced no result")
                  << std::endl;
      }
    }
    cleanup_device_ids_.clear();

    for (auto api_key_id : cleanup_api_key_ids_) {
      misc::ThreadNotifier del_notifier(60000);
      std::optional<monad::MyVoidResult> del_result;
      testutil::delete_api_key_io(*http_client_mgr_, base_url_, session_cookie_,
                                  user_id_, api_key_id)
          .run([&](auto r) {
            del_result = std::move(r);
            del_notifier.notify();
          });
      del_notifier.waitForNotification();
      if (!del_result || del_result->is_err()) {
        std::cerr << "Failed to delete test API key id=" << api_key_id
                  << ": "
                  << (del_result ? del_result->error().what
                                 : "delete_api_key_io produced no result")
                  << std::endl;
      }
    }
    cleanup_api_key_ids_.clear();
  }
};

TEST_F(RealServerLoginFixture, LoginAndStatus) {
  std::string base = testutil::url_base();
  std::optional<testutil::loginSuccessResult> r;
  auto io = testutil::login_io(*http_client_mgr_, base, testutil::login_email(),
                               testutil::login_password());
  io.run([&](auto rr) {
    r = std::move(rr);
    notifier_.notify();
  });
  notifier_.waitForNotification();
  ASSERT_FALSE(r->is_err()) << "Login failed: " << r->error();
  ASSERT_FALSE(r->value().user.email.empty());
  ASSERT_FALSE(r->value().session_cookie.empty());
}

TEST_F(RealServerLoginFixture, ApiKeyRegistersDevice) {
  auto options = testutil::default_api_key_options();
  auto now = std::chrono::system_clock::now().time_since_epoch();
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now).count();
  options.name += "-" + std::to_string(seconds);

  misc::ThreadNotifier api_key_notifier(60000);
  std::optional<monad::MyResult<testutil::ApiKeyInfo>> api_key_result;
  testutil::create_api_key_io(*http_client_mgr_, base_url_, session_cookie_,
                              user_id_, options)
      .run([&](auto r) {
        api_key_result = std::move(r);
        api_key_notifier.notify();
      });
  api_key_notifier.waitForNotification();
  ASSERT_TRUE(api_key_result.has_value())
      << "create_api_key_io produced no result";
  ASSERT_FALSE(api_key_result->is_err())
      << "create_api_key failed: " << api_key_result->error().what;

  const auto api_key = api_key_result->value();
  cleanup_api_key_ids_.push_back(api_key.id);
  ASSERT_FALSE(api_key.token.empty()) << "API key token is empty";

  auto registration_request = testutil::make_device_registration_request();

  misc::ThreadNotifier reg_notifier(60000);
  std::optional<monad::MyResult<testutil::DeviceRegistrationResult>> reg_result;
  testutil::register_device_with_apikey_io(*http_client_mgr_, base_url_,
                                           user_id_, api_key.token,
                                           registration_request)
      .run([&](auto r) {
        reg_result = std::move(r);
        reg_notifier.notify();
      });
  reg_notifier.waitForNotification();
  ASSERT_TRUE(reg_result.has_value())
      << "register_device_with_apikey_io produced no result";
  ASSERT_FALSE(reg_result->is_err())
      << "register_device_with_apikey failed: " << reg_result->error().what;

  const auto device_result = reg_result->value();
  if (device_result.device_id.has_value()) {
    cleanup_device_ids_.push_back(*device_result.device_id);
  }

  EXPECT_FALSE(device_result.access_token.empty())
      << "Device registration missing access token";

  misc::ThreadNotifier list_notifier(60000);
  std::optional<monad::MyResult<json::array>> list_result;
  testutil::list_devices_io(*http_client_mgr_, base_url_, session_cookie_,
                            user_id_)
      .run([&](auto r) {
        list_result = std::move(r);
        list_notifier.notify();
      });
  list_notifier.waitForNotification();
  ASSERT_TRUE(list_result.has_value())
      << "list_devices_io produced no result";
  ASSERT_FALSE(list_result->is_err())
      << "list_devices failed: " << list_result->error().what;

  const auto &devices = list_result->value();
  bool found = false;
  for (const auto &entry : devices) {
    if (!entry.is_object()) {
      continue;
    }
    const auto &device_obj = entry.as_object();
    const auto *public_id = device_obj.if_contains("device_public_id");
    if (public_id && public_id->is_string() &&
        public_id->as_string() == device_result.device_public_id) {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Registered device not found in inventory";
}
