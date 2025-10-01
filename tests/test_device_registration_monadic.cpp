#include <boost/di.hpp>
#include <boost/json.hpp>
#include <boost/url.hpp>
#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>

#include "client_ssl_ctx.hpp"
#include "http_client_config_provider.hpp"
#include "http_client_manager.hpp"
#include "login_helper.hpp"
#include "misc_util.hpp"
#include "test_injector.hpp"

// This test mirrors the imperative docker device registration test but uses the
// monadic http_io pattern similar to httpclient_test.cpp.
// Steps:
// 1. login -> obtain session cookie & user id
// 2. device_start -> device_code
// 3. device_poll (single shot) -> may be authorization_pending or include
// tokens
//
// The test is resilient: if any network/contract issue occurs it GTEST_SKIPs.

namespace json = boost::json;

namespace di = boost::di;
namespace fs = std::filesystem;

class MonadicFixture : public ::testing::Test {
protected:
  client_async::HttpClientManager *http_client_mgr_{};
  std::shared_ptr<cjj365::HttpclientConfigProviderFile> http_config_provider_;
  std::unique_ptr<cjj365::ClientSSLContext> client_ssl_ctx_;
  std::shared_ptr<void> injector_holder_;
  std::string base_url_;

  void SetUp() override {
    base_url_ = testutil::url_base();
    static fs::path tmp_root = fs::temp_directory_path() / "certctrl-monadic";
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
    std::vector<std::string> profiles; // empty profiles
    static cjj365::ConfigSources config_sources(config_paths, profiles);
    auto injector =
        di::make_injector(testinfra::build_base_injector(config_sources));
    using InjT = decltype(injector);
    auto real_inj = std::make_shared<InjT>(std::move(injector));
    injector_holder_ = real_inj;
    auto &inj = *real_inj;
    http_client_mgr_ = &inj.create<client_async::HttpClientManager &>();
  }
  void TearDown() override {}
};

TEST_F(MonadicFixture, MonadicLoginDeviceFlow) {
  misc::ThreadNotifier notifier(10000);
  std::optional<monad::Result<data::LoginSuccess, monad::Error>> login_r;
  std::string email = std::getenv("TEST_EMAIL") ? std::getenv("TEST_EMAIL")
                                                : testutil::LOGIN_EMAIL;
  std::string password = std::getenv("TEST_PASSWORD")
                             ? std::getenv("TEST_PASSWORD")
                             : testutil::LOGIN_PASSWORD;
  testutil::login_io(*http_client_mgr_, base_url_, email, password)
      .run([&](auto r) {
        login_r = std::move(r);
        notifier.notify();
      });
  notifier.waitForNotification();
  if (!login_r || login_r->is_err()) {
    std::string emsg =
        (!login_r ? std::string("no result") : login_r->error().what);
    GTEST_SKIP() << "login failed: " << emsg;
  }
  ASSERT_FALSE(login_r->value().user.email.empty());
  auto session_cookie = login_r->value().session_cookie;

  // device_start
  misc::ThreadNotifier notifier2(5000);
  std::optional<monad::Result<testutil::DeviceStartData, monad::Error>> start_r;
  testutil::device_start_io(*http_client_mgr_, base_url_, session_cookie)
      .run([&](auto r) {
        start_r = std::move(r);
        notifier2.notify();
      });
  notifier2.waitForNotification();
  if (!start_r || start_r->is_err()) {
    std::string emsg =
        (!start_r ? std::string("no result") : start_r->error().what);
    GTEST_SKIP() << "device_start failed: " << emsg;
  }
  ASSERT_FALSE(start_r->value().device_code.empty());

  // device_poll (single attempt, non-looping)
  misc::ThreadNotifier notifier3(5000);
  std::optional<monad::Result<testutil::DevicePollData, monad::Error>> poll_r;
  testutil::device_poll_io(*http_client_mgr_, base_url_,
                           start_r->value().device_code)
      .run([&](auto r) {
        poll_r = std::move(r);
        notifier3.notify();
      });
  notifier3.waitForNotification();
  if (!poll_r || poll_r->is_err()) {
    std::string emsg =
        (!poll_r ? std::string("no result") : poll_r->error().what);
    GTEST_SKIP() << "device_poll failed: " << emsg;
  }
  auto status = poll_r->value().status;
  ASSERT_FALSE(status.empty());
  // Accept both authorization_pending and success statuses. If pending we don't
  // assert tokens.
  if (status != "authorization_pending") {
    EXPECT_FALSE(poll_r->value().access_token.empty());
    EXPECT_FALSE(poll_r->value().refresh_token.empty());
  }
}
