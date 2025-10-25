#include <boost/di.hpp>
#include <boost/json.hpp>
#include <boost/url.hpp>
#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <string>

#include "client_ssl_ctx.hpp"
#include "http_client_config_provider.hpp"
#include "http_client_manager.hpp"
#include "include/login_helper.hpp"
#include "login_helper.hpp"
#include "misc_util.hpp"
#include "test_injector.hpp"

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
  }
  void TearDown() override {}
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
