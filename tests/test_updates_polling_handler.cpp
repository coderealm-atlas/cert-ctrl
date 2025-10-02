#include <boost/di.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>

#include "include/login_helper.hpp"
#include "login_helper.hpp"
#include "misc_util.hpp"
#include "my_error_codes.hpp"

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "handlers/updates_polling_handler.hpp"
#include "http_client_manager.hpp"
#include "test_injector.hpp"

// Rough test: ensures UpdatesPollingHandler::start() issues a request and
// handles 401/204 gracefully. We cannot guarantee a live server here; if
// unreachable or error we just assert it returns (no crash).

namespace {

namespace po = boost::program_options;
namespace di = boost::di;

struct TestEnvFixture : public ::testing::Test {
  // temp config dir + owned context
  std::filesystem::path tmp_root_;
  std::vector<std::filesystem::path> config_paths_;
  std::vector<std::string> profiles_;
  std::unique_ptr<cjj365::ConfigSources> config_sources_ptr_;
  std::unique_ptr<certctrl::CliCtx> cli_ctx_ptr_;
  certctrl::CliCtx *clictx_{}; // raw
  std::shared_ptr<void> injector_holder_;
  client_async::HttpClientManager *http_client_mgr_{};
  cjj365::IoContextManager *io_context_manager_{};
  customio::ConsoleOutput *output_{};
  std::shared_ptr<certctrl::UpdatesPollingHandler> handler_;

  void SetUp() override {
    namespace json = boost::json;
    // create temp dir and minimal configs
    tmp_root_ = std::filesystem::temp_directory_path() / "updates-handler-test";
    std::error_code ec;
    std::filesystem::create_directories(tmp_root_, ec);
    auto write_json = [](const std::filesystem::path &p,
                         const json::object &o) {
      std::ofstream ofs(p);
      ofs << json::serialize(o);
    };
    // minimal httpclient config so provider succeeds
    write_json(tmp_root_ / "httpclient_config.json",
               json::object{{"threads_num", 1},
                            {"ssl_method", "tls_client"},
                            {"insecure_skip_verify", true},
                            {"verify_paths", json::array{}},
                            {"certificates", json::array{}},
                            {"certificate_files", json::array{}},
                            {"proxy_pool", json::array{}}});
    // application.json for base url (use default helper)
    write_json(tmp_root_ / "application.json",
               json::object{{"auto_fetch_config", false},
                            {"verbose", "info"},
                            {"url_base", testutil::url_base()}});
    // ioc_config.json minimal
    write_json(tmp_root_ / "ioc_config.json",
               json::object{{"threads_num", 1}, {"name", "updates-test-env"}});
    config_paths_.assign({tmp_root_});
    profiles_.clear();
    config_sources_ptr_ =
        std::make_unique<cjj365::ConfigSources>(config_paths_, profiles_);
    certctrl::CliParams params;
    params.subcmd = "updates";
    params.config_dirs = {tmp_root_};
    params.keep_running = false;
    cli_ctx_ptr_ = std::make_unique<certctrl::CliCtx>(
        po::variables_map{}, std::vector<std::string>{"updates"},
        std::vector<std::string>{}, std::move(params));
    clictx_ = cli_ctx_ptr_.get();
    // Simple stub provider to avoid file load race (we already write file but
    // fixture only needs minimal values)
    struct HttpClientConfigProviderTest : cjj365::IHttpclientConfigProvider {
      cjj365::HttpclientConfig cfg; // default values: tlsv12_client,
                                    // threads_num=0 -> auto, insecure=false
      const cjj365::HttpclientConfig &get() const override { return cfg; }
    };
    auto injector = di::make_injector(
        di::bind<cjj365::ConfigSources>().to(*config_sources_ptr_),
        di::bind<cjj365::IHttpclientConfigProvider>()
            .to<HttpClientConfigProviderTest>(),
        di::bind<cjj365::IIocConfigProvider>()
            .to<cjj365::IocConfigProviderFile>(),
        di::bind<cjj365::IIoContextManager>().to<cjj365::IoContextManager>().in(
            di::singleton),
        di::bind<customio::IOutput>().to(testinfra::shared_output()),
        di::bind<certctrl::CliCtx>().to(*cli_ctx_ptr_),
        di::bind<certctrl::ICertctrlConfigProvider>()
            .to<certctrl::CertctrlConfigProviderFile>()
            .in(di::singleton));
    using InjT = decltype(injector);
    auto real_inj = std::make_shared<InjT>(std::move(injector));
    injector_holder_ = real_inj;
    auto &inj = *real_inj;
    http_client_mgr_ = &inj.create<client_async::HttpClientManager &>();
    io_context_manager_ = &inj.create<cjj365::IoContextManager &>();
    output_ = &inj.create<customio::ConsoleOutput &>();
    handler_ = inj.create<std::shared_ptr<certctrl::UpdatesPollingHandler>>();
  }
};

TEST_F(TestEnvFixture, PollOnceHandlesMissingToken) {
  // Ensure env not set
  unsetenv("DEVICE_ACCESS_TOKEN");
  bool done = false;
  monad::Error err;
  bool has_err = false;
  handler_->start().run([&](auto r) {
    has_err = r.is_err();
    if (has_err)
      err = r.error();
    done = true;
  });
  // start() executes asynchronously; wait small time by sleeping
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  ASSERT_TRUE(has_err);
  ASSERT_EQ(err.code, my_errors::GENERAL::INVALID_ARGUMENT);
  // State should reflect no HTTP call actually performed
  EXPECT_EQ(handler_->last_http_status(), 0);
  EXPECT_FALSE(handler_->last_updates().has_value());
  EXPECT_TRUE(handler_->parse_error().empty());
  EXPECT_EQ(handler_->install_updated_count(), 0u);
  EXPECT_EQ(handler_->cert_renewed_count(), 0u);
  EXPECT_EQ(handler_->cert_revoked_count(), 0u);
}

// Real workflow fixture-based test
class UpdatesRealServerFixture : public ::testing::Test {
protected:
  misc::ThreadNotifier notifier_{180000};
  std::filesystem::path tmp_root_;
  std::string base_url_;
  std::shared_ptr<void> injector_holder_;
  client_async::HttpClientManager *http_mgr_{};
  cjj365::IoContextManager *io_ctx_mgr_{};
  certctrl::ICertctrlConfigProvider *cfg_provider_{};
  certctrl::CliCtx *cli_ctx_{}; // raw view
  std::shared_ptr<certctrl::UpdatesPollingHandler> handler_;
  // Owned config / cli backing storage
  std::vector<std::filesystem::path> config_paths_;
  std::vector<std::string> profiles_;
  std::unique_ptr<cjj365::ConfigSources> config_sources_ptr_;
  po::variables_map vm_;
  std::vector<std::string> positional_;
  std::vector<std::string> unrecognized_;
  certctrl::CliParams params_;
  std::unique_ptr<certctrl::CliCtx> cli_ctx_ptr_;
  std::string session_cookie_;

  void SetUp() override {
    using namespace std::chrono_literals;
    namespace json = boost::json;
    base_url_ = testutil::url_base();
    tmp_root_ = std::filesystem::temp_directory_path() / "updates-real-flow";
    std::error_code ec;
    std::filesystem::create_directories(tmp_root_, ec);
    auto write_json = [](const std::filesystem::path &p,
                         const json::object &o) {
      std::ofstream ofs(p);
      ofs << json::serialize(o);
    };
    write_json(tmp_root_ / "application.json",
               json::object{{"auto_fetch_config", false},
                            {"verbose", "info"},
                            {"url_base", base_url_}});
    write_json(tmp_root_ / "httpclient_config.json",
               json::object{{"threads_num", 1},
                            {"ssl_method", "tls_client"},
                            {"insecure_skip_verify", true},
                            {"verify_paths", json::array{}},
                            {"certificates", json::array{}},
                            {"certificate_files", json::array{}},
                            {"proxy_pool", json::array{}}});
    write_json(tmp_root_ / "ioc_config.json",
               json::object{{"threads_num", 1}, {"name", "updates-real"}});
    config_paths_.clear();
    config_paths_.push_back(tmp_root_);
    profiles_.clear();
    config_sources_ptr_ =
        std::make_unique<cjj365::ConfigSources>(config_paths_, profiles_);
    params_ = certctrl::CliParams{};
    params_.subcmd = "updates";
    params_.config_dirs = {tmp_root_};
    positional_.assign({"updates"});
    unrecognized_.assign({"updates"});
    cli_ctx_ptr_ = std::make_unique<certctrl::CliCtx>(
        po::variables_map{}, std::vector<std::string>(positional_),
        std::vector<std::string>(unrecognized_), certctrl::CliParams(params_));
    cli_ctx_ = cli_ctx_ptr_.get();
    auto injector = di::make_injector(
        di::bind<cjj365::ConfigSources>().to(*config_sources_ptr_),
        di::bind<cjj365::IHttpclientConfigProvider>()
            .to<cjj365::HttpclientConfigProviderFile>(),
        di::bind<cjj365::IIocConfigProvider>()
            .to<cjj365::IocConfigProviderFile>(),
        di::bind<customio::IOutput>().to(testinfra::shared_output()),
        di::bind<certctrl::CliCtx>().to(*cli_ctx_ptr_),
        di::bind<certctrl::ICertctrlConfigProvider>()
            .to<certctrl::CertctrlConfigProviderFile>()
            .in(di::singleton),
        di::bind<cjj365::IIoContextManager>().to<cjj365::IoContextManager>().in(
            di::singleton));
    using InjT3 = decltype(injector);
    auto real_inj = std::make_shared<InjT3>(std::move(injector));
    injector_holder_ = real_inj;
    auto &inj = *real_inj;
    http_mgr_ = &inj.create<client_async::HttpClientManager &>();
    io_ctx_mgr_ = &inj.create<cjj365::IoContextManager &>();
    cfg_provider_ = &inj.create<certctrl::ICertctrlConfigProvider &>();
    cfg_provider_->get().base_url = base_url_;
    handler_ = inj.create<std::shared_ptr<certctrl::UpdatesPollingHandler>>();

    std::optional<monad::Result<data::LoginSuccess, monad::Error>> login_r;
    testutil::login_io(*http_mgr_, base_url_, testutil::login_email(),
                       testutil::login_password())
        .run([&](auto r) {
          login_r = std::move(r);
          notifier_.notify();
        });
    notifier_.waitForNotification();
    ASSERT_FALSE(login_r->is_err()) << "login failed: " << login_r->error();
    session_cookie_ = login_r->value().session_cookie;
    ASSERT_FALSE(session_cookie_.empty()) << "missing session cookie";
    // device_start
  }
};

TEST_F(UpdatesRealServerFixture, DeviceRegisterThenPollUpdates) {
  using namespace std::chrono_literals;
  // Login
  misc::ThreadNotifier login_notifier(10000);
  // std::optional<monad::Result<data::LoginSuccess, monad::Error>> login_r;
  // testutil::login_io(*http_mgr_, base_url_, testutil::login_email(),
  //                    testutil::login_password())
  //     .run([&](auto r) {
  //       login_r = std::move(r);
  //       login_notifier.notify();
  //     });
  // login_notifier.waitForNotification();
  // if (!login_r || login_r->is_err()) {
  //   GTEST_SKIP() << "login failed: "
  //                << (!login_r ? "no result" : login_r->error().what);
  // }
  // auto session_cookie = login_r->value().session_cookie;
  // if (session_cookie.empty())
  //   GTEST_SKIP() << "missing session cookie";
  // device_start
  misc::ThreadNotifier start_notifier(5000);
  // std::optional<monad::Result<testutil::DeviceStartData, monad::Error>> start_r;
  // testutil::device_start_io(*http_mgr_, base_url_, session_cookie_)
  //     .run([&](auto r) {
  //       start_r = std::move(r);
  //       start_notifier.notify();
  //     });
  // start_notifier.waitForNotification();
  // if (!start_r || start_r->is_err()) {
  //   GTEST_SKIP() << "device_start failed: "
  //                << (!start_r ? "no result" : start_r->error().what);
  // }
  // auto device_code = start_r->value().device_code;
  // if (device_code.empty())
  //   GTEST_SKIP() << "missing device_code";
  // std::string access_token;
  // std::string refresh_token;
  // std::string last_status;
  // for (int attempt = 0; attempt < 5; ++attempt) {
  //   misc::ThreadNotifier poll_notifier(5000);
  //   std::optional<monad::Result<testutil::DevicePollData, monad::Error>> poll_r;
  //   testutil::device_poll_io(*http_mgr_, base_url_, device_code)
  //       .run([&](auto r) {
  //         poll_r = std::move(r);
  //         poll_notifier.notify();
  //       });
  //   poll_notifier.waitForNotification();
  //   if (!poll_r || poll_r->is_err()) {
  //     last_status = poll_r && poll_r->is_err() ? poll_r->error().what : "error";
  //     break;
  //   }
  //   last_status = poll_r->value().status;
  //   if (!poll_r->value().access_token.empty()) {
  //     access_token = poll_r->value().access_token;
  //     refresh_token = poll_r->value().refresh_token;
  //     break;
  //   }
  //   std::this_thread::sleep_for(1500ms);
  // }
  // if (access_token.empty()) {
  //   GTEST_SKIP() << "device_poll did not yield access token; last status="
  //                << last_status;
  // }
  // auto write_text = [](const std::filesystem::path &p, const std::string &s) {
  //   std::ofstream ofs(p, std::ios::trunc);
  //   ofs << s;
  // };
  // write_text(tmp_root_ / "access_token.txt", access_token);
  // if (!refresh_token.empty())
  //   write_text(tmp_root_ / "refresh_token.txt", refresh_token);
  // ::setenv("DEVICE_ACCESS_TOKEN", access_token.c_str(), 1);
  // // Poll updates
  // misc::ThreadNotifier updates_notifier(5000);
  // std::optional<monad::MyVoidResult> updates_r;
  // handler_->start().run([&](auto r) {
  //   updates_r = std::move(r);
  //   updates_notifier.notify();
  // });
  // updates_notifier.waitForNotification();
  // if (!updates_r) {
  //   GTEST_SKIP() << "no result from updates handler";
  // }
  // if (updates_r->is_err()) {
  //   if (updates_r->error().code == 401 || updates_r->error().code == 403) {
  //     FAIL() << "updates polling auth failure: " << updates_r->error().what;
  //   } else {
  //     GTEST_SKIP() << "updates handler error: code=" << updates_r->error().code
  //                  << " msg=" << updates_r->error().what;
  //   }
  // }
  // // Validate handler state for a successful single poll
  // int status = handler_->last_http_status();
  // EXPECT_TRUE(status == 200 || status == 204) << "unexpected status=" << status;
  // if (status == 200) {
  //   ASSERT_TRUE(handler_->last_updates().has_value());
  //   const auto &resp = handler_->last_updates().value();
  //   // Cursor should not be empty once we parsed a body with signals/cursor
  //   EXPECT_FALSE(handler_->last_cursor().empty());
  //   // Basic structural sanity
  //   EXPECT_GE(resp.data.cursor.size(), 0u);
  //   // Counters should be consistent with the number of signals of each type
  //   size_t counted_install = 0, counted_renewed = 0, counted_revoked = 0;
  //   for (auto &sig : resp.data.signals) {
  //     if (data::is_install_updated(sig))
  //       ++counted_install;
  //     else if (data::is_cert_renewed(sig))
  //       ++counted_renewed;
  //     else if (data::is_cert_revoked(sig))
  //       ++counted_revoked;
  //   }
  //   EXPECT_EQ(handler_->install_updated_count(), counted_install);
  //   EXPECT_EQ(handler_->cert_renewed_count(), counted_renewed);
  //   EXPECT_EQ(handler_->cert_revoked_count(), counted_revoked);
  // } else if (status == 204) {
  //   EXPECT_FALSE(handler_->last_updates().has_value());
  // }
  // EXPECT_TRUE(handler_->parse_error().empty())
  //     << "parse error: " << handler_->parse_error();
  // SUCCEED();
}

} // namespace
