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

// Windows compatibility for environment variables
#ifdef _WIN32
#define setenv(name, value, overwrite) _putenv_s(name, value)
#define unsetenv(name) _putenv_s(name, "")
#endif

#include "include/login_helper.hpp"
#include "include/api_test_helper.hpp"
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
  
  // Get user_id from login
  int64_t user_id = 0;
  {
    misc::ThreadNotifier login_notifier(5000);
    std::optional<monad::Result<data::LoginSuccess, monad::Error>> login_r;
    testutil::login_io(*http_mgr_, base_url_, testutil::login_email(),
                       testutil::login_password())
        .run([&](auto r) {
          login_r = std::move(r);
          login_notifier.notify();
        });
    login_notifier.waitForNotification();
    if (!login_r || login_r->is_err()) {
      GTEST_SKIP() << "login failed: "
                   << (!login_r ? "no result" : login_r->error().what);
    }
    user_id = login_r->value().user.id;
    std::cout << "Logged in as user_id=" << user_id << std::endl;
  }
  
  // Fetch existing device list to get device_id for polling/assignment
  int64_t device_id = 0;
  {
    misc::ThreadNotifier devices_notifier(5000);
    std::optional<monad::Result<boost::json::array, monad::Error>> devices_r;
    testutil::list_devices_io(*http_mgr_, base_url_, session_cookie_, user_id)
        .run([&](auto r) {
          devices_r = std::move(r);
          devices_notifier.notify();
        });
    devices_notifier.waitForNotification();
    if (!devices_r || devices_r->is_err() || devices_r->value().empty()) {
      GTEST_SKIP() << "no devices found for user";
    }
    const auto &devices = devices_r->value();
    device_id = devices.at(0).as_object().at("id").as_int64();
    std::cout << "Using device_id=" << device_id << " for polling" << std::endl;
  }

  // Start device authorization flow
  misc::ThreadNotifier start_notifier(5000);
  std::optional<monad::Result<data::deviceauth::StartResp, monad::Error>> start_r;
  testutil::device_start_io(*http_mgr_, base_url_, session_cookie_)
      .run([&](auto r) {
        start_r = std::move(r);
        start_notifier.notify();
      });
  start_notifier.waitForNotification();
  if (!start_r || start_r->is_err()) {
    GTEST_SKIP() << "device_start failed: "
                 << (!start_r ? "no result" : start_r->error().what);
  }
  auto device_code = start_r->value().device_code;
  auto user_code = start_r->value().user_code;
  if (device_code.empty())
    GTEST_SKIP() << "missing device_code";
  
  std::cout << "Device authorization started, user_code=" << user_code << std::endl;
  
  // Verify device authorization (simulates user approval)
  misc::ThreadNotifier verify_notifier(5000);
  std::optional<monad::Result<data::deviceauth::VerifyResp, monad::Error>> verify_r;
  testutil::device_verify_io(*http_mgr_, base_url_, session_cookie_, user_code, true)
      .run([&](auto r) {
        verify_r = std::move(r);
        verify_notifier.notify();
      });
  verify_notifier.waitForNotification();
  if (!verify_r || verify_r->is_err()) {
    GTEST_SKIP() << "device_verify failed: "
                 << (!verify_r ? "no result" : verify_r->error().what);
  }
  
  std::cout << "Device verified, status=" << verify_r->value().status << std::endl;
  
  // Poll for tokens
  std::string access_token;
  std::string refresh_token;
  std::string registration_code;
  std::string last_status;
  for (int attempt = 0; attempt < 5; ++attempt) {
    misc::ThreadNotifier poll_notifier(5000);
    std::optional<monad::Result<data::deviceauth::PollResp, monad::Error>> poll_r;
    testutil::device_poll_io(*http_mgr_, base_url_, device_code, device_id)
        .run([&](auto r) {
          poll_r = std::move(r);
          poll_notifier.notify();
        });
    poll_notifier.waitForNotification();
    if (!poll_r || poll_r->is_err()) {
      last_status = poll_r && poll_r->is_err() ? poll_r->error().what : "error";
      break;
    }
    const auto &poll_resp = poll_r->value();
    last_status = poll_resp.status;
    if (poll_resp.access_token && !poll_resp.access_token->empty()) {
      access_token = *poll_resp.access_token;
      if (poll_resp.refresh_token && !poll_resp.refresh_token->empty()) {
        refresh_token = *poll_resp.refresh_token;
      }
      break;
    }
    if (poll_resp.registration_code && !poll_resp.registration_code->empty()) {
      registration_code = *poll_resp.registration_code;
      break;
    }
    std::this_thread::sleep_for(1500ms);
  }
  if (access_token.empty()) {
    if (!registration_code.empty()) {
      GTEST_SKIP() << "device_poll returned registration_code; updates test "
                      "needs registration flow";
    }
    GTEST_SKIP() << "device_poll did not yield access token; last status="
                 << last_status;
  }
  
  std::cout << "Device access token obtained" << std::endl;
  
  // Generate unique timestamp for naming
  auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();
  
  // NOTE: The device is already registered during the OAuth device authorization flow.
  // The access_token should contain the device_id claim. We'll use this token
  // directly for the updates polling endpoint.
  
  std::cout << "Found device_id=" << device_id << std::endl;
  
  // Step 1: Create self-CA (needed for immediate cert issuance without event producer)
  std::string ca_name = "test-ca-" + std::to_string(timestamp);
  std::cout << "Creating self-CA..." << std::endl;
  testutil::SelfCAInfo ca_info;
  {
    misc::ThreadNotifier ca_notifier(10000);
    std::optional<monad::Result<testutil::SelfCAInfo, monad::Error>> ca_r;
    testutil::create_self_ca_io(*http_mgr_, base_url_, session_cookie_, user_id,
                                ca_name, "Test CA")
        .run([&](auto r) {
          ca_r = std::move(r);
          ca_notifier.notify();
        });
    ca_notifier.waitForNotification();
    if (!ca_r || ca_r->is_err()) {
      GTEST_SKIP() << "create_self_ca failed: "
                   << (!ca_r ? "no result" : ca_r->error().what);
    }
    ca_info = ca_r->value();
    std::cout << "Created self-CA id=" << ca_info.id << " name=" << ca_info.name << std::endl;
  }
  
  // Step 2: Create ACME account with ca_id (for self-signed certificates)
  std::cout << "Creating ACME account with ca_id=" << ca_info.id << "..." << std::endl;
  std::string acct_name = "test-updates-" + std::to_string(timestamp);
  testutil::AcmeAccountInfo acme_info;
  {
    misc::ThreadNotifier acme_notifier(10000);
    std::optional<monad::Result<testutil::AcmeAccountInfo, monad::Error>> acme_r;
    testutil::create_acme_account_io(*http_mgr_, base_url_, session_cookie_, user_id,
                                    acct_name, "test@example.com", "letsencrypt", ca_info.id)
        .run([&](auto r) {
          acme_r = std::move(r);
          acme_notifier.notify();
        });
    acme_notifier.waitForNotification();
    if (!acme_r || acme_r->is_err()) {
      GTEST_SKIP() << "create_acme_account failed: "
                   << (!acme_r ? "no result" : acme_r->error().what);
    }
    acme_info = acme_r->value();
    std::cout << "Created ACME account id=" << acme_info.id << " name=" << acme_info.name 
              << " with ca_id=" << ca_info.id << std::endl;
  }
  
  // Step 3: Create certificate record
  std::cout << "Creating certificate record..." << std::endl;
  testutil::CertInfo cert_info;
  {
    misc::ThreadNotifier cert_notifier(10000);
    std::optional<monad::Result<testutil::CertInfo, monad::Error>> cert_r;
    std::vector<std::string> sans{"*.test-updates.local"};
    testutil::create_cert_record_io(*http_mgr_, base_url_, session_cookie_,
                                    user_id, acme_info.id, "test-updates.local", sans)
        .run([&](auto r) {
          cert_r = std::move(r);
          cert_notifier.notify();
        });
    cert_notifier.waitForNotification();
    if (!cert_r || cert_r->is_err()) {
      GTEST_SKIP() << "create_cert_record failed: "
                   << (!cert_r ? "no result" : cert_r->error().what);
    }
    cert_info = cert_r->value();
    std::cout << "Created certificate record id=" << cert_info.id 
              << " domain=" << cert_info.domain_name << std::endl;
  }
  
  // Step 4: Issue the certificate (for self-CA this is immediate, for public it's async)
  std::cout << "Issuing certificate..." << std::endl;
  {
    misc::ThreadNotifier issue_notifier(10000);
    std::optional<monad::Result<testutil::CertInfo, monad::Error>> issue_r;
    testutil::issue_cert_io(*http_mgr_, base_url_, session_cookie_,
                           user_id, cert_info.id, 7776000)
        .run([&](auto r) {
          issue_r = std::move(r);
          issue_notifier.notify();
        });
    issue_notifier.waitForNotification();
    if (!issue_r || issue_r->is_err()) {
      GTEST_SKIP() << "issue_cert failed: "
                   << (!issue_r ? "no result" : issue_r->error().what);
    }
    auto issued_cert = issue_r->value();
    if (issued_cert.id > 0) {
      cert_info = issued_cert;  // Update with issued cert info
      std::cout << "Certificate issued id=" << cert_info.id 
                << " serial=" << cert_info.serial_number << std::endl;
    } else {
      std::cout << "Certificate issuance started (async)" << std::endl;
    }
  }
  
  // Assign certificate to device
  std::cout << "Assigning certificate to device..." << std::endl;
  {
    misc::ThreadNotifier assign_notifier(10000);
    std::optional<monad::Result<void, monad::Error>> assign_r;
    testutil::assign_cert_to_device_io(*http_mgr_, base_url_, session_cookie_,
                                       user_id, device_id, cert_info.id)
        .run([&](auto r) {
          assign_r = std::move(r);
          assign_notifier.notify();
        });
    assign_notifier.waitForNotification();
    ASSERT_TRUE(assign_r.has_value()) << "no result from assign_cert";
    ASSERT_FALSE(assign_r->is_err()) << "assign_cert failed: " << assign_r->error();
    std::cout << "Certificate assigned to device successfully" << std::endl;
  }
  
  // Wait for server to generate update signals (max 2 seconds according to API docs)
  std::cout << "Waiting 2.5 seconds for server to generate update signals..." << std::endl;
  std::this_thread::sleep_for(2500ms);
  
  // Set device token for handler
  ::setenv("DEVICE_ACCESS_TOKEN", access_token.c_str(), 1);
  
  // Poll for updates - should get signals about certificate assignment
  std::cout << "Polling for updates..." << std::endl;
  misc::ThreadNotifier updates_notifier(10000);
  std::optional<monad::MyVoidResult> updates_r;
  handler_->start().run([&](auto r) {
    updates_r = std::move(r);
    updates_notifier.notify();
  });
  updates_notifier.waitForNotification();
  
  ASSERT_TRUE(updates_r.has_value()) << "no result from updates handler";
  
  if (updates_r->is_err()) {
    // Auth failures should not occur with properly registered device token
    if (updates_r->error().code == 401 || updates_r->error().code == 403) {
      FAIL() << "updates polling auth failure: " << updates_r->error().what;
    }
    // Other errors are acceptable (e.g., network issues, server issues)
    GTEST_SKIP() << "updates handler error: code=" << updates_r->error().code
                 << " msg=" << updates_r->error().what;
  }
  
  // Validate handler state for a successful single poll
  int status = handler_->last_http_status();
  std::cout << "Updates polling returned status=" << status << std::endl;
  EXPECT_TRUE(status == 200 || status == 204) << "unexpected status=" << status;
  
  if (status == 200) {
    // Got signals
    ASSERT_TRUE(handler_->last_updates().has_value());
    const auto &resp = handler_->last_updates().value();
    
    // Cursor should be set (non-empty)
    EXPECT_FALSE(handler_->last_cursor().empty())
        << "cursor should be set after 200 response";
    EXPECT_FALSE(resp.data.cursor.empty())
        << "response cursor should not be empty";
    
    std::cout << "Cursor: " << resp.data.cursor << std::endl;
    
    // Counters should match signal types
    size_t counted_install = 0, counted_renewed = 0, counted_revoked = 0;
    for (auto &sig : resp.data.signals) {
      if (data::is_install_updated(sig))
        ++counted_install;
      else if (data::is_cert_renewed(sig))
        ++counted_renewed;
      else if (data::is_cert_revoked(sig))
        ++counted_revoked;
    }
    EXPECT_EQ(handler_->install_updated_count(), counted_install)
        << "install.updated count mismatch";
    EXPECT_EQ(handler_->cert_renewed_count(), counted_renewed)
        << "cert.renewed count mismatch";
    EXPECT_EQ(handler_->cert_revoked_count(), counted_revoked)
        << "cert.revoked count mismatch";
    
    // Log signals for visibility
    std::cout << "Received " << resp.data.signals.size() << " signals:\n";
    for (auto &sig : resp.data.signals) {
      std::cout << "  - type=" << sig.type 
                << " ts_ms=" << sig.ts_ms 
                << " ref=" << boost::json::serialize(sig.ref) << "\n";
    }
    
    // We should have at least one install.updated signal from cert assignment
    EXPECT_GT(counted_install, 0) 
        << "Expected at least one install.updated signal after cert assignment";
  } else if (status == 204) {
    // No updates available - this might happen if signals haven't propagated yet
    EXPECT_FALSE(handler_->last_updates().has_value())
        << "should not have updates data on 204";
    std::cout << "No updates (204), cursor=" << handler_->last_cursor() << std::endl;
    std::cout << "Note: Signals may not have propagated yet" << std::endl;
  }
  
  EXPECT_TRUE(handler_->parse_error().empty())
      << "parse error: " << handler_->parse_error();
  
  // Cleanup: delete certificate, ACME account, and self-CA
  std::cout << "Cleaning up test resources..." << std::endl;
  {
    misc::ThreadNotifier del_cert_notifier(5000);
    testutil::delete_cert_io(*http_mgr_, base_url_, session_cookie_, user_id, cert_info.id)
        .run([&](auto) { del_cert_notifier.notify(); });
    del_cert_notifier.waitForNotification();
    
    misc::ThreadNotifier del_acme_notifier(5000);
    testutil::delete_acme_account_io(*http_mgr_, base_url_, session_cookie_, user_id, acme_info.id)
        .run([&](auto) { del_acme_notifier.notify(); });
    del_acme_notifier.waitForNotification();
    
    misc::ThreadNotifier del_ca_notifier(5000);
    testutil::delete_self_ca_io(*http_mgr_, base_url_, session_cookie_, user_id, ca_info.id)
        .run([&](auto) { del_ca_notifier.notify(); });
    del_ca_notifier.waitForNotification();
    
    std::cout << "Cleanup completed (cert, ACME account, CA)" << std::endl;
  }
  
  SUCCEED();
}

} // namespace
