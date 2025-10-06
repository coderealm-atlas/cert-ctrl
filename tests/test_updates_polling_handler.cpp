#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <boost/di.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/beast/http.hpp>
#include <sodium.h>

#include "base64.h"
#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "handlers/updates_polling_handler.hpp"
#include "http_client_config_provider.hpp"
#include "http_client_manager.hpp"
#include "include/api_test_helper.hpp"
#include "include/login_helper.hpp"
#include "include/test_injector.hpp"
#include "io_context_manager.hpp"
#include "log_stream.hpp"
#include "misc_util.hpp"

namespace di = boost::di;
namespace fs = std::filesystem;
namespace json = boost::json;
namespace po = boost::program_options;

namespace {

std::string make_unique_suffix() {
  auto now =
      std::chrono::steady_clock::now().time_since_epoch().count();
  std::mt19937_64 gen(std::random_device{}());
  std::uniform_int_distribution<uint64_t> dist;
  std::ostringstream oss;
  oss << std::hex << now << '-' << dist(gen);
  return oss.str();
}

std::string random_uuid() {
  std::array<unsigned char, 16> bytes{};
  randombytes_buf(bytes.data(), bytes.size());
  bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0F) | 0x40);
  bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3F) | 0x80);
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < bytes.size(); ++i) {
    oss << std::setw(2) << static_cast<int>(bytes[i]);
    if (i == 3 || i == 5 || i == 7 || i == 9) {
      oss << '-';
    }
  }
  return oss.str();
}

struct RegisteredDeviceSession {
  int64_t device_id{};
  std::string device_public_id;
  std::string access_token;
  std::optional<std::string> refresh_token;
};

class UpdatesRealServerFixture : public ::testing::Test {
protected:
  std::shared_ptr<void> injector_holder_;
  client_async::HttpClientManager *http_mgr_{nullptr};
  cjj365::IoContextManager *io_ctx_mgr_{nullptr};
  certctrl::ICertctrlConfigProvider *cfg_provider_{nullptr};
  std::shared_ptr<certctrl::UpdatesPollingHandler> handler_;
  certctrl::CliCtx *cli_ctx_{nullptr};

  std::unique_ptr<cjj365::ConfigSources> config_sources_ptr_;
  std::unique_ptr<certctrl::CliCtx> cli_ctx_ptr_;

  std::string base_url_;
  fs::path tmp_root_;
  std::string session_cookie_;
  int64_t user_id_{};
  std::optional<int64_t> newly_registered_device_id_;

  void SetUp() override {
    ASSERT_GE(sodium_init(), 0) << "libsodium initialization failed";

    base_url_ = testutil::url_base();
    auto temp_base = fs::temp_directory_path() / "updates-real-flow";
    tmp_root_ = temp_base / make_unique_suffix();
    std::error_code ec;
    fs::create_directories(tmp_root_, ec);
    ASSERT_FALSE(ec) << "failed to create temp directory: " << ec.message();

    auto write_json = [](const fs::path &p, const json::object &o) {
      std::ofstream ofs(p);
      ofs << json::serialize(o);
    };

  write_json(tmp_root_ / "application.json",
         json::object{{"auto_apply_config", false},
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
               json::object{{"threads_num", 1},
                            {"name", "updates-real"}});

  std::vector<fs::path> config_paths{tmp_root_};
  std::vector<std::string> profiles;

  config_sources_ptr_ =
    std::make_unique<cjj365::ConfigSources>(config_paths, profiles);

  certctrl::CliParams params{};
  params.subcmd = "updates";
  params.config_dirs = {tmp_root_};

  auto vm = po::variables_map{};
  auto positional = std::vector<std::string>{"updates"};
  auto unrecognized = std::vector<std::string>{"updates"};

  cli_ctx_ptr_ = std::make_unique<certctrl::CliCtx>(
    std::move(vm), std::move(positional), std::move(unrecognized),
    std::move(params));
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

    using InjT = decltype(injector);
    auto real_inj = std::make_shared<InjT>(std::move(injector));
    injector_holder_ = real_inj;
    auto &inj = *real_inj;

    http_mgr_ = &inj.create<client_async::HttpClientManager &>();
    io_ctx_mgr_ = &inj.create<cjj365::IoContextManager &>();
    cfg_provider_ = &inj.create<certctrl::ICertctrlConfigProvider &>();
    cfg_provider_->get().base_url = base_url_;
    handler_ = inj.create<std::shared_ptr<certctrl::UpdatesPollingHandler>>();

    misc::ThreadNotifier login_notifier(60000);
    std::optional<testutil::loginSuccessResult> login_r;
    testutil::login_io(*http_mgr_, base_url_, testutil::login_email(),
                       testutil::login_password())
        .run([&](auto r) {
          login_r = std::move(r);
          login_notifier.notify();
        });
    login_notifier.waitForNotification();
    ASSERT_TRUE(login_r.has_value()) << "login_io produced no result";
    ASSERT_FALSE(login_r->is_err())
        << "login failed: " << login_r->error().what;
    session_cookie_ = login_r->value().session_cookie;
    user_id_ = login_r->value().user.id;
    ASSERT_FALSE(session_cookie_.empty()) << "missing session cookie";
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

  void TearDown() override {
    if (newly_registered_device_id_.has_value()) {
      misc::ThreadNotifier del_notifier(60000);
      std::optional<monad::MyVoidResult> del_result;
      testutil::delete_device_io(*http_mgr_, base_url_, session_cookie_,
                                 user_id_, *newly_registered_device_id_)
          .run([&](auto r) {
            del_result = std::move(r);
            del_notifier.notify();
          });
      del_notifier.waitForNotification();
      if (del_result && del_result->is_err()) {
        std::cerr << "Failed to delete test device id="
                  << *newly_registered_device_id_ << ": "
                  << del_result->error().what << std::endl;
      }
    }

    if (!tmp_root_.empty()) {
      std::error_code ec;
      fs::remove_all(tmp_root_, ec);
      if (ec) {
        std::cerr << "Failed to remove temp dir " << tmp_root_ << ": "
                  << ec.message() << std::endl;
      }
    }
  }

  void set_device_tokens_env(const std::string &access_token,
                             const std::optional<std::string> &refresh_token) {
#ifdef _WIN32
    _putenv_s("DEVICE_ACCESS_TOKEN", access_token.c_str());
    if (refresh_token && !refresh_token->empty()) {
      _putenv_s("DEVICE_REFRESH_TOKEN", refresh_token->c_str());
    } else {
      _putenv_s("DEVICE_REFRESH_TOKEN", "");
    }
#else
    ::setenv("DEVICE_ACCESS_TOKEN", access_token.c_str(), 1);
    if (refresh_token && !refresh_token->empty()) {
      ::setenv("DEVICE_REFRESH_TOKEN", refresh_token->c_str(), 1);
    } else {
      ::unsetenv("DEVICE_REFRESH_TOKEN");
    }
#endif
  }

  json::array fetch_user_devices() {
    misc::ThreadNotifier notifier(60000);
    std::optional<monad::MyResult<json::array>> devices_r;
    testutil::list_devices_io(*http_mgr_, base_url_, session_cookie_, user_id_)
        .run([&](auto r) {
          devices_r = std::move(r);
          notifier.notify();
        });
    notifier.waitForNotification();
    EXPECT_TRUE(devices_r.has_value());
    if (!devices_r || devices_r->is_err()) {
      ADD_FAILURE() << "list_devices failed: "
                    << (devices_r ? devices_r->error().what
                                  : "list_devices_io produced no result");
      return {};
    }
    return devices_r->value();
  }

  std::optional<RegisteredDeviceSession> register_device_with_code(
      const std::string &registration_code) {
    if (registration_code.empty()) {
      ADD_FAILURE() << "registration_code is empty";
      return std::nullopt;
    }
    std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> pk{};
    std::array<unsigned char, crypto_kx_SECRETKEYBYTES> sk{};
    if (crypto_kx_keypair(pk.data(), sk.data()) != 0) {
      ADD_FAILURE() << "crypto_kx_keypair failed";
      return std::nullopt;
    }

    RegisteredDeviceSession session{};
    session.device_public_id = random_uuid();

    auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    std::string device_name = "Updates Test Device " + std::to_string(now_secs);
    std::string user_agent = "cert-ctrl/tests-updates";
    std::string dev_pk_b64 = base64_encode(pk.data(), pk.size());

    json::object body{
        {"device_public_id", session.device_public_id},
        {"platform", "linux"},
        {"model", "updates-test"},
        {"app_version", "1.0.0-test"},
        {"name", device_name},
        {"ip", "127.0.0.1"},
        {"user_agent", user_agent},
        {"dev_pk", dev_pk_b64},
        {"registration_code", registration_code}};

    using RegisterIO = monad::IO<json::object>;
    namespace http = boost::beast::http;

    std::string url = base_url_ + "/apiv1/users/" + std::to_string(user_id_) +
                      "/devices";
    auto payload_ptr = std::make_shared<json::object>(std::move(body));

    misc::ThreadNotifier notifier(60000);
    std::optional<monad::MyResult<json::object>> register_r;

    monad::http_io<monad::PostJsonTag>(url)
        .map([cookie = session_cookie_, payload_ptr](auto ex) {
          ex->setRequestJsonBody(*payload_ptr);
          ex->request.set(http::field::cookie, cookie);
          return ex;
        })
        .then(monad::http_request_io<monad::PostJsonTag>(*http_mgr_))
        .then([](auto ex) {
          return RegisterIO::from_result(
              ex->template parseJsonDataResponse<json::object>());
        })
        .run([&](auto r) {
          register_r = std::move(r);
          notifier.notify();
        });

    notifier.waitForNotification();
    if (!register_r.has_value()) {
      ADD_FAILURE() << "register_device_with_code produced no result";
      return std::nullopt;
    }
    if (register_r->is_err()) {
      ADD_FAILURE() << "device register failed: "
                    << register_r->error().what;
      return std::nullopt;
    }

    auto data_obj = register_r->value();
    if (!data_obj.if_contains("device")) {
      ADD_FAILURE() << "register response missing device object";
      return std::nullopt;
    }
    const auto &device_obj = data_obj.at("device").as_object();
    session.device_id = device_obj.at("id").as_int64();

    if (data_obj.if_contains("session") &&
        data_obj.at("session").is_object()) {
      const auto &session_obj = data_obj.at("session").as_object();
      if (session_obj.if_contains("access_token") &&
          session_obj.at("access_token").is_string()) {
        session.access_token =
            std::string(session_obj.at("access_token").as_string().c_str());
      }
      if (session_obj.if_contains("refresh_token") &&
          session_obj.at("refresh_token").is_string()) {
        session.refresh_token =
            std::string(session_obj.at("refresh_token").as_string().c_str());
      }
    }

    if (session.access_token.empty()) {
      ADD_FAILURE() << "register response missing access_token";
      return std::nullopt;
    }
    return session;
  }
};

TEST_F(UpdatesRealServerFixture, DeviceRegistrationWorkflowPollsUpdates) {
  using namespace std::chrono_literals;

  misc::ThreadNotifier start_notifier(120000);
  std::optional<monad::MyResult<data::deviceauth::StartResp>> start_r;
  testutil::device_start_io(*http_mgr_, base_url_, session_cookie_)
      .run([&](auto r) {
        start_r = std::move(r);
        start_notifier.notify();
      });
  start_notifier.waitForNotification();
  ASSERT_TRUE(start_r.has_value()) << "device_start produced no result";
  ASSERT_FALSE(start_r->is_err())
      << "device_start failed: " << start_r->error().what;

  const auto start_resp = start_r->value();
  ASSERT_FALSE(start_resp.device_code.empty());
  ASSERT_FALSE(start_resp.user_code.empty());

  misc::ThreadNotifier verify_notifier(120000);
  std::optional<monad::MyResult<data::deviceauth::VerifyResp>> verify_r;
  testutil::device_verify_io(*http_mgr_, base_url_, session_cookie_,
                             start_resp.user_code, true)
      .run([&](auto r) {
        verify_r = std::move(r);
        verify_notifier.notify();
      });
  verify_notifier.waitForNotification();
  ASSERT_TRUE(verify_r.has_value()) << "device_verify produced no result";
  ASSERT_FALSE(verify_r->is_err())
      << "device_verify failed: " << verify_r->error().what;

  const int poll_interval =
      std::clamp(start_resp.interval, 1, 10);
  const int max_attempts =
      std::clamp(start_resp.expires_in / start_resp.interval, 1, 20);

  std::optional<std::string> registration_code;
  std::string last_status;

  for (int attempt = 0; attempt < max_attempts; ++attempt) {
    misc::ThreadNotifier poll_notifier(120000);
    std::optional<monad::MyResult<data::deviceauth::PollResp>> poll_r;
    testutil::device_poll_io(*http_mgr_, base_url_, start_resp.device_code)
        .run([&](auto r) {
          poll_r = std::move(r);
          poll_notifier.notify();
        });
    poll_notifier.waitForNotification();
    ASSERT_TRUE(poll_r.has_value())
        << "device_poll attempt " << attempt << " produced no result";
    ASSERT_FALSE(poll_r->is_err())
        << "device_poll failed: " << poll_r->error().what;

    const auto &poll_resp = poll_r->value();
    last_status = poll_resp.status;
    if (poll_resp.registration_code &&
        !poll_resp.registration_code->empty()) {
      registration_code = *poll_resp.registration_code;
      break;
    }

    if (poll_resp.status == "authorization_pending" ||
        poll_resp.status == "pending" || poll_resp.status == "slow_down") {
      std::this_thread::sleep_for(std::chrono::seconds(poll_interval));
      continue;
    }

    if (poll_resp.status == "ready" && poll_resp.access_token &&
        !poll_resp.access_token->empty()) {
      FAIL() << "device_poll returned legacy access_token flow; "
                "registration workflow expectation violated";
    }

    FAIL() << "device_poll returned unexpected status: " << poll_resp.status;
  }

  ASSERT_TRUE(registration_code.has_value())
      << "device_poll never returned registration_code; last status="
      << last_status;

  auto device_session_opt = register_device_with_code(*registration_code);
  ASSERT_TRUE(device_session_opt.has_value())
      << "register_device_with_code returned no session";
  auto device_session = std::move(device_session_opt.value());
  newly_registered_device_id_ = device_session.device_id;
  set_device_tokens_env(device_session.access_token,
                        device_session.refresh_token);

  auto devices = fetch_user_devices();
  bool found_new_device = false;
  for (const auto &item : devices) {
    if (!item.is_object()) {
      continue;
    }
    const auto &obj = item.as_object();
    if (!obj.if_contains("id")) {
      continue;
    }
    if (obj.at("id").as_int64() == device_session.device_id) {
      found_new_device = true;
      break;
    }
  }
  EXPECT_TRUE(found_new_device)
      << "Registered device id " << device_session.device_id
      << " not present in device list";

  auto timestamp =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  std::string ca_name = "test-ca-" + std::to_string(timestamp);
  testutil::SelfCAInfo ca_info;
  {
    misc::ThreadNotifier ca_notifier(120000);
    std::optional<monad::MyResult<testutil::SelfCAInfo>> ca_r;
    testutil::create_self_ca_io(*http_mgr_, base_url_, session_cookie_,
                                user_id_, ca_name, "Test CA")
        .run([&](auto r) {
          ca_r = std::move(r);
          ca_notifier.notify();
        });
    ca_notifier.waitForNotification();
    ASSERT_TRUE(ca_r.has_value()) << "create_self_ca produced no result";
    ASSERT_FALSE(ca_r->is_err())
        << "create_self_ca failed: " << ca_r->error().what;
    ca_info = ca_r->value();
  }

  std::string acct_name = "test-updates-" + std::to_string(timestamp);
  testutil::AcmeAccountInfo acme_info;
  {
    misc::ThreadNotifier acme_notifier(120000);
    std::optional<monad::MyResult<testutil::AcmeAccountInfo>> acme_r;
    testutil::create_acme_account_io(*http_mgr_, base_url_, session_cookie_,
                                     user_id_, acct_name, "test@example.com",
                                     "letsencrypt", ca_info.id)
        .run([&](auto r) {
          acme_r = std::move(r);
          acme_notifier.notify();
        });
    acme_notifier.waitForNotification();
    ASSERT_TRUE(acme_r.has_value()) << "create_acme_account produced no result";
    ASSERT_FALSE(acme_r->is_err())
        << "create_acme_account failed: " << acme_r->error().what;
    acme_info = acme_r->value();
  }

  testutil::CertInfo cert_info;
  {
    misc::ThreadNotifier cert_notifier(120000);
    std::optional<monad::MyResult<testutil::CertInfo>> cert_r;
    std::vector<std::string> sans{"*.test-updates.local"};
    testutil::create_cert_record_io(*http_mgr_, base_url_, session_cookie_,
                                    user_id_, acme_info.id, "test-updates.local",
                                    sans)
        .run([&](auto r) {
          cert_r = std::move(r);
          cert_notifier.notify();
        });
    cert_notifier.waitForNotification();
    ASSERT_TRUE(cert_r.has_value()) << "create_cert_record produced no result";
    ASSERT_FALSE(cert_r->is_err())
        << "create_cert_record failed: " << cert_r->error().what;
    cert_info = cert_r->value();
  }

  {
    misc::ThreadNotifier issue_notifier(120000);
    std::optional<monad::MyResult<testutil::CertInfo>> issue_r;
    testutil::issue_cert_io(*http_mgr_, base_url_, session_cookie_, user_id_,
                            cert_info.id, 7776000)
        .run([&](auto r) {
          issue_r = std::move(r);
          issue_notifier.notify();
        });
    issue_notifier.waitForNotification();
    ASSERT_TRUE(issue_r.has_value()) << "issue_cert produced no result";
    ASSERT_FALSE(issue_r->is_err())
        << "issue_cert failed: " << issue_r->error().what;
    if (issue_r->value().id > 0) {
      cert_info = issue_r->value();
    }
  }

  {
    misc::ThreadNotifier assign_notifier(120000);
    std::optional<monad::MyVoidResult> assign_r;
    testutil::assign_cert_to_device_io(*http_mgr_, base_url_, session_cookie_,
                                       user_id_, device_session.device_id,
                                       cert_info.id)
        .run([&](auto r) {
          assign_r = std::move(r);
          assign_notifier.notify();
        });
    assign_notifier.waitForNotification();
    ASSERT_TRUE(assign_r.has_value()) << "assign_cert produced no result";
    ASSERT_FALSE(assign_r->is_err())
        << "assign_cert failed: " << assign_r->error().what;
  }

  std::this_thread::sleep_for(2500ms);

  misc::ThreadNotifier updates_notifier(120000);
  std::optional<monad::MyVoidResult> updates_r;
  handler_->start().run([&](auto r) {
    updates_r = std::move(r);
    updates_notifier.notify();
  });
  updates_notifier.waitForNotification();

  ASSERT_TRUE(updates_r.has_value()) << "updates handler produced no result";
  if (updates_r->is_err()) {
    FAIL() << "updates handler error: code=" << updates_r->error().code
           << " message=" << updates_r->error().what;
  }

  int status = handler_->last_http_status();
  EXPECT_TRUE(status == 200 || status == 204)
      << "unexpected updates status " << status;

  if (status == 200) {
    ASSERT_TRUE(handler_->last_updates().has_value());
    const auto &resp = handler_->last_updates().value();

    EXPECT_FALSE(handler_->last_cursor().empty());
    EXPECT_FALSE(resp.data.cursor.empty());

    size_t counted_install = 0, counted_renewed = 0, counted_revoked = 0;
    for (const auto &sig : resp.data.signals) {
      if (data::is_install_updated(sig))
        ++counted_install;
      else if (data::is_cert_renewed(sig))
        ++counted_renewed;
      else if (data::is_cert_revoked(sig))
        ++counted_revoked;
    }
    EXPECT_EQ(handler_->install_updated_count(), counted_install);
    EXPECT_EQ(handler_->cert_renewed_count(), counted_renewed);
    EXPECT_EQ(handler_->cert_revoked_count(), counted_revoked);
    EXPECT_GT(counted_install, 0)
        << "expected at least one install.updated signal";
  } else {
    EXPECT_FALSE(handler_->last_updates().has_value());
  }

  EXPECT_TRUE(handler_->parse_error().empty())
      << "parse error: " << handler_->parse_error();

  {
    misc::ThreadNotifier del_cert_notifier(60000);
    testutil::delete_cert_io(*http_mgr_, base_url_, session_cookie_, user_id_,
                             cert_info.id)
        .run([&](auto) { del_cert_notifier.notify(); });
    del_cert_notifier.waitForNotification();

    misc::ThreadNotifier del_acme_notifier(60000);
    testutil::delete_acme_account_io(*http_mgr_, base_url_, session_cookie_,
                                     user_id_, acme_info.id)
        .run([&](auto) { del_acme_notifier.notify(); });
    del_acme_notifier.waitForNotification();

    misc::ThreadNotifier del_ca_notifier(60000);
    testutil::delete_self_ca_io(*http_mgr_, base_url_, session_cookie_, user_id_,
                                ca_info.id)
        .run([&](auto) { del_ca_notifier.notify(); });
    del_ca_notifier.waitForNotification();
  }
}

} // namespace
