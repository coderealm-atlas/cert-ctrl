#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/device_automation_handler.hpp"
#include "http_client_config_provider.hpp"
#include "http_client_manager.hpp"
#include "misc_util.hpp"
#include "simple_data.hpp"
#include "include/test_config_utils.hpp"

namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace json = boost::json;
namespace fs = std::filesystem;
namespace po = boost::program_options;

class FakeStateStore : public certctrl::IDeviceStateStore {
public:
  std::optional<std::string> device_public_id;

  std::optional<std::string> get_access_token() const override {
    return std::nullopt;
  }
  std::optional<std::string> get_refresh_token() const override {
    return std::nullopt;
  }
  std::optional<std::string>
  save_tokens(const std::optional<std::string> &, const std::optional<std::string> &,
              std::optional<int>) override {
    return std::nullopt;
  }
  std::optional<std::string> clear_tokens() override { return std::nullopt; }

  std::optional<std::string> get_device_public_id() const override {
    return device_public_id;
  }
  std::optional<std::string> get_device_fingerprint_hex() const override {
    return std::nullopt;
  }
  std::optional<std::string>
  save_device_identity(const std::optional<std::string> &id,
                       const std::optional<std::string> &) override {
    device_public_id = id;
    return std::nullopt;
  }
  std::optional<std::string> clear_device_identity() override {
    device_public_id.reset();
    return std::nullopt;
  }

  std::optional<std::string> get_install_config_json() const override {
    return std::nullopt;
  }
  std::optional<std::int64_t> get_install_config_version() const override {
    return std::nullopt;
  }
  std::optional<std::string>
  save_install_config(const std::optional<std::string> &,
                      std::optional<std::int64_t>) override {
    return std::nullopt;
  }
  std::optional<std::string> clear_install_config() override {
    return std::nullopt;
  }

  std::optional<std::string> get_updates_cursor() const override {
    return std::nullopt;
  }
  std::optional<std::string>
  save_updates_cursor(const std::optional<std::string> &) override {
    return std::nullopt;
  }

  std::optional<std::string> get_websocket_resume_token() const override {
    return std::nullopt;
  }
  std::optional<std::string>
  save_websocket_resume_token(const std::optional<std::string> &) override {
    return std::nullopt;
  }

  std::optional<std::string> get_processed_signals_json() const override {
    return std::nullopt;
  }
  std::optional<std::string>
  save_processed_signals_json(const std::optional<std::string> &) override {
    return std::nullopt;
  }

  std::optional<std::string> get_imported_ca_name(std::int64_t) const override {
    return std::nullopt;
  }
  std::optional<std::string>
  set_imported_ca_name(std::int64_t, const std::optional<std::string> &) override {
    return std::nullopt;
  }
  std::optional<std::string> clear_imported_ca_name(std::int64_t) override {
    return std::nullopt;
  }

  std::pair<bool, std::optional<std::string>>
  try_acquire_refresh_lock(const std::string &, std::chrono::milliseconds) override {
    return {true, std::nullopt};
  }

  std::optional<std::string> release_refresh_lock(const std::string &) override {
    return std::nullopt;
  }

  bool available() const override { return true; }
};

class TestInstallConfigUpdateServer {
public:
  struct Record {
    std::string target;
    std::string authorization;
    std::string body;
  };

  TestInstallConfigUpdateServer() {
    using tcp = asio::ip::tcp;
    tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), 0);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
    port_ = acceptor_.local_endpoint().port();
    thread_ = std::thread([this] { run(); });
  }

  ~TestInstallConfigUpdateServer() {
    stop();
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  std::string base_url() const {
    return std::string("http://127.0.0.1:") + std::to_string(port_);
  }

  std::vector<Record> records() const {
    std::lock_guard<std::mutex> lk(mu_);
    return records_;
  }

  bool wait_for_records(std::size_t n, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(mu_);
    return cv_.wait_for(lk, timeout, [&] { return records_.size() >= n; });
  }

  void stop() {
    if (stopped_.exchange(true)) {
      return;
    }

    // Wake the blocking accept/read loop so the server thread can exit cleanly.
    // Closing the acceptor alone is not guaranteed to interrupt a synchronous
    // accept() on all platforms/toolchains.
    try {
      using tcp = asio::ip::tcp;
      tcp::socket wake_sock{ioc_};
      boost::system::error_code ec;
      wake_sock.connect(
          tcp::endpoint(asio::ip::make_address("127.0.0.1"), port_), ec);
      if (!ec) {
        const std::string req =
            "GET /__shutdown__ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        asio::write(wake_sock, asio::buffer(req), ec);
      }
      wake_sock.shutdown(tcp::socket::shutdown_both, ec);
      wake_sock.close(ec);
    } catch (...) {
      // Best-effort wake-up; ignore any errors.
    }

    boost::system::error_code ec;
    auto close_res = acceptor_.close(ec);
    (void)close_res;
  }

private:
  void run() {
    using tcp = asio::ip::tcp;
    while (!stopped_) {
      tcp::socket sock{ioc_};
      boost::system::error_code ec;
      auto accepted_ep = acceptor_.accept(sock, ec);
      (void)accepted_ep;
      if (ec) {
        if (stopped_) {
          return;
        }
        continue;
      }

      beast::flat_buffer buffer;
      http::request<http::string_body> req;
      http::read(sock, buffer, req, ec);
      if (!ec) {
        Record r;
        r.target = std::string(req.target());
        if (auto it = req.find(http::field::authorization); it != req.end()) {
          r.authorization = std::string(it->value());
        }
        r.body = req.body();
        {
          std::lock_guard<std::mutex> lk(mu_);
          records_.push_back(std::move(r));
        }
        cv_.notify_all();
      }

      http::response<http::string_body> resp;
      resp.version(11);
      resp.keep_alive(false);
      resp.result(http::status::ok);
      resp.set(http::field::content_type, "application/json");
      resp.body() = R"({"message":"ok"})";
      resp.prepare_payload();
      http::write(sock, resp, ec);
      auto shutdown_res = sock.shutdown(tcp::socket::shutdown_both, ec);
      (void)shutdown_res;
    }
  }

  asio::io_context ioc_{1};
  asio::ip::tcp::acceptor acceptor_{ioc_};
  unsigned short port_{0};
  std::thread thread_;
  std::atomic<bool> stopped_{false};

  mutable std::mutex mu_;
  mutable std::condition_variable cv_;
  std::vector<Record> records_;
};

struct HandlerHarness {
  fs::path config_dir;
  fs::path runtime_dir;

  std::unique_ptr<cjj365::ConfigSources> config_sources;
  std::unique_ptr<cjj365::AppProperties> app_properties;

  std::unique_ptr<customio::ConsoleOutputWithColor> output_backend;
  std::unique_ptr<customio::ConsoleOutput> output;

  std::unique_ptr<cjj365::HttpclientConfigProviderFile> http_cfg;
  std::unique_ptr<cjj365::ClientSSLContext> ssl_ctx;
  std::unique_ptr<client_async::HttpClientManager> http_mgr;

  std::unique_ptr<certctrl::CertctrlConfigProviderFile> cert_cfg;

  FakeStateStore state_store;

  HandlerHarness(std::string base_url) {
    config_dir = testinfra::make_temp_dir("device-automation-config");
    runtime_dir = testinfra::make_temp_dir("device-automation-runtime");

    testinfra::ConfigFileOptions opts;
    opts.base_url = std::move(base_url);
    opts.runtime_dir = runtime_dir;
    opts.http_threads = 1;
    opts.ioc_threads = 1;
    testinfra::write_basic_config_files(config_dir, opts);

    config_sources = testinfra::make_config_sources({config_dir}, {});
    app_properties = std::make_unique<cjj365::AppProperties>(*config_sources);

    output_backend = std::make_unique<customio::ConsoleOutputWithColor>(5);
    output = std::make_unique<customio::ConsoleOutput>(*output_backend);

    http_cfg = std::make_unique<cjj365::HttpclientConfigProviderFile>(
        *app_properties, *config_sources);
    ssl_ctx = std::make_unique<cjj365::ClientSSLContext>(*http_cfg);
    http_mgr = std::make_unique<client_async::HttpClientManager>(*ssl_ctx, *http_cfg);

    cert_cfg = std::make_unique<certctrl::CertctrlConfigProviderFile>(
        *app_properties, *config_sources, *output_backend);
  }

  ~HandlerHarness() {
    if (http_mgr) {
      http_mgr->stop();
    }

    cert_cfg.reset();
    http_mgr.reset();
    ssl_ctx.reset();
    http_cfg.reset();
    output.reset();
    output_backend.reset();
    app_properties.reset();
    config_sources.reset();

    cjj365::ConfigSources::instance_count.store(0);

    std::error_code ec;
    fs::remove_all(config_dir, ec);
    fs::remove_all(runtime_dir, ec);
  }
};

TEST(DeviceAutomationInstallConfigUpdate, AcceptsObjectPayloadWithPatchesAndAfterUpdateScriptNull) {
  TestInstallConfigUpdateServer server;
  HandlerHarness harness(server.base_url());

  harness.state_store.device_public_id = std::string("dev-123");

  const std::string payload =
      R"({"patches":[{"ob_type":"cert","ob_id":10,"changes":{"cmd":"echo hi"},"details":{"ignored":true}}],"after_update_script":null})";

  po::variables_map vm;
  certctrl::CliParams params;
  certctrl::CliCtx cli_ctx(std::move(vm),
                           std::vector<std::string>{"device", "install-config-update"},
                           std::vector<std::string>{"--apikey", "tok", "--payload", payload},
                           std::move(params));

  certctrl::DeviceAutomationHandler handler(cli_ctx, *harness.output, *harness.cert_cfg,
                                            *harness.http_mgr, harness.state_store);

  misc::ThreadNotifier notifier(5000);
  std::optional<monad::MyVoidResult> result;
  handler.start().run([&](auto r) {
    result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();

  ASSERT_TRUE(result.has_value()) << "handler produced no result";
  ASSERT_FALSE(result->is_err()) << result->error().what;

  ASSERT_TRUE(server.wait_for_records(1, std::chrono::milliseconds(2000)));
  auto recs = server.records();
  ASSERT_EQ(recs.size(), 1u);
  EXPECT_EQ(recs[0].authorization, "Bearer tok");
  EXPECT_NE(recs[0].target.find("/apiv1/me/install-config-update/dev-123"), std::string::npos);

  json::value received = json::parse(recs[0].body);
  ASSERT_TRUE(received.is_object());
  auto &obj = received.as_object();
  ASSERT_TRUE(obj.contains("after_update_script"));
  EXPECT_TRUE(obj.at("after_update_script").is_null());

  ASSERT_TRUE(obj.contains("patches"));
  ASSERT_TRUE(obj.at("patches").is_array());
  auto &patches = obj.at("patches").as_array();
  ASSERT_EQ(patches.size(), 1u);
  ASSERT_TRUE(patches[0].is_object());
  auto &p0 = patches[0].as_object();

  EXPECT_TRUE(p0.contains("cmd")) << "expected legacy changes flattened";
  EXPECT_FALSE(p0.contains("changes"));
  EXPECT_FALSE(p0.contains("details"));
}

TEST(DeviceAutomationInstallConfigUpdate, AcceptsObjectPayloadWithOnlyAfterUpdateScript) {
  TestInstallConfigUpdateServer server;
  HandlerHarness harness(server.base_url());

  harness.state_store.device_public_id = std::string("dev-123");

  const std::string payload = R"({"after_update_script":"@@@BEGIN posix.sh\nexit 0\n@@@END\n"})";

  po::variables_map vm;
  certctrl::CliParams params;
  certctrl::CliCtx cli_ctx(std::move(vm),
                           std::vector<std::string>{"device", "install-config-update"},
                           std::vector<std::string>{"--apikey", "tok", "--payload", payload},
                           std::move(params));

  certctrl::DeviceAutomationHandler handler(cli_ctx, *harness.output, *harness.cert_cfg,
                                            *harness.http_mgr, harness.state_store);

  misc::ThreadNotifier notifier(5000);
  std::optional<monad::MyVoidResult> result;
  handler.start().run([&](auto r) {
    result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();

  ASSERT_TRUE(result.has_value()) << "handler produced no result";
  ASSERT_FALSE(result->is_err()) << result->error().what;

  ASSERT_TRUE(server.wait_for_records(1, std::chrono::milliseconds(2000)));
  auto recs = server.records();
  ASSERT_EQ(recs.size(), 1u);

  json::value received = json::parse(recs[0].body);
  ASSERT_TRUE(received.is_object());
  auto &obj = received.as_object();
  ASSERT_TRUE(obj.contains("after_update_script"));
  ASSERT_TRUE(obj.at("after_update_script").is_string());
}

TEST(DeviceAutomationInstallConfigUpdate, RejectsInvalidAfterUpdateScriptTypeWithoutSendingRequest) {
  TestInstallConfigUpdateServer server;
  HandlerHarness harness(server.base_url());

  harness.state_store.device_public_id = std::string("dev-123");

  const std::string payload = R"({"after_update_script":123})";

  po::variables_map vm;
  certctrl::CliParams params;
  certctrl::CliCtx cli_ctx(std::move(vm),
                           std::vector<std::string>{"device", "install-config-update"},
                           std::vector<std::string>{"--apikey", "tok", "--payload", payload},
                           std::move(params));

  certctrl::DeviceAutomationHandler handler(cli_ctx, *harness.output, *harness.cert_cfg,
                                            *harness.http_mgr, harness.state_store);

  misc::ThreadNotifier notifier(5000);
  std::optional<monad::MyVoidResult> result;
  handler.start().run([&](auto r) {
    result = std::move(r);
    notifier.notify();
  });
  notifier.waitForNotification();

  ASSERT_TRUE(result.has_value()) << "handler produced no result";
  ASSERT_TRUE(result->is_err()) << "expected invalid payload to fail";

  EXPECT_FALSE(server.wait_for_records(1, std::chrono::milliseconds(300)))
      << "expected no HTTP request to be sent";
}

} // namespace
