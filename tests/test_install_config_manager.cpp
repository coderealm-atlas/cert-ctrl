#include <gtest/gtest.h>

#include <atomic>
#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/di.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <cstdlib>
#include <filesystem>
#include <fmt/format.h>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "common_macros.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/data_shape.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_config_manager.hpp"
#include "http_client_manager.hpp"
#include "include/install_manager_harness.hpp"
#include "install_config_fetcher.hpp"
#include "io_monad.hpp"
#include "misc_util.hpp"
#include "my_error_codes.hpp"
#include "resource_fetcher.hpp"
#include "result_monad.hpp"

namespace {

namespace asio = boost::asio;
namespace json = boost::json;

class FailingCaServer {
public:
  FailingCaServer()
      : acceptor_(ioc_, asio::ip::tcp::endpoint(
                            asio::ip::make_address("127.0.0.1"), 0)) {
    port_ = acceptor_.local_endpoint().port();
    thread_ = std::thread([this] { run(); });
  }

  ~FailingCaServer() { stop(); }

  std::string base_url() const {
    return fmt::format("http://127.0.0.1:{}", port_);
  }

  void stop() {
    bool expected = false;
    if (!stopped_.compare_exchange_strong(expected, true)) {
      return;
    }
    boost::system::error_code ec;
    if (acceptor_.is_open()) {
      try {
        asio::io_context poke_ctx;
        asio::ip::tcp::socket poke_socket(poke_ctx);
        asio::ip::tcp::endpoint endpoint{asio::ip::make_address("127.0.0.1"),
                                         port_};
        poke_socket.connect(endpoint, ec);
        if (ec) {
          ec.clear();
        } else {
          boost::system::error_code shutdown_ec;
          [[maybe_unused]] auto shutdown_status = poke_socket.shutdown(
              asio::ip::tcp::socket::shutdown_both, shutdown_ec);
          if (shutdown_ec) {
            shutdown_ec.clear();
          }
        }
        boost::system::error_code close_ec;
        [[maybe_unused]] auto close_status = poke_socket.close(close_ec);
        if (close_ec) {
          close_ec.clear();
        }
      } catch (const std::exception &) {
        // Ignore failures during shutdown poke.
      }
      [[maybe_unused]] auto close_status = acceptor_.close(ec);
    }
    if (thread_.joinable()) {
      thread_.join();
    }
  }

private:
  void run() {
    while (!stopped_.load()) {
      boost::system::error_code ec;
      asio::ip::tcp::socket socket(ioc_);
      [[maybe_unused]] auto accept_status = acceptor_.accept(socket, ec);
      if (ec) {
        if (stopped_.load()) {
          break;
        }
        continue;
      }
      handle_connection(std::move(socket));
    }
  }

  void handle_connection(asio::ip::tcp::socket socket) {
    DEBUG_PRINT("**Local server accepted connection**");
    try {
      boost::system::error_code ec;
      boost::asio::streambuf request;
      boost::asio::read_until(socket, request, "\r\n\r\n", ec);
      const std::string response = "HTTP/1.1 500 Internal Server Error\r\n"
                                   "Content-Type: text/plain\r\n"
                                   "Content-Length: 14\r\n"
                                   "Connection: close\r\n"
                                   "\r\n"
                                   "bad allocation";
      DEBUG_PRINT("**Local server responding with 500**");
      boost::asio::write(socket, boost::asio::buffer(response), ec);
      [[maybe_unused]] auto shutdown_status =
          socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
      [[maybe_unused]] auto close_status = socket.close(ec);
    } catch (...) {
      // Ignore socket errors during teardown.
    }
  }

  asio::io_context ioc_;
  asio::ip::tcp::acceptor acceptor_;
  std::thread thread_;
  std::atomic<bool> stopped_{false};
  std::uint16_t port_{0};
};

class MockRefreshServer {
public:
  MockRefreshServer()
      : acceptor_(ioc_, asio::ip::tcp::endpoint(
                            asio::ip::make_address("127.0.0.1"), 0)) {
    port_ = acceptor_.local_endpoint().port();
    thread_ = std::thread([this] { run(); });
  }

  ~MockRefreshServer() { stop(); }

  std::string base_url() const {
    return fmt::format("http://127.0.0.1:{}", port_);
  }

  void set_expected_refresh_token(std::string token) {
    std::lock_guard<std::mutex> lock(mutex_);
    expected_refresh_token_ = std::move(token);
  }

  void set_response_tokens(std::string access_token,
                           std::string refresh_token) {
    std::lock_guard<std::mutex> lock(mutex_);
    response_access_token_ = std::move(access_token);
    response_refresh_token_ = std::move(refresh_token);
  }

  int refresh_calls() const { return refresh_calls_.load(); }

  std::string last_refresh_token() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_refresh_token_;
  }

  bool observed_expected_token() const {
    return observed_expected_token_.load();
  }

  void stop() {
    bool expected = false;
    if (!stopped_.compare_exchange_strong(expected, true)) {
      return;
    }
    boost::system::error_code ec;
    if (acceptor_.is_open()) {
      try {
        asio::io_context poke_ctx;
        asio::ip::tcp::socket poke_socket(poke_ctx);
        asio::ip::tcp::endpoint endpoint{asio::ip::make_address("127.0.0.1"),
                                         port_};
        poke_socket.connect(endpoint, ec);
        if (!ec) {
          boost::system::error_code shutdown_ec;
          [[maybe_unused]] auto shutdown_status = poke_socket.shutdown(
              asio::ip::tcp::socket::shutdown_both, shutdown_ec);
          if (shutdown_ec) {
            shutdown_ec.clear();
          }
        } else {
          ec.clear();
        }
        boost::system::error_code close_ec;
        [[maybe_unused]] auto close_status = poke_socket.close(close_ec);
        if (close_ec) {
          close_ec.clear();
        }
      } catch (const std::exception &) {
        // Ignore shutdown failures.
      }
      [[maybe_unused]] auto close_status = acceptor_.close(ec);
    }
    if (thread_.joinable()) {
      thread_.join();
    }
  }

private:
  void run() {
    while (!stopped_.load()) {
      boost::system::error_code ec;
      asio::ip::tcp::socket socket(ioc_);
      [[maybe_unused]] auto accept_status = acceptor_.accept(socket, ec);
      if (ec) {
        if (stopped_.load()) {
          break;
        }
        continue;
      }
      handle_connection(std::move(socket));
    }
  }

  void handle_connection(asio::ip::tcp::socket socket) {
    namespace http = boost::beast::http;

    try {
      boost::beast::flat_buffer buffer;
      http::request<http::string_body> req;
      boost::system::error_code read_ec;
      http::read(socket, buffer, req, read_ec);
      if (read_ec) {
        return;
      }

      http::response<http::string_body> res{http::status::ok, req.version()};
      res.set(http::field::server, "MockRefreshServer");
      res.set(http::field::content_type, "application/json");
      res.keep_alive(false);

      if (req.method() == http::verb::post && req.target() == "/auth/refresh") {
        refresh_calls_.fetch_add(1);
        std::string provided_refresh;
        try {
          auto parsed = json::parse(req.body());
          if (parsed.is_object()) {
            auto &obj = parsed.as_object();
            if (auto *token = obj.if_contains("refresh_token");
                token && token->is_string()) {
              provided_refresh = std::string(token->as_string().c_str(),
                                             token->as_string().size());
            }
          }
        } catch (...) {
          provided_refresh.clear();
        }

        bool matches = false;
        std::string access;
        std::string refresh;
        {
          std::lock_guard<std::mutex> lock(mutex_);
          last_refresh_token_ = provided_refresh;
          matches = !expected_refresh_token_.empty() &&
                    provided_refresh == expected_refresh_token_;
          access = response_access_token_;
          refresh = response_refresh_token_;
        }
        if (matches) {
          observed_expected_token_.store(true);
        }

        json::object data{{"access_token", access},
                          {"refresh_token", refresh},
                          {"expires_in", 900}};
        res.body() = json::serialize(json::object{{"data", std::move(data)}});
        res.prepare_payload();
      } else {
        res.result(http::status::not_found);
        res.body() = "{}";
        res.prepare_payload();
      }

      boost::system::error_code write_ec;
      http::write(socket, res, write_ec);
      boost::system::error_code shutdown_ec;
      [[maybe_unused]] auto shutdown_status =
          socket.shutdown(asio::ip::tcp::socket::shutdown_both, shutdown_ec);
      boost::system::error_code close_ec;
      [[maybe_unused]] auto close_status = socket.close(close_ec);
    } catch (const std::exception &) {
      // Ignore connection errors during teardown.
    }
  }

  asio::io_context ioc_;
  asio::ip::tcp::acceptor acceptor_;
  std::thread thread_;
  std::atomic<bool> stopped_{false};
  std::uint16_t port_{0};
  std::atomic<int> refresh_calls_{0};
  std::atomic<bool> observed_expected_token_{false};
  mutable std::mutex mutex_;
  std::string expected_refresh_token_;
  std::string last_refresh_token_;
  std::string response_access_token_ = "refreshed-access";
  std::string response_refresh_token_ = "refreshed-refresh";
};

std::filesystem::path make_temp_runtime_dir() {
  auto base = std::filesystem::temp_directory_path();
  std::mt19937_64 gen{std::random_device{}()};
  std::uniform_int_distribution<std::uint64_t> dist;
  auto dir = base / fmt::format("certctrl-test-{}", dist(gen));
  std::filesystem::create_directories(dir);
  return dir;
}

void write_file(const std::filesystem::path &path, std::string_view content) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
  ofs << content;
}

std::string read_file(const std::filesystem::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(ifs),
          std::istreambuf_iterator<char>()};
}

void write_json_file(const std::filesystem::path &path,
                     const json::object &payload) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
  ofs << json::serialize(payload);
}

class ScopedEnvVar {
public:
  ScopedEnvVar(const char *name, const std::string &value) : name_(name) {
#ifdef _WIN32
    _putenv_s(name, value.c_str());
#else
    ::setenv(name, value.c_str(), 1);
#endif
  }

  ~ScopedEnvVar() {
#ifdef _WIN32
    _putenv_s(name_.c_str(), "");
#else
    ::unsetenv(name_.c_str());
#endif
  }

private:
  std::string name_;
};

::data::DeviceUpdateSignal make_cert_updated_signal(std::int64_t cert_id) {
  json::object ref;
  ref["cert_id"] = cert_id;
  json::object payload;
  payload["type"] = "cert.updated";
  payload["ts_ms"] = 1234567;
  payload["ref"] = ref;
  json::value signal = payload;
  return json::value_to<::data::DeviceUpdateSignal>(signal);
}

struct MockAccessTokenLoaderFixed
    : public certctrl::install_actions::IAccessTokenLoader {
  std::optional<std::string> token;

  MockAccessTokenLoaderFixed(std::optional<std::string> t)
      : token(std::move(t)) {
    DEBUG_PRINT("MockAccessTokenLoaderFixed initialized with token: "
                << (token ? *token : "<none>"));
  }

  ~MockAccessTokenLoaderFixed() {
    DEBUG_PRINT("MockAccessTokenLoaderFixed destroyed");
  }

  std::optional<std::string> load_token() const override { return token; }
};

struct MockInstallConfigFetcher
    : public certctrl::install_actions::IDeviceInstallConfigFetcher {

  dto::DeviceInstallConfigDto config;
  MockInstallConfigFetcher(dto::DeviceInstallConfigDto cfg)
      : config(std::move(cfg)) {}

  monad::IO<dto::DeviceInstallConfigDto> fetch_install_config(
      std::optional<std::string> access_token,
      std::optional<std::int64_t> expected_version,
      const std::optional<std::string> &expected_hash) override {
    config.version = 1;
    dto::DeviceInstallConfigDto copy = config;
    if (expected_version) {
      copy.version = *expected_version;
    }
    if (expected_hash) {
      copy.installs_hash = *expected_hash;
    }
    return monad::IO<dto::DeviceInstallConfigDto>::pure(copy);
  }
};

struct LambdaInstallConfigFetcher
    : public certctrl::install_actions::IDeviceInstallConfigFetcher {
  using FetchFn = std::function<monad::IO<dto::DeviceInstallConfigDto>(
      std::optional<std::string>, std::optional<std::int64_t>,
      const std::optional<std::string> &)>;

  explicit LambdaInstallConfigFetcher(FetchFn fn) : fn_(std::move(fn)) {}

  monad::IO<dto::DeviceInstallConfigDto> fetch_install_config(
      std::optional<std::string> access_token,
      std::optional<std::int64_t> expected_version,
      const std::optional<std::string> &expected_hash) override {
    return fn_(std::move(access_token), std::move(expected_version),
               expected_hash);
  }

private:
  FetchFn fn_;
};

struct MockerResourceFetcher
    : public certctrl::install_actions::IResourceFetcher {
  std::string override_body;

  static std::string make_default_cert_payload() {
    constexpr std::string_view kMockKey = R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIC+BYXto9Jw4/dZElWXKfW6hDqmUC8Uh7xiw5J2wGxmh
-----END PRIVATE KEY-----
)";
    constexpr std::string_view kMockCert = R"(-----BEGIN CERTIFICATE-----
MIIBVTCCAQegAwIBAgIUNaR75E43mHngKYNdCa8JOW/d7dEwBQYDK2VwMCAxHjAc
BgNVBAMMFWZhbGxiYWNrLmV4YW1wbGUudGVzdDAeFw0yNTEwMjUxMTA3NTBaFw0y
NjEwMjUxMTA3NTBaMCAxHjAcBgNVBAMMFWZhbGxiYWNrLmV4YW1wbGUudGVzdDAq
MAUGAytlcAMhABceLDKOiP/CqZAfwi/uDcA4UO/1Kv5bect8to8uuVoLo1MwUTAd
BgNVHQ4EFgQUaZ/x7IAcuGgUL6gSG+8//Kf1JRswHwYDVR0jBBgwFoAUaZ/x7IAc
uGgUL6gSG+8//Kf1JRswDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBeHFmFCaDL
7Ary5Uhf27nkdLdiq/QpOr5oiOEG7jnW5NwaJhj9kRo45MmK5yDGYLpUYmpb+Bnn
futpyqmphkYC
-----END CERTIFICATE-----
)";

    boost::json::object detail{
        {"private_key_pem", kMockKey},
        {"certificate_pem", kMockCert},
        {"fullchain_pem", kMockCert},
        {"chain_pem", kMockCert},
    };
    boost::json::object deploy{
        {"enc_scheme", "plaintext"},
        {"private_key_pem", kMockKey},
        {"fullchain_pem", kMockCert},
    };
    boost::json::object root;
    root["detail"] = detail;
    root["deploy"] = deploy;
    return boost::json::serialize(root);
  }

  MockerResourceFetcher(std::string body) : override_body(std::move(body)) {
    if (override_body.empty()) {
      override_body = make_default_cert_payload();
    }
  }
  monad::IO<void>
  fetch(std::optional<std::string> access_token,
        std::shared_ptr<certctrl::install_actions::MaterializationData>
            current_materialization) override {
    DEBUG_PRINT("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
    if (current_materialization->is_cert) {
      auto state = current_materialization;
      boost::system::error_code ec;
      auto parsed = boost::json::parse(override_body, ec);
      if (ec || !parsed.is_object()) {
        return monad::IO<void>::fail(
            monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                              "Override payload for cert is not an object"));
      }
      auto &obj = parsed.as_object();
      if (auto *deploy = obj.if_contains("deploy")) {
        if (deploy->is_object()) {
          state->deploy_obj = deploy->as_object();
          state->deploy_available = true;
        }
      }
      if (auto *detail = obj.if_contains("detail")) {
        if (detail->is_object()) {
          state->detail_obj = detail->as_object();
          state->detail_parsed = true;
        }
      }
      if (state->deploy_obj.empty() && obj.if_contains("data") &&
          obj["data"].is_object()) {
        state->deploy_obj = obj["data"].as_object();
        state->deploy_available = true;
      }
      if (state->detail_obj.empty() && obj.if_contains("certificate") &&
          obj["certificate"].is_object()) {
        state->detail_obj = obj["certificate"].as_object();
        state->detail_parsed = true;
      }
      if (state->detail_obj.empty()) {
        return monad::IO<void>::fail(monad::make_error(
            my_errors::GENERAL::UNEXPECTED_RESULT,
            "Override payload missing certificate detail object"));
      }

      state->detail_raw_json = boost::json::serialize(
          boost::json::object{{"data", state->detail_obj}});
      if (!state->deploy_obj.empty()) {
        state->deploy_raw_json = boost::json::serialize(
            boost::json::object{{"data", state->deploy_obj}});
      } else {
        boost::json::object placeholder;
        placeholder["note"] =
            "resource override missing deploy materials; generated locally";
        state->deploy_raw_json =
            boost::json::serialize(boost::json::object{{"data", placeholder}});
      }
      state->deploy_available = !state->deploy_obj.empty();
    }
    return monad::IO<void>::pure();
  }
};

struct AlwaysFailingResourceFetcher
    : public certctrl::install_actions::IResourceFetcher {
  monad::IO<void>
  fetch(std::optional<std::string> /*access_token*/,
        std::shared_ptr<certctrl::install_actions::MaterializationData>
        /*current_materialization*/) override {
    auto err = monad::make_error(my_errors::GENERAL::FILE_NOT_FOUND,
                                 "CA fetch failed");
    err.response_status = 500;
    err.params["response_body_preview"] = "bad allocation";
    return monad::IO<void>::fail(std::move(err));
  }
};

struct ServerBackedResourceFetcher
    : public certctrl::install_actions::IResourceFetcher {
  void bind(cjj365::IoContextManager &io_ctx,
            certctrl::ICertctrlConfigProvider &config,
            customio::ConsoleOutput &output,
            client_async::HttpClientManager &http_client) {
    delegate_ = std::make_unique<certctrl::install_actions::ResourceFetcher>(
        io_ctx, config, output, http_client);
  }

  monad::IO<void>
  fetch(std::optional<std::string> access_token,
        std::shared_ptr<certctrl::install_actions::MaterializationData>
            current_materialization) override {
    if (!delegate_) {
      return monad::IO<void>::fail(
          monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                            "ServerBackedResourceFetcher not bound"));
    }
    try {
      return delegate_->fetch(std::move(access_token),
                              std::move(current_materialization));
    } catch (const std::exception &ex) {
      auto err =
          monad::make_error(my_errors::NETWORK::CONNECT_ERROR, ex.what());
      return monad::IO<void>::fail(std::move(err));
    }
  }

private:
  std::unique_ptr<certctrl::install_actions::ResourceFetcher> delegate_;
};

class InstallConfigManagerFixture : public ::testing::Test {
protected:
  void SetUp() override { DEBUG_PRINT("xxxxxxxxxxxxxxxxx setup"); }

  void TearDown() override { DEBUG_PRINT("xxxxxxxxxxxxxxxxx teardown"); }

  void createHarness(
      std::filesystem::path config_dir, std::filesystem::path runtime_dir,
      std::unique_ptr<certctrl::install_actions::IDeviceInstallConfigFetcher>
          fetcher,
      std::unique_ptr<certctrl::install_actions::IResourceFetcher>
          resource_fetcher,
      std::unique_ptr<certctrl::install_actions::IAccessTokenLoader>
          token_loader,
      std::string base_url = "http://127.0.0.1", //
      int http_threads = 1) {
    fetcher_holder_ = std::move(fetcher);
    resource_fetcher_holder_ = std::move(resource_fetcher);
    token_loader_ = std::move(token_loader);
    harness_ = std::make_unique<InstallManagerDiHarness>(
        std::move(config_dir), std::move(runtime_dir), std::move(base_url),
        *fetcher_holder_, *resource_fetcher_holder_, http_threads,
        token_loader_.get());
  }

  std::unique_ptr<certctrl::install_actions::IDeviceInstallConfigFetcher>
      fetcher_holder_;
  std::unique_ptr<certctrl::install_actions::IResourceFetcher>
      resource_fetcher_holder_;
  std::unique_ptr<certctrl::install_actions::IAccessTokenLoader> token_loader_;
  std::unique_ptr<InstallManagerDiHarness> harness_;
};

} // namespace

TEST_F(InstallConfigManagerFixture, AppliesCopyActionsFullPlan) {
  misc::ThreadNotifier notifier;

  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  auto resource_dir = runtime_dir / "resources" / "certs" / "123" / "current";
  write_file(resource_dir / "private.key", "PRIVATE-KEY-CONTENT\n");
  write_file(resource_dir / "fullchain.pem", "FULLCHAIN\n");

  dto::DeviceInstallConfigDto config{};
  config.id = 1;
  config.user_device_id = 10;
  config.version = 42;
  config.installs_hash = "abc123";

  dto::InstallItem copy_item{};
  copy_item.id = "copy-cert";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = static_cast<std::int64_t>(123);
  copy_item.from = std::vector<std::string>{"private.key", "fullchain.pem"};
  auto dest_key = runtime_dir / "deploy" / "certs" / "service" / "private.key";
  auto dest_chain =
      runtime_dir / "deploy" / "certs" / "service" / "fullchain.pem";
  copy_item.to =
      std::vector<std::string>{dest_key.string(), dest_chain.string()};
  config.installs.push_back(copy_item);

  static MockInstallConfigFetcher fetcher{config};
  static MockerResourceFetcher resource_fetcher{""};
  static MockAccessTokenLoaderFixed token_loader{std::nullopt};
  harness_ = std::make_unique<InstallManagerDiHarness>(
      config_dir, runtime_dir, "https://api.example.test", fetcher,
      resource_fetcher, 1, &token_loader);

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  std::optional<
      monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      op_r;
  harness_->install_manager()
      .ensure_config_version(config.version, config.installs_hash)
      .run([&](auto result) {
        op_r = result;
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(op_r.has_value());
  ASSERT_TRUE(op_r->is_ok())
      << "ensure_config_version failed: " << op_r->error();
  plan = op_r->value();
  ASSERT_TRUE(plan);
  monad::MyVoidResult void_r;

  harness_->install_manager()
      .apply_copy_actions(*plan, std::nullopt, std::nullopt)
      .run([&](auto result) {
        void_r = result;
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(void_r.is_ok())
      << "apply_copy_actions failed: " << void_r.error();

  EXPECT_TRUE(std::filesystem::exists(dest_key));
  EXPECT_TRUE(std::filesystem::exists(dest_chain));
  EXPECT_EQ(read_file(dest_key), "PRIVATE-KEY-CONTENT\n");
  EXPECT_EQ(read_file(dest_chain), "FULLCHAIN\n");

#ifndef _WIN32
  auto key_perms = std::filesystem::status(dest_key).permissions();
  EXPECT_NE(key_perms & std::filesystem::perms::owner_read,
            std::filesystem::perms::none);
  EXPECT_NE(key_perms & std::filesystem::perms::owner_write,
            std::filesystem::perms::none);
  EXPECT_EQ(key_perms & std::filesystem::perms::others_read,
            std::filesystem::perms::none);

  auto chain_perms = std::filesystem::status(dest_chain).permissions();
  EXPECT_NE(chain_perms & std::filesystem::perms::others_read,
            std::filesystem::perms::none);
#endif

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture, SkipsCopyActionsWithEmptyDestinations) {
  misc::ThreadNotifier notifier;
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  auto resource_dir = runtime_dir / "resources" / "certs" / "789" / "current";
  write_file(resource_dir / "fullchain.pem", "CHAIN789\n");

  dto::DeviceInstallConfigDto config{};
  config.id = 2;
  config.user_device_id = 20;
  config.version = 99;

  dto::InstallItem copy_item{};
  copy_item.id = "copy-empty";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = static_cast<std::int64_t>(789);
  copy_item.from = std::vector<std::string>{"fullchain.pem"};
  copy_item.to = std::vector<std::string>{};
  config.installs.push_back(copy_item);

  static MockInstallConfigFetcher fetcher{config};
  static MockerResourceFetcher resource_fetcher{""};
  static MockAccessTokenLoaderFixed token_loader{std::nullopt};
  harness_ = std::make_unique<InstallManagerDiHarness>(
      config_dir, runtime_dir, "https://api.example.test", fetcher,
      resource_fetcher, 1, &token_loader);

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  std::optional<
      monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      op_r;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        op_r = result;
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(op_r.has_value());
  ASSERT_FALSE(op_r->is_err())
      << "Expected success but got error: " << op_r->error();
  plan = op_r->value();
  ASSERT_TRUE(plan);

  auto dest_path = runtime_dir / "deploy" / "fullchain.pem";

  std::optional<monad::MyVoidResult> apply_r;
  harness_->install_manager()
      .apply_copy_actions(*plan, std::nullopt, std::nullopt)
      .run([&](auto result) {
        apply_r = result;
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(apply_r.has_value());
  ASSERT_FALSE(apply_r->is_err())
      << "Expected success but got error: " << apply_r->error();

  EXPECT_FALSE(std::filesystem::exists(dest_path));

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture,
  CertUpdatedAppliesCopyActionsWhenInstallItemsActionable) {
  misc::ThreadNotifier notifier;
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  const std::int64_t target_cert = 321;

  dto::DeviceInstallConfigDto config{};
  config.version = 3;

  dto::InstallItem copy_item{};
  copy_item.id = "copy-cert";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = target_cert;
  copy_item.from = std::vector<std::string>{"fullchain.pem"};
  auto dest_path = runtime_dir / "deploy" / "certs" / "active.pem";
  copy_item.to = std::vector<std::string>{dest_path.string()};
  config.installs.push_back(copy_item);

  createHarness(config_dir, runtime_dir,
                std::make_unique<MockInstallConfigFetcher>(config),
                std::make_unique<MockerResourceFetcher>(""),
                std::make_unique<MockAccessTokenLoaderFixed>(std::nullopt));

  std::optional<monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      plan_result;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        plan_result = result;
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(plan_result.has_value());
  ASSERT_TRUE(plan_result->is_ok()) << plan_result->error();

  auto signal = make_cert_updated_signal(target_cert);

  std::optional<monad::MyVoidResult> apply_r;
  harness_->install_manager()
      .apply_copy_actions_for_signal(signal)
      .run([&](auto result) {
        apply_r = result;
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(apply_r.has_value());
  ASSERT_TRUE(apply_r->is_ok()) << apply_r->error();

  ASSERT_TRUE(std::filesystem::exists(dest_path));
  const auto copied = read_file(dest_path);
  EXPECT_NE(copied.find("BEGIN CERTIFICATE"), std::string::npos);

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture,
  CertUpdatedSkipsWhenInstallItemsLackTargets) {
  misc::ThreadNotifier notifier;
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  const std::int64_t target_cert = 654;

  dto::DeviceInstallConfigDto config{};
  config.version = 7;

  dto::InstallItem copy_item{};
  copy_item.id = "copy-empty";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = target_cert;
  copy_item.from = std::vector<std::string>{"fullchain.pem"};
  copy_item.to = std::vector<std::string>{};
  config.installs.push_back(copy_item);

  createHarness(config_dir, runtime_dir,
                std::make_unique<MockInstallConfigFetcher>(config),
                std::make_unique<MockerResourceFetcher>(""),
                std::make_unique<MockAccessTokenLoaderFixed>(std::nullopt));

  auto resource_dir = runtime_dir / "resources" / "certs" /
                      std::to_string(target_cert) / "current";
  write_file(resource_dir / "fullchain.pem", "CHAIN654\n");

  std::optional<monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      plan_result;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        plan_result = result;
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(plan_result.has_value());
  ASSERT_TRUE(plan_result->is_ok()) << plan_result->error();

  auto signal = make_cert_updated_signal(target_cert);

  std::optional<monad::MyVoidResult> apply_r;
  harness_->install_manager()
      .apply_copy_actions_for_signal(signal)
      .run([&](auto result) {
        apply_r = result;
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(apply_r.has_value());
  ASSERT_TRUE(apply_r->is_ok()) << apply_r->error();

  auto dest_path = runtime_dir / "deploy" / "certs" / "inactive.pem";
  EXPECT_FALSE(std::filesystem::exists(dest_path));

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture, CopyActionsAggregateFailures) {
  misc::ThreadNotifier notifier;
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  dto::DeviceInstallConfigDto config{};
  dto::InstallItem copy_item{};
  copy_item.id = "copy-failures";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = static_cast<std::int64_t>(4242);
  copy_item.from = std::vector<std::string>{"missing.pem", "also-missing.pem"};
  auto absolute_dest = runtime_dir / "deploy" / "certs" / "missing.pem";
  copy_item.to =
      std::vector<std::string>{"relative-dest.pem", absolute_dest.string()};
  config.installs.push_back(copy_item);

  auto fetch_override =
      [config](std::optional<std::string> /*access_token*/,
               std::optional<std::int64_t> expected_version,
               const std::optional<std::string> &expected_hash)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    dto::DeviceInstallConfigDto copy = config;
    if (expected_version) {
      copy.version = *expected_version;
    }
    if (expected_hash) {
      copy.installs_hash = *expected_hash;
    }
    return monad::IO<dto::DeviceInstallConfigDto>::pure(std::move(copy));
  };

  createHarness(
      config_dir, runtime_dir,
      std::make_unique<LambdaInstallConfigFetcher>(std::move(fetch_override)),
      std::make_unique<MockerResourceFetcher>(""),
      std::make_unique<MockAccessTokenLoaderFixed>(std::nullopt));

  auto handler = harness_->copy_action_handler_factory();
  std::optional<monad::MyVoidResult> apply_r;
  handler->apply(config, std::nullopt, std::nullopt).run([&](auto result) {
    apply_r = result;
    notifier.notify();
  });
  notifier.waitForNotification();
  ASSERT_TRUE(apply_r.has_value());
  ASSERT_TRUE(apply_r->is_err())
      << "Expected aggregated failures but copy actions succeeded";
  auto err = apply_r->error();
  EXPECT_EQ(err.code, my_errors::GENERAL::FILE_READ_WRITE);
  std::string_view message(err.what);
  EXPECT_NE(message.find("Missing deploy materials"), std::string_view::npos)
      << "Missing deploy materials diagnostic";
  EXPECT_NE(message.find("missing.pem"), std::string_view::npos)
      << "Missing source identifier for missing.pem";
  EXPECT_NE(message.find("also-missing.pem"), std::string_view::npos)
      << "Missing source identifier for also-missing.pem";

  EXPECT_FALSE(std::filesystem::exists(absolute_dest))
      << "No destination file should be created on failure";

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture, CopiesCaIntoOverrideDirectory) {
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  dto::DeviceInstallConfigDto config{};
  dto::InstallItem import_item{};
  import_item.id = "import-root";
  import_item.type = "import_ca";
  import_item.ob_type = std::string{"ca"};
  import_item.ob_id = static_cast<std::int64_t>(55);
  import_item.ob_name = std::string{"Example Root CA"};
  import_item.continue_on_error = true;
  config.installs.push_back(import_item);

  createHarness(config_dir, runtime_dir,
                std::make_unique<MockInstallConfigFetcher>(config),
                std::make_unique<MockerResourceFetcher>(""),
                std::make_unique<MockAccessTokenLoaderFixed>(std::nullopt));

  auto runtime_dir_path = harness_->runtime_dir();
  auto resource_dir = runtime_dir_path / "resources" / "cas" / "55" / "current";
  write_file(resource_dir / "ca.pem", "CA-PEM-DATA\n");

  auto trust_dir = runtime_dir_path / "trust-anchors";
  ScopedEnvVar dir_env("CERTCTRL_CA_IMPORT_DIR", trust_dir.string());
#if defined(_WIN32)
  ScopedEnvVar cmd_env("CERTCTRL_CA_UPDATE_COMMAND", "exit 0");
#else
  ScopedEnvVar cmd_env("CERTCTRL_CA_UPDATE_COMMAND", "true");
#endif

  // auto materializer = make_noop_materializer();
  // auto resource_factory = make_fixed_resource_factory(materializer);
  // certctrl::install_actions::ImportCaActionHandler handler(provider, output,
  //                                                          resource_factory);
  misc::ThreadNotifier notifier(3000);
  auto handler = harness_->import_ca_handler_factory();
  std::optional<monad::Error> apply_err;
  handler->apply(config, std::nullopt, std::nullopt).run([&](auto result) {
    if (!result.is_ok()) {
      apply_err = result.error();
    }
    notifier.notify();
  });
  notifier.waitForNotification();
  if (apply_err) {
    FAIL() << "apply_import_ca_actions failed: " << apply_err->what;
  }

  // Find any generated CA file in trust_dir and verify its contents
  std::vector<std::filesystem::path> crt_files;
  if (std::filesystem::exists(trust_dir)) {
    for (const auto &entry : std::filesystem::directory_iterator(trust_dir)) {
      if (entry.is_regular_file() && entry.path().extension() == ".crt") {
        crt_files.push_back(entry.path());
      }
    }
  }
  ASSERT_FALSE(crt_files.empty()) << "no .crt file found in " << trust_dir;
  EXPECT_EQ(read_file(crt_files.front()), "CA-PEM-DATA\n");

  std::filesystem::remove_all(runtime_dir_path);
}

TEST_F(InstallConfigManagerFixture, FailsCaImportWhenServerReturns500) {
  misc::ThreadNotifier notifier(3000);
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();
  FailingCaServer server;

  dto::DeviceInstallConfigDto config{};
  dto::InstallItem ca_item{};
  ca_item.id = "ca-fetch";
  ca_item.type = "import_ca";
  ca_item.ob_type = std::string{"ca"};
  ca_item.ob_id = static_cast<std::int64_t>(99);
  ca_item.ob_name = std::string{"Failing CA"};
  ca_item.from = std::vector<std::string>{"ca.pem"};
  config.installs.push_back(ca_item);

  ScopedEnvVar dir_env("CERTCTRL_CA_IMPORT_DIR",
                       (runtime_dir / "trust-anchors").string());
#if defined(_WIN32)
  ScopedEnvVar cmd_env("CERTCTRL_CA_UPDATE_COMMAND", "exit 0");
#else
  ScopedEnvVar cmd_env("CERTCTRL_CA_UPDATE_COMMAND", "true");
#endif
  std::filesystem::create_directories(runtime_dir / "trust-anchors");

  auto install_fetcher = std::make_unique<MockInstallConfigFetcher>(config);
  auto resource_fetcher = std::make_unique<ServerBackedResourceFetcher>();
  auto *resource_fetcher_ptr = resource_fetcher.get();
  createHarness(config_dir, runtime_dir, std::move(install_fetcher),
                std::move(resource_fetcher),
                std::make_unique<MockAccessTokenLoaderFixed>("hello-token"),
                server.base_url());
  resource_fetcher_ptr->bind(harness_->io_context_manager(),
                             harness_->config_provider(), harness_->output(),
                             harness_->http_client_manager());

  ASSERT_FALSE(harness_->state_store()
                   .save_tokens("test-access-token", std::nullopt, std::nullopt)
                   .has_value());

  monad::MyVoidResult r;
  harness_->install_manager()
      .apply_import_ca_actions(config, std::nullopt, std::nullopt)
      .run([&](auto result) {
        r = std::move(result);
        notifier.notify();
      });
  notifier.waitForNotification();
  EXPECT_TRUE(r.is_err())
      << "Expected CA import to fail when server returns 500";

  EXPECT_EQ(r.error().code, my_errors::NETWORK::READ_ERROR);
  EXPECT_EQ(r.error().response_status, 500);
  auto *preview_field = r.error().params.if_contains("response_body_preview");
  EXPECT_NE(preview_field, nullptr);
  EXPECT_TRUE(preview_field->is_string());
  std::string preview = preview_field->as_string().c_str();
  EXPECT_NE(preview.find("bad allocation"), std::string::npos);

  auto ca_root = runtime_dir / "resources" / "cas" /
                 std::to_string(*ca_item.ob_id) / "current";
  EXPECT_FALSE(std::filesystem::exists(ca_root / "ca.pem"));
  std::cerr << "Before stopping server" << std::endl;
  std::cerr << "Stopping server" << std::endl;
  server.stop();
  std::cerr << "Server stopped" << std::endl;
  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture, FiltersCopyActionsByResource) {
  misc::ThreadNotifier notifier(3000);
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  auto resource_dir_123 =
      runtime_dir / "resources" / "certs" / "123" / "current";
  auto resource_dir_456 =
      runtime_dir / "resources" / "certs" / "456" / "current";
  write_file(resource_dir_123 / "fullchain.pem", "CHAIN123\n");
  write_file(resource_dir_456 / "fullchain.pem", "CHAIN456\n");

  dto::DeviceInstallConfigDto config{};
  config.id = 11;
  config.user_device_id = 77;
  config.version = 12;

  dto::InstallItem item_a{};
  item_a.id = "cert123";
  item_a.type = "copy";
  item_a.ob_type = std::string{"cert"};
  item_a.ob_id = static_cast<std::int64_t>(123);
  item_a.from = std::vector<std::string>{"fullchain.pem"};
  auto dest_a = runtime_dir / "deploy" / "123" / "fullchain.pem";
  item_a.to = std::vector<std::string>{dest_a.string()};

  dto::InstallItem item_b{};
  item_b.id = "cert456";
  item_b.type = "copy";
  item_b.ob_type = std::string{"cert"};
  item_b.ob_id = static_cast<std::int64_t>(456);
  item_b.from = std::vector<std::string>{"fullchain.pem"};
  auto dest_b = runtime_dir / "deploy" / "456" / "fullchain.pem";
  item_b.to = std::vector<std::string>{dest_b.string()};

  config.installs.push_back(item_a);
  config.installs.push_back(item_b);

  createHarness(config_dir, runtime_dir,
                std::make_unique<MockInstallConfigFetcher>(config),
                std::make_unique<MockerResourceFetcher>(""),
                std::make_unique<MockAccessTokenLoaderFixed>(std::nullopt));

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  std::optional<
      monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      op_r;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        if (result.is_ok()) {
          plan = result.value();
        }
        op_r = std::move(result);
      });

  ASSERT_TRUE(op_r.has_value());
  ASSERT_TRUE(op_r->is_ok());
  ASSERT_TRUE(plan);

  // First apply only cert 123
  monad::MyVoidResult void_r;
  harness_->install_manager()
      .apply_copy_actions(*plan, std::string("cert"),
                          static_cast<std::int64_t>(123))
      .run([&](auto result) { void_r = std::move(result); });

  ASSERT_TRUE(void_r.is_ok());
  EXPECT_TRUE(std::filesystem::exists(dest_a));
  EXPECT_FALSE(std::filesystem::exists(dest_b));
  EXPECT_EQ(read_file(dest_a), "CHAIN123\n");

  // Now apply only cert 456
  harness_->install_manager()
      .apply_copy_actions(*plan, std::string("cert"),
                          static_cast<std::int64_t>(456))
      .run([&](auto result) {
        void_r = std::move(result);
        notifier.notify();
      });
  notifier.waitForNotification();

  ASSERT_TRUE(void_r.is_ok());
  EXPECT_TRUE(std::filesystem::exists(dest_b));
  EXPECT_EQ(read_file(dest_b), "CHAIN456\n");

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture, HandlesMasterOnlyPlaintextBundle) {
  misc::ThreadNotifier notifier(3000);
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  const std::int64_t cert_id = 321;
  const std::string private_key_pem =
      "-----BEGIN PRIVATE KEY-----\n"
      "MC4CAQAwBQYDK2VwBCIEIC+BYXto9Jw4/dZElWXKfW6hDqmUC8Uh7xiw5J2wGxmh\n"
      "-----END PRIVATE KEY-----\n";

  const std::string certificate_pem =
      "-----BEGIN CERTIFICATE-----\n"
      "MIIBVTCCAQegAwIBAgIUNaR75E43mHngKYNdCa8JOW/d7dEwBQYDK2VwMCAxHjAc\n"
      "BgNVBAMMFWZhbGxiYWNrLmV4YW1wbGUudGVzdDAeFw0yNTEwMjUxMTA3NTBaFw0y\n"
      "NjEwMjUxMTA3NTBaMCAxHjAcBgNVBAMMFWZhbGxiYWNrLmV4YW1wbGUudGVzdDAq\n"
      "MAUGAytlcAMhABceLDKOiP/CqZAfwi/uDcA4UO/1Kv5bect8to8uuVoLo1MwUTAd\n"
      "BgNVHQ4EFgQUaZ/x7IAcuGgUL6gSG+8//Kf1JRswHwYDVR0jBBgwFoAUaZ/x7IAc\n"
      "uGgUL6gSG+8//Kf1JRswDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBeHFmFCaDL\n"
      "7Ary5Uhf27nkdLdiq/QpOr5oiOEG7jnW5NwaJhj9kRo45MmK5yDGYLpUYmpb+Bnn\n"
      "futpyqmphkYC\n"
      "-----END CERTIFICATE-----\n";

  boost::json::object deploy_data;
  deploy_data["enc_scheme"] = "plaintext";
  deploy_data["private_key_pem"] = private_key_pem;

  boost::json::object detail_data;
  detail_data["certificate_pem"] = certificate_pem;

  boost::json::object payload;
  payload["deploy"] = deploy_data;
  payload["detail"] = detail_data;

  dto::DeviceInstallConfigDto config{};
  config.id = 3;
  config.user_device_id = 30;
  config.version = 5;

  dto::InstallItem copy_item{};
  copy_item.id = "plaintext-cert";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = cert_id;
  copy_item.from = std::vector<std::string>{"private.key"};
  auto dest = runtime_dir / "deploy" / "certs" / "private.key";
  copy_item.to = std::vector<std::string>{dest.string()};
  config.installs.push_back(copy_item);

  createHarness(config_dir, runtime_dir,
                std::make_unique<MockInstallConfigFetcher>(config),
                std::make_unique<MockerResourceFetcher>(""),
                std::make_unique<MockAccessTokenLoaderFixed>(std::nullopt));
  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  std::optional<
      monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      op_r;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        op_r = std::move(result);
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(op_r.has_value());
  ASSERT_TRUE(op_r->is_ok())
      << "ensure_config_version failed: " << op_r->error();
  plan = op_r->value();
  ASSERT_TRUE(plan);

  std::optional<monad::MyVoidResult> apply_r;
  harness_->install_manager()
      .apply_copy_actions(*plan, std::nullopt, std::nullopt)
      .run([&](auto result) {
        apply_r = std::move(result);
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(apply_r.has_value());
  ASSERT_TRUE(apply_r->is_ok())
      << "apply_copy_actions failed: " << apply_r->error();

  ASSERT_TRUE(std::filesystem::exists(dest));
  EXPECT_EQ(read_file(dest), private_key_pem);

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture,
       GeneratesMaterialsFromCertificateDetailOnly) {
  misc::ThreadNotifier notifier(3000);
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  const std::int64_t cert_id = 654321;
  const std::string private_key_pem =
      "-----BEGIN PRIVATE KEY-----\n"
      "MC4CAQAwBQYDK2VwBCIEIC+BYXto9Jw4/dZElWXKfW6hDqmUC8Uh7xiw5J2wGxmh\n"
      "-----END PRIVATE KEY-----\n";

  const std::string leaf_cert =
      "-----BEGIN CERTIFICATE-----\n"
      "MIIBVTCCAQegAwIBAgIUNaR75E43mHngKYNdCa8JOW/d7dEwBQYDK2VwMCAxHjAc\n"
      "BgNVBAMMFWZhbGxiYWNrLmV4YW1wbGUudGVzdDAeFw0yNTEwMjUxMTA3NTBaFw0y\n"
      "NjEwMjUxMTA3NTBaMCAxHjAcBgNVBAMMFWZhbGxiYWNrLmV4YW1wbGUudGVzdDAq\n"
      "MAUGAytlcAMhABceLDKOiP/CqZAfwi/uDcA4UO/1Kv5bect8to8uuVoLo1MwUTAd\n"
      "BgNVHQ4EFgQUaZ/x7IAcuGgUL6gSG+8//Kf1JRswHwYDVR0jBBgwFoAUaZ/x7IAc\n"
      "uGgUL6gSG+8//Kf1JRswDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBeHFmFCaDL\n"
      "7Ary5Uhf27nkdLdiq/QpOr5oiOEG7jnW5NwaJhj9kRo45MmK5yDGYLpUYmpb+Bnn\n"
      "futpyqmphkYC\n"
      "-----END CERTIFICATE-----\n";

  const std::string chain_cert = leaf_cert;

  boost::json::object detail_data;
  detail_data["id"] = cert_id;
  detail_data["domain_name"] = "fallback.example.test";
  detail_data["certificate_pem"] = leaf_cert;
  detail_data["fullchain_pem"] = leaf_cert + chain_cert;
  detail_data["chain_pem"] = chain_cert;
  detail_data["private_key_pem"] = private_key_pem;

  boost::json::object deploy_data;
  deploy_data["fullchain_pem"] = leaf_cert + chain_cert;
  deploy_data["chain_pem"] = chain_cert;

  boost::json::object payload;
  payload["detail"] = detail_data;
  payload["deploy"] = deploy_data;

  dto::DeviceInstallConfigDto config{};
  config.id = 4;
  config.user_device_id = 44;
  config.version = 7;

  dto::InstallItem copy_item{};
  copy_item.id = "cert-detail-only";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = cert_id;
  copy_item.from = std::vector<std::string>{
      "private.key",     "certificate.pem", "chain.pem", "fullchain.pem",
      "certificate.der", "bundle.pfx",      "meta.json"};

  auto install_root = runtime_dir / "install";
  copy_item.to = std::vector<std::string>{
      (install_root / "cert" / "private.key").string(),
      (install_root / "cert" / "certificate.pem").string(),
      (install_root / "cert" / "chain.pem").string(),
      (install_root / "cert" / "fullchain.pem").string(),
      (install_root / "cert" / "certificate.der").string(),
      (install_root / "cert" / "bundle.pfx").string(),
      (install_root / "cert" / "meta.json").string()};
  config.installs.push_back(copy_item);

  createHarness(
      config_dir, runtime_dir,
      std::make_unique<MockInstallConfigFetcher>(config),
      std::make_unique<MockerResourceFetcher>(boost::json::serialize(payload)),
      std::make_unique<MockAccessTokenLoaderFixed>(std::nullopt));

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  std::optional<
      monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      op_r;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        op_r = std::move(result);
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(op_r.has_value());
  ASSERT_TRUE(op_r->is_ok())
      << "ensure_config_version failed: " << op_r->error();
  plan = op_r->value();

  ASSERT_TRUE(plan);

  std::optional<monad::MyVoidResult> apply_r;
  harness_->install_manager()
      .apply_copy_actions(*plan, std::nullopt, std::nullopt)
      .run([&](auto result) {
        apply_r = std::move(result);
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(apply_r.has_value());
  ASSERT_TRUE(apply_r->is_ok())
      << "apply_copy_actions failed: " << apply_r->error();

  auto resource_root =
      runtime_dir / "resources" / "certs" / std::to_string(cert_id) / "current";
  ASSERT_TRUE(std::filesystem::exists(resource_root));
  EXPECT_EQ(read_file(resource_root / "private.key"), private_key_pem);
  EXPECT_EQ(read_file(resource_root / "certificate.pem"), leaf_cert);
  EXPECT_EQ(read_file(resource_root / "chain.pem"), chain_cert);
  EXPECT_EQ(read_file(resource_root / "fullchain.pem"), leaf_cert + chain_cert);

  auto der_path = resource_root / "certificate.der";
  ASSERT_TRUE(std::filesystem::exists(der_path));
  EXPECT_GT(std::filesystem::file_size(der_path), 0u);

  auto pfx_path = resource_root / "bundle.pfx";
  ASSERT_TRUE(std::filesystem::exists(pfx_path));
  EXPECT_GT(std::filesystem::file_size(pfx_path), 0u);

  auto meta_text = read_file(resource_root / "meta.json");
  boost::system::error_code ec;
  auto meta_json = boost::json::parse(meta_text, ec);
  ASSERT_FALSE(ec);
  ASSERT_TRUE(meta_json.is_object());
  auto &meta_obj = meta_json.as_object();
  ASSERT_TRUE(meta_obj.if_contains("certificate"));
  ASSERT_TRUE(meta_obj.if_contains("deploy_materials"));

  for (const auto &dest : *copy_item.to) {
    ASSERT_TRUE(std::filesystem::exists(dest))
        << "expected install destination missing: " << dest;
  }

  EXPECT_EQ(read_file(copy_item.to->at(0)), private_key_pem);
  EXPECT_EQ(read_file(copy_item.to->at(1)), leaf_cert);
  EXPECT_EQ(read_file(copy_item.to->at(2)), chain_cert);
  EXPECT_EQ(read_file(copy_item.to->at(3)), leaf_cert + chain_cert);

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture,
       PersistsExpectedVersionWhenFetcherSucceeds) {
  misc::ThreadNotifier notifier(3000);
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  dto::DeviceInstallConfigDto config{};
  config.id = 5;
  config.user_device_id = 55;
  config.version = 17;

  int call_count = 0;
  bool saw_expected_version = false;
  auto fetch_override = [&config, &call_count, &saw_expected_version](
                            std::optional<std::string> /*access_token*/,
                            std::optional<std::int64_t> expected_version,
                            const std::optional<std::string> &expected_hash)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    ++call_count;
    dto::DeviceInstallConfigDto copy = config;
    if (expected_version) {
      saw_expected_version = (*expected_version == config.version);
      copy.version = *expected_version;
    }
    if (expected_hash) {
      copy.installs_hash = *expected_hash;
    }
    return monad::IO<dto::DeviceInstallConfigDto>::pure(std::move(copy));
  };

  createHarness(
      config_dir, runtime_dir,
      std::make_unique<LambdaInstallConfigFetcher>(std::move(fetch_override)),
      std::make_unique<MockerResourceFetcher>(""),
      std::make_unique<MockAccessTokenLoaderFixed>(std::nullopt));

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  std::optional<
      monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      op_r;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        op_r = std::move(result);
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(op_r.has_value());
  ASSERT_TRUE(op_r->is_ok());
  plan = op_r->value();

  ASSERT_TRUE(plan);
  EXPECT_EQ(call_count, 1);
  EXPECT_TRUE(saw_expected_version);
  ASSERT_TRUE(harness_->install_manager().local_version());
  EXPECT_EQ(*harness_->install_manager().local_version(), config.version);

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture, PropagatesFetcherFailure) {
  misc::ThreadNotifier notifier(3000);
  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  dto::DeviceInstallConfigDto config{};
  config.id = 6;
  config.user_device_id = 66;
  config.version = 23;

  int call_count = 0;
  auto fetch_override =
      [&call_count](std::optional<std::string> /*access_token*/,
                    std::optional<std::int64_t> /*expected_version*/,
                    const std::optional<std::string> & /*expected_hash*/)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    ++call_count;
    auto err = monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                                 "install-config fetch returned stale version");
    return monad::IO<dto::DeviceInstallConfigDto>::fail(std::move(err));
  };

  createHarness(
      config_dir, runtime_dir,
      std::make_unique<LambdaInstallConfigFetcher>(std::move(fetch_override)),
      std::make_unique<MockerResourceFetcher>(""),
      std::make_unique<MockAccessTokenLoaderFixed>(std::nullopt));
  std::optional<
      monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      op_r;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        op_r = std::move(result);
        notifier.notify();
      });
  notifier.waitForNotification();
  ASSERT_TRUE(op_r.has_value());
  ASSERT_TRUE(op_r->is_err());

  EXPECT_EQ(op_r->error().code, my_errors::GENERAL::UNEXPECTED_RESULT);
  EXPECT_FALSE(harness_->install_manager().local_version());
  EXPECT_EQ(call_count, 1);

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture, RefreshesAccessTokenOnUnauthorizedFetch) {
  misc::ThreadNotifier notifier(3000);

  MockRefreshServer refresh_server;
  refresh_server.set_expected_refresh_token("refresh-initial");
  refresh_server.set_response_tokens("refreshed-access", "refreshed-refresh");
  auto base_url = refresh_server.base_url();

  auto config_dir = make_temp_runtime_dir();
  auto runtime_dir = make_temp_runtime_dir();

  auto fetch_call_count = std::make_shared<std::atomic<int>>(0);
  auto first_token = std::make_shared<std::string>("<unset>");
  auto second_token = std::make_shared<std::string>("<unset>");

  auto fetch_override =
      [fetch_call_count, first_token,
       second_token](std::optional<std::string> access_token,
                     std::optional<std::int64_t> /*expected_version*/,
                     const std::optional<std::string> & /*expected_hash*/)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    const int call_index = fetch_call_count->fetch_add(1);
    if (call_index == 0) {
      *first_token = access_token.value_or("<missing>");
      auto err = monad::make_error(my_errors::NETWORK::READ_ERROR,
                                   "install-config fetch HTTP status 401");
      err.response_status = 401;
      return monad::IO<dto::DeviceInstallConfigDto>::fail(std::move(err));
    }

    *second_token = access_token.value_or("<missing>");
    dto::DeviceInstallConfigDto cfg{};
    cfg.version = 77;
    cfg.user_device_id = 1234;
    return monad::IO<dto::DeviceInstallConfigDto>::pure(std::move(cfg));
  };

  createHarness(
      config_dir, runtime_dir,
      std::make_unique<LambdaInstallConfigFetcher>(std::move(fetch_override)),
      std::make_unique<MockerResourceFetcher>(""), nullptr, base_url);

  ASSERT_FALSE(harness_->state_store()
                   .save_tokens("expired-access", "refresh-initial",
                                std::nullopt)
                   .has_value());

  std::optional<
      monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      op_r;
  harness_->install_manager()
      .ensure_config_version(std::nullopt, std::nullopt)
      .run([&](auto result) {
        op_r = std::move(result);
        notifier.notify();
      });
  notifier.waitForNotification();

  ASSERT_TRUE(op_r.has_value());
  ASSERT_TRUE(op_r->is_ok())
      << "ensure_config_version failed: " << op_r->error();
  const auto plan = op_r->value();
  ASSERT_TRUE(plan);
  EXPECT_EQ(plan->version, 77);

  EXPECT_EQ(fetch_call_count->load(), 2);
  EXPECT_EQ(*first_token, "expired-access");
  EXPECT_EQ(*second_token, "refreshed-access");

  EXPECT_EQ(refresh_server.refresh_calls(), 1);
  EXPECT_EQ(refresh_server.last_refresh_token(), "refresh-initial");
  EXPECT_TRUE(refresh_server.observed_expected_token());

  auto stored_access = harness_->state_store().get_access_token();
  auto stored_refresh = harness_->state_store().get_refresh_token();
  ASSERT_TRUE(stored_access.has_value());
  ASSERT_TRUE(stored_refresh.has_value());
  EXPECT_EQ(*stored_access, "refreshed-access");
  EXPECT_EQ(*stored_refresh, "refreshed-refresh");

  std::filesystem::remove_all(runtime_dir);
}
