#include <gtest/gtest.h>

#include <atomic>
#include <boost/asio.hpp>
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
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include "certctrl_common.hpp"
#include "client_ssl_ctx.hpp"
#include "common_macros.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/function_adapters.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "handlers/install_actions/install_resource_materializer.hpp"
#include "handlers/install_config_manager.hpp"
#include "http_client_manager.hpp"
#include "include/install_config_manager_test_utils.hpp"
#include "install_config_fetcher.hpp"
#include "io_monad.hpp"
#include "log_stream.hpp"
#include "misc_util.hpp"
#include "my_error_codes.hpp"
#include "resource_fetcher.hpp"
#include "result_monad.hpp"

namespace {

namespace asio = boost::asio;
namespace json = boost::json;
namespace di = boost::di;

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
    [[maybe_unused]] auto close_status = acceptor_.close(ec);
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

  MockerResourceFetcher(std::string body) : override_body(std::move(body)) {}
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

struct InstallManagerDiHarness {
  InstallManagerDiHarness(
      std::filesystem::path config_dir, std::filesystem::path runtime_dir,
      std::string base_url,
      certctrl::install_actions::IDeviceInstallConfigFetcher &fetcher,
      certctrl::install_actions::IResourceFetcher &resource_fetcher,
      int http_threads = 1) {
    config_dir_ = std::move(config_dir);
    runtime_dir_ = std::move(runtime_dir);

    json::object app_json{{"auto_apply_config", false},
                          {"verbose", "info"},
                          {"url_base", std::move(base_url)},
                          {"runtime_dir", runtime_dir_.string()}};
    write_json_file(config_dir_ / "application.json", app_json);

    json::object httpclient_json{
        {"threads_num", http_threads},   {"ssl_method", "tlsv12_client"},
        {"insecure_skip_verify", true},  {"verify_paths", json::array{}},
        {"certificates", json::array{}}, {"certificate_files", json::array{}},
        {"proxy_pool", json::array{}}};
    write_json_file(config_dir_ / "httpclient_config.json", httpclient_json);

    json::object ioc_json{{"threads_num", 1},
                          {"name", "install-config-test-ioc"}};
    write_json_file(config_dir_ / "ioc_config.json", ioc_json);

    json::object certctrl_config_json{
        {"auto_apply_config", false},
        {"verbose", "info"},
        {"url_base", std::move(base_url)},
        {"runtime_dir", runtime_dir_.string()},
        {"interval_seconds", 300},
        {"update_check_url",
         "https://install.lets-script.com/api/version/check"}};
    DEBUG_PRINT("application.json: " << certctrl_config_json);
    write_json_file(config_dir_ / "application.json", certctrl_config_json);

    std::vector<fs::path> config_paths{config_dir_};
    std::vector<std::string> profiles;
    cjj365::ConfigSources::instance_count.store(0);
    static auto config_sources = cjj365::ConfigSources(config_paths, profiles);
    config_sources_ = &config_sources;

    auto injector = di::make_injector(
        testinfra::build_base_injector(config_sources),
        di::bind<certctrl::install_actions::IDeviceInstallConfigFetcher>.to(
            fetcher),
        di::bind<certctrl::install_actions::IResourceFetcher>.to(
            resource_fetcher));

    auto inj_holder = std::make_shared<decltype(injector)>(std::move(injector));
    injector_holder_ = inj_holder;
    auto &inj = *inj_holder;

    output_ = &injector.template create<customio::ConsoleOutput &>();
    config_provider_ = &inj.create<certctrl::ICertctrlConfigProvider &>();
    io_context_manager_ = &inj.create<cjj365::IoContextManager &>();
    http_client_manager_ = &inj.create<client_async::HttpClientManager &>();
    install_manager_ = &inj.create<certctrl::InstallConfigManager &>();
    import_ca_handler_factory =
        inj.create<certctrl::install_actions::ImportCaActionHandler::Factory>();
    resource_factory =
        inj.create<certctrl::install_actions::IResourceMaterializer::Factory>();
    exec_env_factory = inj.create<
        certctrl::install_actions::IExecEnvironmentResolver::Factory>();
    copy_action_handler_factory =
        inj.create<certctrl::install_actions::CopyActionHandler::Factory>();
    exec_action_handler_factory =
        inj.create<certctrl::install_actions::ExecActionHandler::Factory>();
  }

  ~InstallManagerDiHarness() {
    if (http_client_manager_) {
      http_client_manager_->stop();
    }
    cjj365::ConfigSources::instance_count.store(0);
    std::error_code ec;
    std::filesystem::remove_all(config_dir_, ec);
    std::filesystem::remove_all(runtime_dir_, ec);
  }

  certctrl::ICertctrlConfigProvider &config_provider() {
    return *config_provider_;
  }

  customio::ConsoleOutput &output() { return *output_; }

  cjj365::IoContextManager &io_context_manager() {
    return *io_context_manager_;
  }

  client_async::HttpClientManager &http_client_manager() {
    return *http_client_manager_;
  }

  certctrl::InstallConfigManager &install_manager() {
    return *install_manager_;
  }

  const std::filesystem::path &runtime_dir() const { return runtime_dir_; }

  certctrl::install_actions::ImportCaActionHandler::Factory
      import_ca_handler_factory;
  certctrl::install_actions::IResourceMaterializer::Factory resource_factory;
  certctrl::install_actions::IExecEnvironmentResolver::Factory exec_env_factory;
  certctrl::install_actions::CopyActionHandler::Factory
      copy_action_handler_factory;
  certctrl::install_actions::ExecActionHandler::Factory
      exec_action_handler_factory;

private:
  std::filesystem::path config_dir_{};
  std::filesystem::path runtime_dir_{};
  customio::ConsoleOutput *output_;
  std::shared_ptr<certctrl::CliCtx> cli_ctx_{};
  cjj365::ConfigSources *config_sources_{nullptr};
  std::shared_ptr<void> injector_holder_{};
  certctrl::ICertctrlConfigProvider *config_provider_{nullptr};
  cjj365::IoContextManager *io_context_manager_{nullptr};
  client_async::HttpClientManager *http_client_manager_{nullptr};
  certctrl::InstallConfigManager *install_manager_{nullptr};
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
      std::string base_url = "https://api.example.test", int http_threads = 1) {
    fetcher_holder_ = std::move(fetcher);
    resource_fetcher_holder_ = std::move(resource_fetcher);
    harness_ = std::make_unique<InstallManagerDiHarness>(
        std::move(config_dir), std::move(runtime_dir), std::move(base_url),
        *fetcher_holder_, *resource_fetcher_holder_, http_threads);
  }

  std::unique_ptr<certctrl::install_actions::IDeviceInstallConfigFetcher>
      fetcher_holder_;
  std::unique_ptr<certctrl::install_actions::IResourceFetcher>
      resource_fetcher_holder_;
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
  harness_ = std::make_unique<InstallManagerDiHarness>(
      config_dir, runtime_dir, "https://api.example.test", fetcher,
      resource_fetcher);

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
  harness_ = std::make_unique<InstallManagerDiHarness>(
      config_dir, runtime_dir, "https://api.example.test", fetcher,
      resource_fetcher);

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

TEST_F(InstallConfigManagerFixture, CopyActionsAggregateFailures) {
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

  createHarness(config_dir, runtime_dir,
                std::make_unique<MockInstallConfigFetcher>(config),
                std::make_unique<MockerResourceFetcher>(""));

  bool callback_invoked = false;
  // auto materializer = make_noop_materializer();
  // auto resource_factory = make_fixed_resource_factory(materializer);
  // certctrl::install_actions::CopyActionHandler handler(provider, output,
  //                                                      resource_factory);
  auto handler = harness_->copy_action_handler_factory();
  handler->apply(config, std::nullopt, std::nullopt).run([&](auto result) {
    callback_invoked = true;
    ASSERT_TRUE(result.is_err())
        << "Expected aggregated failures but copy actions succeeded";
    auto err = result.error();
    EXPECT_EQ(err.code, my_errors::GENERAL::FILE_READ_WRITE);
    std::string_view message(err.what);
    EXPECT_NE(
        message.find("destination path 'relative-dest.pem' is not absolute"),
        std::string_view::npos)
        << "Missing relative path diagnostic";
    EXPECT_NE(message.find("Source file"), std::string_view::npos)
        << "Missing source not found diagnostic";
  });

  ASSERT_TRUE(callback_invoked);
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
  config.installs.push_back(import_item);

  createHarness(config_dir, runtime_dir,
                std::make_unique<MockInstallConfigFetcher>(config),
                std::make_unique<MockerResourceFetcher>(""));

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
  auto handler = harness_->import_ca_handler_factory();
  handler->apply(config, std::nullopt, std::nullopt).run([&](auto result) {
    if (!result.is_ok()) {
      auto err = result.error();
      FAIL() << "apply_import_ca_actions failed: " << err.what;
    }
  });

  std::filesystem::path expected = trust_dir / "example-root-ca.crt";
  ASSERT_TRUE(std::filesystem::exists(expected));
  EXPECT_EQ(read_file(expected), "CA-PEM-DATA\n");

  std::filesystem::remove_all(runtime_dir_path);
}

TEST_F(InstallConfigManagerFixture, FailsCaImportWhenServerReturns500) {
  auto runtime_dir = harness_->runtime_dir();
  misc::ThreadNotifier notifier(3000);
  FailingCaServer server;

  std::filesystem::create_directories(runtime_dir / "state");
  write_file(runtime_dir / "state" / "access_token.txt", "test-access-token");

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

  EXPECT_EQ(r.error().code, my_errors::GENERAL::FILE_NOT_FOUND);
  EXPECT_EQ(r.error().response_status, 500);
  DEBUG_PRINT("**********\n" << r.error() << "\n**********\n");
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
  auto runtime_dir = harness_->runtime_dir();

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

  auto fetch_override =
      [config](std::optional<std::int64_t> expected_version,
               const std::optional<std::string> &expected_hash)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    dto::DeviceInstallConfigDto copy = config;
    if (expected_version) {
      copy.version = *expected_version;
    }
    if (expected_hash) {
      copy.installs_hash = *expected_hash;
    }
    return monad::IO<dto::DeviceInstallConfigDto>::pure(copy);
  };

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  std::optional<
      monad::MyResult<std::shared_ptr<const dto::DeviceInstallConfigDto>>>
      op_r;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        op_r = std::move(result);
        plan = result.value();
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
      .run([&](auto result) { void_r = std::move(result); });

  ASSERT_TRUE(void_r.is_ok());
  EXPECT_TRUE(std::filesystem::exists(dest_b));
  EXPECT_EQ(read_file(dest_b), "CHAIN456\n");

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture, HandlesMasterOnlyPlaintextBundle) {
  auto runtime_dir = harness_->runtime_dir();

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

  auto fetch_override =
      [config](std::optional<std::int64_t> expected_version,
               const std::optional<std::string> &expected_hash)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    dto::DeviceInstallConfigDto copy = config;
    if (expected_version) {
      copy.version = *expected_version;
    }
    if (expected_hash) {
      copy.installs_hash = *expected_hash;
    }
    return monad::IO<dto::DeviceInstallConfigDto>::pure(copy);
  };

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        ASSERT_TRUE(result.is_ok());
        plan = result.value();
      });

  ASSERT_TRUE(plan);

  bool apply_ok = false;
  monad::Error apply_err{};
  harness_->install_manager()
      .apply_copy_actions(*plan, std::nullopt, std::nullopt)
      .run([&](auto result) {
        apply_ok = result.is_ok();
        if (!apply_ok) {
          apply_err = result.error();
        }
      });

  ASSERT_TRUE(apply_ok) << "apply_copy_actions failed: " << apply_err.what;

  ASSERT_TRUE(std::filesystem::exists(dest));
  EXPECT_EQ(read_file(dest), private_key_pem);

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture,
       GeneratesMaterialsFromCertificateDetailOnly) {
  auto runtime_dir = harness_->runtime_dir();

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
  detail_data["cert"] = leaf_cert + chain_cert;
  detail_data["chain_pem"] = chain_cert;
  detail_data["private_key_pem"] = private_key_pem;

  boost::json::object payload;
  payload["detail"] = detail_data;

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

  auto fetch_override =
      [config](std::optional<std::int64_t> expected_version,
               const std::optional<std::string> &expected_hash)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    dto::DeviceInstallConfigDto copy = config;
    if (expected_version) {
      copy.version = *expected_version;
    }
    if (expected_hash) {
      copy.installs_hash = *expected_hash;
    }
    return monad::IO<dto::DeviceInstallConfigDto>::pure(copy);
  };

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        ASSERT_TRUE(result.is_ok());
        plan = result.value();
      });

  ASSERT_TRUE(plan);

  bool apply_ok = false;
  monad::Error apply_err{};
  harness_->install_manager()
      .apply_copy_actions(*plan, std::nullopt, std::nullopt)
      .run([&](auto result) {
        apply_ok = result.is_ok();
        if (!apply_ok) {
          apply_err = result.error();
        }
      });

  ASSERT_TRUE(apply_ok) << "apply_copy_actions failed: " << apply_err.what;

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

TEST_F(InstallConfigManagerFixture, RetriesUntilExpectedVersionAvailable) {
  auto runtime_dir = harness_->runtime_dir();

  dto::DeviceInstallConfigDto config{};
  config.id = 5;
  config.user_device_id = 55;
  config.version = 17;

  int call_count = 0;
  auto fetch_override =
      [&config, &call_count](std::optional<std::int64_t> expected_version,
                             const std::optional<std::string> &expected_hash)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    dto::DeviceInstallConfigDto copy = config;
    ++call_count;
    if (expected_version) {
      copy.version =
          (call_count < 3) ? (*expected_version - 1) : *expected_version;
    }
    if (expected_hash) {
      copy.installs_hash = *expected_hash;
    }
    return monad::IO<dto::DeviceInstallConfigDto>::pure(copy);
  };

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  harness_->install_manager()
      .ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        ASSERT_TRUE(result.is_ok());
        plan = result.value();
      });

  ASSERT_TRUE(plan);
  EXPECT_EQ(call_count, 3);
  ASSERT_TRUE(harness_->install_manager().local_version());
  EXPECT_EQ(*harness_->install_manager().local_version(), config.version);

  std::filesystem::remove_all(runtime_dir);
}

TEST_F(InstallConfigManagerFixture, FailsWhenExpectedVersionNeverArrives) {
  misc::ThreadNotifier notifier(3000);
  auto runtime_dir = harness_->runtime_dir();

  dto::DeviceInstallConfigDto config{};
  config.id = 6;
  config.user_device_id = 66;
  config.version = 23;

  int call_count = 0;
  auto fetch_override =
      [&config, &call_count](std::optional<std::int64_t> expected_version,
                             const std::optional<std::string> &expected_hash)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    dto::DeviceInstallConfigDto copy = config;
    ++call_count;
    if (expected_version) {
      copy.version = *expected_version - 1;
    }
    if (expected_hash) {
      copy.installs_hash = *expected_hash;
    }
    return monad::IO<dto::DeviceInstallConfigDto>::pure(copy);
  };

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
  EXPECT_GE(call_count, 4);

  std::filesystem::remove_all(runtime_dir);
}
