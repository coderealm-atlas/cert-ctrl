#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "backoff_utils.hpp"
#include "client_ssl_ctx.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/session_refresher.hpp"
#include "http_client_config_provider.hpp"
#include "http_client_manager.hpp"
#include "ioc_manager_config_provider.hpp"
#include "io_context_manager.hpp"
#include "log_stream.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "state/device_state_store.hpp"
#include "test_config_utils.hpp"

namespace fs = std::filesystem;

class InMemoryDeviceStateStore : public certctrl::IDeviceStateStore {
 public:
  std::optional<std::string> get_access_token() const override {
    return access_token_;
  }

  std::optional<std::string> get_refresh_token() const override {
    return refresh_token_;
  }

  std::optional<std::string> save_tokens(
      const std::optional<std::string> &access_token,
      const std::optional<std::string> &refresh_token,
      std::optional<int> expires_in = std::nullopt) override {
    access_token_ = access_token;
    refresh_token_ = refresh_token;
    expires_in_ = expires_in;
    return std::nullopt;
  }

  std::optional<std::string> clear_tokens() override {
    access_token_.reset();
    refresh_token_.reset();
    expires_in_.reset();
    return std::nullopt;
  }

  std::optional<std::string> get_device_public_id() const override {
    return device_public_id_;
  }

  std::optional<std::string> get_device_fingerprint_hex() const override {
    return device_fingerprint_;
  }

  std::optional<std::string> save_device_identity(
      const std::optional<std::string> &device_public_id,
      const std::optional<std::string> &fingerprint_hex) override {
    device_public_id_ = device_public_id;
    device_fingerprint_ = fingerprint_hex;
    return std::nullopt;
  }

  std::optional<std::string> clear_device_identity() override {
    device_public_id_.reset();
    device_fingerprint_.reset();
    return std::nullopt;
  }

  std::optional<std::string> get_install_config_json() const override {
    return install_config_json_;
  }

  std::optional<std::int64_t> get_install_config_version() const override {
    return install_config_version_;
  }

  std::optional<std::string> save_install_config(
      const std::optional<std::string> &serialized_json,
      std::optional<std::int64_t> version) override {
    install_config_json_ = serialized_json;
    install_config_version_ = version;
    return std::nullopt;
  }

  std::optional<std::string> clear_install_config() override {
    install_config_json_.reset();
    install_config_version_.reset();
    return std::nullopt;
  }

  std::optional<std::string> get_updates_cursor() const override {
    return updates_cursor_;
  }

  std::optional<std::string> save_updates_cursor(
      const std::optional<std::string> &cursor) override {
    updates_cursor_ = cursor;
    return std::nullopt;
  }

  std::optional<std::string> get_processed_signals_json() const override {
    return processed_signals_;
  }

  std::optional<std::string> save_processed_signals_json(
      const std::optional<std::string> &serialized_json) override {
    processed_signals_ = serialized_json;
    return std::nullopt;
  }

  std::optional<std::string> get_imported_ca_name(
      std::int64_t ca_id) const override {
    if (auto it = imported_ca_names_.find(ca_id);
        it != imported_ca_names_.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  std::optional<std::string> set_imported_ca_name(
      std::int64_t ca_id,
      const std::optional<std::string> &canonical_name) override {
    imported_ca_names_[ca_id] = canonical_name;
    return std::nullopt;
  }

  std::optional<std::string> clear_imported_ca_name(
      std::int64_t ca_id) override {
    imported_ca_names_.erase(ca_id);
    return std::nullopt;
  }

  bool available() const override { return true; }

 private:
  std::optional<std::string> access_token_;
  std::optional<std::string> refresh_token_;
  std::optional<int> expires_in_;
  std::optional<std::string> device_public_id_;
  std::optional<std::string> device_fingerprint_;
  std::optional<std::string> install_config_json_;
  std::optional<std::int64_t> install_config_version_;
  std::optional<std::string> updates_cursor_;
  std::optional<std::string> processed_signals_;
  std::unordered_map<std::int64_t, std::optional<std::string>>
      imported_ca_names_;
};

class SessionRefresherTest : public ::testing::Test {
 protected:
  void SetUp() override {
    config_dir_ = testinfra::make_temp_dir("session-refresher-config");
    runtime_dir_ = testinfra::make_temp_dir("session-refresher-runtime");

    testinfra::ConfigFileOptions opts;
    opts.runtime_dir = runtime_dir_;
    opts.base_url = "https://api.unit.test";
    opts.http_threads = 1;
    opts.ioc_threads = 1;
    testinfra::write_basic_config_files(config_dir_, opts);

    config_sources_holder_ =
        testinfra::make_config_sources({config_dir_}, {});
    app_properties_ = std::make_unique<cjj365::AppProperties>(
        *config_sources_holder_);

    output_backend_ = std::make_unique<customio::ConsoleOutputWithColor>(5);
    console_output_ =
        std::make_unique<customio::ConsoleOutput>(*output_backend_);

    http_config_provider_ = std::make_unique<cjj365::HttpclientConfigProviderFile>(
        *app_properties_, *config_sources_holder_);
    ioc_config_provider_ =
        std::make_unique<cjj365::IocConfigProviderFile>(*app_properties_,
                                                        *config_sources_holder_);
    cert_config_provider_ =
        std::make_unique<certctrl::CertctrlConfigProviderFile>(
            *app_properties_, *config_sources_holder_, *output_backend_);

    ssl_context_ =
        std::make_unique<cjj365::ClientSSLContext>(*http_config_provider_);
    io_context_manager_ = std::make_unique<cjj365::IoContextManager>(
        *ioc_config_provider_, *output_backend_);
    http_client_manager_ =
        std::make_unique<client_async::HttpClientManager>(
            *ssl_context_, *http_config_provider_);

    state_store_ = std::make_unique<InMemoryDeviceStateStore>();
    state_store_->save_tokens(std::optional<std::string>{"initial-access"},
                  std::optional<std::string>{"initial-refresh"});
    WriteRefreshTokenFile("initial-refresh");
  }

  void TearDown() override {
    if (http_client_manager_) {
      http_client_manager_->stop();
    }
    if (io_context_manager_) {
      io_context_manager_->stop();
    }

    state_store_.reset();
    http_client_manager_.reset();
    io_context_manager_.reset();
    ssl_context_.reset();
    cert_config_provider_.reset();
    ioc_config_provider_.reset();
    http_config_provider_.reset();
    console_output_.reset();
    output_backend_.reset();
    app_properties_.reset();
    config_sources_holder_.reset();
    cjj365::ConfigSources::instance_count.store(0);

    std::error_code ec;
    fs::remove_all(config_dir_, ec);
    fs::remove_all(runtime_dir_, ec);
  }

  std::shared_ptr<certctrl::SessionRefresher> MakeRefresher(
      std::optional<monad::ExponentialBackoffOptions> options = std::nullopt,
      certctrl::SessionRefresher::RequestOverride request_override = {},
      certctrl::SessionRefresher::DelayObserver delay_observer = {}) {
    return std::make_shared<certctrl::SessionRefresher>(
        *io_context_manager_, *cert_config_provider_, *console_output_,
        *http_client_manager_, *state_store_, std::move(options),
        std::move(request_override), std::move(delay_observer));
  }

  monad::Result<void, monad::Error> RunRefresh(
      certctrl::SessionRefresher &refresher, const std::string &reason) {
    std::promise<monad::Result<void, monad::Error>> promise;
    auto future = promise.get_future();
    refresher.refresh(reason).run([
      &promise
    ](monad::Result<void, monad::Error> result) mutable {
      promise.set_value(std::move(result));
    });
    return future.get();
  }

  void WriteRefreshTokenFile(const std::string &token) {
    auto state_dir = runtime_dir_ / "state";
    fs::create_directories(state_dir);
    std::ofstream ofs(state_dir / "refresh_token.txt",
                      std::ios::binary | std::ios::trunc);
    ofs << token;
  }

  fs::path config_dir_;
  fs::path runtime_dir_;
  std::unique_ptr<cjj365::ConfigSources> config_sources_holder_;
  std::unique_ptr<cjj365::AppProperties> app_properties_;
  std::unique_ptr<customio::ConsoleOutputWithColor> output_backend_;
  std::unique_ptr<customio::ConsoleOutput> console_output_;
  std::unique_ptr<cjj365::HttpclientConfigProviderFile> http_config_provider_;
  std::unique_ptr<cjj365::IocConfigProviderFile> ioc_config_provider_;
  std::unique_ptr<certctrl::CertctrlConfigProviderFile> cert_config_provider_;
  std::unique_ptr<cjj365::ClientSSLContext> ssl_context_;
  std::unique_ptr<cjj365::IoContextManager> io_context_manager_;
  std::unique_ptr<client_async::HttpClientManager> http_client_manager_;
  std::unique_ptr<InMemoryDeviceStateStore> state_store_;
};

TEST_F(SessionRefresherTest, RetriesWithExponentialBackoff) {
  monad::ExponentialBackoffOptions options;
  options.initial_delay = std::chrono::milliseconds(5);
  options.max_delay = std::chrono::milliseconds(20);
  options.jitter = std::chrono::milliseconds::zero();

  std::vector<std::chrono::milliseconds> observed_delays;
  int call_count = 0;
  auto request_override = [&call_count](const std::string &, int) mutable {
    ++call_count;
    if (call_count < 3) {
      auto err = monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                                   "transient failure");
      err.response_status = 503;
      return monad::IO<void>::fail(std::move(err));
    }
    return monad::IO<void>::pure();
  };
  auto delay_observer = [&observed_delays](std::chrono::milliseconds wait,
                                           int) {
    observed_delays.push_back(wait);
  };

  auto refresher = MakeRefresher(options, request_override, delay_observer);
  auto result = RunRefresh(*refresher, "retry-sequence");

  ASSERT_TRUE(result.is_ok());
  ASSERT_EQ(observed_delays.size(), 2u);
  EXPECT_EQ(observed_delays[0], options.initial_delay);
  EXPECT_EQ(observed_delays[1], std::chrono::milliseconds(10));
}

TEST_F(SessionRefresherTest, BackoffResetsBetweenRefreshes) {
  monad::ExponentialBackoffOptions options;
  options.initial_delay = std::chrono::milliseconds(5);
  options.max_delay = std::chrono::milliseconds(20);
  options.jitter = std::chrono::milliseconds::zero();

  std::vector<std::chrono::milliseconds> observed_delays;
  std::array<int, 2> failures{{1, 1}};
  std::array<int, 2> attempts{{0, 0}};
  std::atomic<int> phase{0};

  auto request_override = [&failures, &attempts, &phase](const std::string &,
                                                        int) mutable {
    int idx = phase.load();
    ++attempts[idx];
    if (attempts[idx] <= failures[idx]) {
      auto err = monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                                   "transient failure");
      err.response_status = 503;
      return monad::IO<void>::fail(std::move(err));
    }
    return monad::IO<void>::pure();
  };

  auto delay_observer = [&observed_delays](std::chrono::milliseconds wait,
                                           int) {
    observed_delays.push_back(wait);
  };

  auto refresher = MakeRefresher(options, request_override, delay_observer);

  auto first = RunRefresh(*refresher, "first");
  ASSERT_TRUE(first.is_ok());
  ASSERT_EQ(observed_delays.size(), 1u);
  EXPECT_EQ(observed_delays.front(), options.initial_delay);

  phase.store(1);
  attempts[1] = 0;
  auto second = RunRefresh(*refresher, "second");
  ASSERT_TRUE(second.is_ok());
  ASSERT_EQ(observed_delays.size(), 2u);
  EXPECT_EQ(observed_delays.back(), options.initial_delay);
}

TEST_F(SessionRefresherTest, StopsRetryingOnRotationError) {
  std::vector<std::chrono::milliseconds> observed_delays;
  auto request_override = [](const std::string &, int) {
    auto err = monad::make_error(my_errors::GENERAL::UNAUTHORIZED,
                                 "refresh token rotated");
    err.key = "refresh_token_rotated";
    return monad::IO<void>::fail(std::move(err));
  };
  auto delay_observer = [&observed_delays](std::chrono::milliseconds wait,
                                           int) {
    observed_delays.push_back(wait);
  };

  auto refresher = MakeRefresher(std::nullopt, request_override, delay_observer);
  auto result = RunRefresh(*refresher, "rotation");

  ASSERT_TRUE(result.is_err());
  EXPECT_EQ(result.error().key, std::string("refresh_token_rotated"));
  EXPECT_TRUE(observed_delays.empty());
}
