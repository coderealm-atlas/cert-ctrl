#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <string>

#include "handlers/info_handler_tokens.hpp"

namespace {
namespace fs = std::filesystem;

struct ScopedTempDir {
  fs::path path;
  ScopedTempDir() {
    auto base = fs::temp_directory_path() / "certctrl-info-tests";
    fs::create_directories(base);
    std::mt19937_64 gen{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    path = base / (std::string("info-") + std::to_string(dist(gen)));
    fs::create_directories(path);
  }
  ~ScopedTempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
};

class FakeStateStore : public certctrl::IDeviceStateStore {
public:
  std::optional<std::string> access_token;
  std::optional<std::string> refresh_token;

  std::optional<std::string> get_access_token() const override {
    return access_token;
  }
  std::optional<std::string> get_refresh_token() const override {
    return refresh_token;
  }
  std::optional<std::string>
  save_tokens(const std::optional<std::string> &access,
              const std::optional<std::string> &refresh,
              std::optional<int>) override {
    access_token = access;
    refresh_token = refresh;
    return std::nullopt;
  }
  std::optional<std::string> clear_tokens() override {
    access_token.reset();
    refresh_token.reset();
    return std::nullopt;
  }
  std::optional<std::string> get_device_public_id() const override {
    return std::nullopt;
  }
  std::optional<std::string> get_device_fingerprint_hex() const override {
    return std::nullopt;
  }
  std::optional<std::string>
  save_device_identity(const std::optional<std::string> &,
                       const std::optional<std::string> &) override {
    return std::nullopt;
  }
  std::optional<std::string> clear_device_identity() override {
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
  std::optional<std::string> save_websocket_resume_token(
      const std::optional<std::string> &) override {
    return std::nullopt;
  }
  std::optional<std::string> get_processed_signals_json() const override {
    return std::nullopt;
  }
  std::optional<std::string>
  save_processed_signals_json(const std::optional<std::string> &) override {
    return std::nullopt;
  }
  std::optional<std::string>
  get_imported_ca_name(std::int64_t) const override {
    return std::nullopt;
  }
  std::optional<std::string>
  set_imported_ca_name(std::int64_t,
                       const std::optional<std::string> &) override {
    return std::nullopt;
  }
  std::optional<std::string>
  clear_imported_ca_name(std::int64_t) override {
    return std::nullopt;
  }
  bool available() const override { return true; }

  std::pair<bool, std::optional<std::string>>
  try_acquire_refresh_lock(const std::string &owner,
                           std::chrono::milliseconds ttl) override {
    (void)owner;
    (void)ttl;
    return {true, std::nullopt};
  }

  std::optional<std::string>
  release_refresh_lock(const std::string &owner) override {
    (void)owner;
    return std::nullopt;
  }
};

TEST(InfoHandlerTokensTest, UsesStoreTokensWhenPresent) {
  FakeStateStore store;
  store.access_token = std::string("db-access");
  store.refresh_token = std::string("db-refresh");

  ScopedTempDir temp;
  auto snapshot =
      certctrl::load_session_tokens_from_state(temp.path, store);

  ASSERT_TRUE(snapshot.has_access());
  ASSERT_TRUE(snapshot.has_refresh());
  EXPECT_EQ(*snapshot.access_token, "db-access");
  EXPECT_EQ(*snapshot.refresh_token, "db-refresh");
}

TEST(InfoHandlerTokensTest, FallsBackToLegacyFilesWhenStoreMissing) {
  FakeStateStore store;
  ScopedTempDir temp;
  auto state_dir = temp.path / "state";
  fs::create_directories(state_dir);
  {
    std::ofstream ofs(state_dir / "access_token.txt");
    ofs << "  file-access  ";
  }
  {
    std::ofstream ofs(state_dir / "refresh_token.txt");
    ofs << "file-refresh\n";
  }

  auto snapshot =
      certctrl::load_session_tokens_from_state(temp.path, store);

  ASSERT_TRUE(snapshot.has_access());
  ASSERT_TRUE(snapshot.has_refresh());
  EXPECT_EQ(*snapshot.access_token, "file-access");
  EXPECT_EQ(*snapshot.refresh_token, "file-refresh");
}

} // namespace
