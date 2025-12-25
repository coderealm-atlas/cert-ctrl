#include <gtest/gtest.h>

#include <boost/json.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <sstream>
#include <string>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "log_stream.hpp"
#include "result_monad.hpp"

namespace {
namespace json = boost::json;
namespace fs = std::filesystem;
using certctrl::install_actions::ImportCaActionHandler;

class ScopedTempDir {
public:
  ScopedTempDir() {
    auto base = fs::temp_directory_path();
    std::mt19937_64 gen{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    path_ = base /
            ("certctrl-test-" + std::to_string(dist(gen)));
    fs::create_directories(path_);
  }

  ~ScopedTempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }

  const fs::path &path() const { return path_; }

private:
  fs::path path_;
};

class ScopedEnvVar {
public:
  ScopedEnvVar(std::string name, std::string value)
      : name_(std::move(name)) {
    const char *existing = std::getenv(name_.c_str());
    if (existing && *existing) {
      original_ = std::string(existing);
    }
#ifdef _WIN32
    _putenv_s(name_.c_str(), value.c_str());
#else
    ::setenv(name_.c_str(), value.c_str(), 1);
#endif
  }

  ~ScopedEnvVar() {
#ifdef _WIN32
    if (original_) {
      _putenv_s(name_.c_str(), original_->c_str());
    } else {
      _putenv_s(name_.c_str(), "");
    }
#else
    if (original_) {
      ::setenv(name_.c_str(), original_->c_str(), 1);
    } else {
      ::unsetenv(name_.c_str());
    }
#endif
  }

private:
  std::string name_;
  std::optional<std::string> original_;
};

class StaticConfigProvider : public certctrl::ICertctrlConfigProvider {
public:
  explicit StaticConfigProvider(fs::path runtime_dir) {
    config_.runtime_dir = std::move(runtime_dir);
  }

  const certctrl::CertctrlConfig &get() const override { return config_; }
  certctrl::CertctrlConfig &get() override { return config_; }

  monad::MyVoidResult save(const json::object &) override {
    return monad::MyVoidResult::Ok();
  }

  monad::MyVoidResult save_replace(const json::object &) override {
    return monad::MyVoidResult::Ok();
  }

private:
  certctrl::CertctrlConfig config_{};
};

void write_text_file(const fs::path &path, const std::string &content) {
  fs::create_directories(path.parent_path());
  std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
  ofs << content;
}

fs::path write_executable(const fs::path &dir, const std::string &name,
                          const std::string &content) {
  auto script = dir / name;
  fs::create_directories(script.parent_path());
  std::ofstream ofs(script, std::ios::binary | std::ios::trunc);
  ofs << content;
  ofs.close();
#ifndef _WIN32
  fs::permissions(script,
                  fs::perms::owner_read | fs::perms::owner_write |
                      fs::perms::owner_exec,
                  fs::perm_options::replace);
#endif
  return script;
}

std::shared_ptr<ImportCaActionHandler>
make_handler(certctrl::ICertctrlConfigProvider &provider,
             customio::ConsoleOutput &output) {
  certctrl::install_actions::IResourceMaterializer::Factory factory =
      []() -> certctrl::install_actions::IResourceMaterializer::Ptr {
    return nullptr;
  };
  return std::make_shared<ImportCaActionHandler>(provider, output, factory);
}
} // namespace

#if defined(__APPLE__)
TEST(ImportCaActionMac, DetectsDefaultTrustStore) {
  auto probe =
      certctrl::install_actions::detail::detect_mac_trust_store_for_test();
  ASSERT_TRUE(probe.has_value());

  const auto &result = probe.value();
  EXPECT_EQ(result.directory,
            fs::path("/Library/Caches/certctrl/trust-anchors"));
  EXPECT_TRUE(result.uses_native_import);
  EXPECT_TRUE(result.update_command.empty());
}
#else
TEST(ImportCaActionMac, DetectsDefaultTrustStore) {
  GTEST_SKIP() << "macOS-specific trust store detection";
}
#endif

#if !defined(_WIN32)
TEST(ImportCaActionRemove, PurgesFilesAndRunsUpdateCommand) {
  ScopedTempDir temp_root;
  StaticConfigProvider provider(temp_root.path());
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput output(logger);
  auto handler = make_handler(provider, output);

  auto trust_dir = temp_root.path() / "trust";
  fs::create_directories(trust_dir);
  ScopedEnvVar dir_env("CERTCTRL_CA_IMPORT_DIR", trust_dir.string());

  auto log_path = temp_root.path() / "update.log";
  std::ostringstream script;
  script << "#!/bin/sh\n"
         << "echo invoked >> \"" << log_path.string() << "\"\n"
         << "exit 0\n";
  auto update_script = write_executable(temp_root.path(), "update.sh",
                                        script.str());
  ScopedEnvVar cmd_env("CERTCTRL_CA_UPDATE_COMMAND",
                       update_script.string());

  auto stub_path = temp_root.path() / "stub-bin";
  write_executable(stub_path, "certutil", "#!/bin/sh\nexit 0\n");
  ScopedEnvVar path_env("PATH", stub_path.string());

  auto state_file = temp_root.path() / "state" / "import_ca" /
                    "ca-42.name";
  std::string canonical = "certctrl-ca-42-existing";
  write_text_file(state_file, canonical);

  auto ca_path = trust_dir / (canonical + ".crt");
  write_text_file(ca_path, "dummy");

  bool completed = false;
  handler->remove_ca(42, std::string("Ignored"))
      .run([&](auto result) {
        ASSERT_TRUE(result.is_ok()) << result.error().what;
        completed = true;
      });

  ASSERT_TRUE(completed);
  EXPECT_FALSE(fs::exists(ca_path));
  EXPECT_FALSE(fs::exists(state_file));
  EXPECT_TRUE(fs::exists(log_path));
}

TEST(ImportCaActionRemove, UsesSanitizedCanonicalNameWhenMissingState) {
  ScopedTempDir temp_root;
  StaticConfigProvider provider(temp_root.path());
  customio::ConsoleOutputWithColor logger(5);
  customio::ConsoleOutput output(logger);
  auto handler = make_handler(provider, output);

  auto trust_dir = temp_root.path() / "trust";
  fs::create_directories(trust_dir);
  ScopedEnvVar dir_env("CERTCTRL_CA_IMPORT_DIR", trust_dir.string());

  auto stub_path = temp_root.path() / "stub-bin";
  write_executable(stub_path, "certutil", "#!/bin/sh\nexit 0\n");
  ScopedEnvVar path_env("PATH", stub_path.string());

  ScopedEnvVar cmd_env("CERTCTRL_CA_UPDATE_COMMAND", ":");

  auto base_path = trust_dir / "certctrl-ca-99.crt";
  auto sanitized_path = trust_dir / "certctrl-ca-99-rootone.crt";
  write_text_file(base_path, "preserve");
  write_text_file(sanitized_path, "remove");

  bool completed = false;
  handler->remove_ca(99, std::string("RootOne"))
      .run([&](auto result) {
        ASSERT_TRUE(result.is_ok()) << result.error().what;
        completed = true;
      });

  ASSERT_TRUE(completed);
  EXPECT_TRUE(fs::exists(base_path));
  EXPECT_FALSE(fs::exists(sanitized_path));
  auto state_file = temp_root.path() / "state" / "import_ca" /
                    "ca-99.name";
  EXPECT_FALSE(fs::exists(state_file));
}
#else
TEST(ImportCaActionRemove, PurgesFilesAndRunsUpdateCommand) {
  GTEST_SKIP() << "POSIX-only test";
}

TEST(ImportCaActionRemove, UsesSanitizedCanonicalNameWhenMissingState) {
  GTEST_SKIP() << "POSIX-only test";
}
#endif
