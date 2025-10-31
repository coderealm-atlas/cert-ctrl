#include <gtest/gtest.h>

#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/function_adapters.hpp"
#include "conf/certctrl_config.hpp"
#include "result_monad.hpp"
#include <boost/json.hpp>

#include <sstream>
#include <cstdlib>
#include <filesystem>
#include <chrono>
#include <system_error>
#include <fstream>
#include <mutex>
#include <string>
#include <optional>
#include <unordered_map>

using namespace certctrl::install_actions;

namespace {

using certctrl::install_actions::FunctionExecEnvironmentResolver;
using certctrl::install_actions::FunctionResourceMaterializer;
using certctrl::install_actions::IExecEnvironmentResolver;
using certctrl::install_actions::IResourceMaterializer;

IResourceMaterializer::Ptr make_default_materializer() {
  return std::make_shared<FunctionResourceMaterializer>(
      [](const dto::InstallItem &)
          -> monad::IO<void> { return monad::IO<void>::pure(); });
}

IExecEnvironmentResolver::Ptr make_env_resolver(
    std::function<std::optional<std::unordered_map<std::string, std::string>>(
        const dto::InstallItem &)> fn) {
  return std::make_shared<FunctionExecEnvironmentResolver>(std::move(fn));
}

struct TestConfigProvider : certctrl::ICertctrlConfigProvider {
  explicit TestConfigProvider(std::filesystem::path runtime_dir) {
    config.runtime_dir = std::move(runtime_dir);
  }

  const certctrl::CertctrlConfig &get() const override { return config; }
  certctrl::CertctrlConfig &get() override { return config; }

  monad::MyVoidResult save(const boost::json::object &) override {
    return monad::MyVoidResult::Ok();
  }

  certctrl::CertctrlConfig config;
};

struct HandlerContext {
  std::shared_ptr<TestConfigProvider> provider;
  std::shared_ptr<ExecActionHandler> handler;
};

HandlerContext make_handler(
    customio::ConsoleOutput &cout,
    const std::filesystem::path &runtime_dir =
        std::filesystem::current_path(),
    IResourceMaterializer::Factory materializer_factory = {},
    IExecEnvironmentResolver::Factory resolver_factory = {}) {
  if (!materializer_factory) {
    materializer_factory = []() {
      return make_default_materializer();
    };
  }
  if (!resolver_factory) {
    resolver_factory = []() { return IExecEnvironmentResolver::Ptr{}; };
  }

  auto provider = std::make_shared<TestConfigProvider>(runtime_dir);
  auto handler = std::make_shared<ExecActionHandler>(
      *provider, cout, materializer_factory, resolver_factory);
  handler->customize(runtime_dir, materializer_factory, resolver_factory);
  return HandlerContext{std::move(provider), std::move(handler)};
}

} // namespace

// Minimal test IOutput implementation that captures output into strings
class TestOutput : public customio::IOutput {
public:
  std::stringstream out;
  std::stringstream err;

  customio::LogStream trace() override {
    return customio::LogStream::make_disabled();
  }
  customio::LogStream debug() override {
    return customio::LogStream::make_enabled(out, "[debug]: ", mutex_);
  }
  customio::LogStream info() override {
    return customio::LogStream::make_enabled(out, "[info]: ", mutex_);
  }
  customio::LogStream warning() override {
    return customio::LogStream::make_enabled(err, "[warning]: ", mutex_);
  }
  customio::LogStream error() override {
    return customio::LogStream::make_enabled(err, "[error]: ", mutex_);
  }

  std::ostream &stream() override { return out; }
  std::ostream &err_stream() override { return err; }
  std::size_t verbosity() const override { return 5; }

private:
  std::mutex mutex_;
};

TEST(ExecActionTest, RunsShellCmdAndCapturesSuccess) {
  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t1";
  it.type = "exec";
  it.cmd =
#ifndef _WIN32
  "/bin/echo hello-from-test";
#else
  "echo hello-from-test";
#endif
  it.timeout_ms = 2000;
  cfg.installs.push_back(it);

  auto ctx = make_handler(cout);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, TimesOutOnLongSleep) {
  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t2";
  it.type = "exec";
  it.cmd =
#ifndef _WIN32
  "/bin/sleep 5";
#else
  "ping -n 6 127.0.0.1 >nul";
#endif
  it.timeout_ms = 1000; // 1s
  cfg.installs.push_back(it);

  auto ctx = make_handler(cout);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    EXPECT_FALSE(result.is_ok());
  });
}

#ifndef _WIN32
TEST(ExecActionTest, ZeroTimeoutFallsBackToDefault) {
  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t-timeout-zero";
  it.type = "exec";
  it.cmd = "sleep 1";
  it.timeout_ms = 0;
  cfg.installs.push_back(it);

  auto ctx = make_handler(cout);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}
#endif

TEST(ExecActionTest, RunsCmdArgvDirectly) {
  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t3";
  it.type = "exec";
  // prefer cmd_argv for direct execution (no shell)
#ifndef _WIN32
  it.cmd_argv = std::vector<std::string>{"/bin/echo", "argv-echo-test"};
#else
  // On Windows cmd_argv should execute via CreateProcess; use simple cmd.exe /C echo
  it.cmd_argv = std::vector<std::string>{"cmd.exe", "/C", "echo argv-echo-test"};
#endif
  it.timeout_ms = 2000;
  cfg.installs.push_back(it);

  auto ctx = make_handler(cout);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

#ifndef _WIN32
TEST(ExecActionTest, SuppliesAdditionalEnvironmentFromContext) {
  constexpr const char *kExpectedSecret = "SecretPass123";

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  auto resolver = make_env_resolver(
      [expected = std::string(kExpectedSecret)](
          const dto::InstallItem &)
      -> std::optional<std::unordered_map<std::string, std::string>> {
        std::unordered_map<std::string, std::string> env;
        env.emplace("CERTCTRL_PFX_PASSWORD", expected);
        return env;
      });

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t-env";
  it.type = "exec";
  it.cmd_argv = std::vector<std::string>{
      "/bin/sh", "-c",
      std::string("if [ \"$CERTCTRL_PFX_PASSWORD\" = \"") + kExpectedSecret +
          "\" ]; then exit 0; else exit 9; fi"};
  it.timeout_ms = 2000;
  cfg.installs.push_back(it);

  auto materializer_factory = [materializer = make_default_materializer()]() {
    return materializer;
  };
  auto resolver_factory = [resolver]() { return resolver; };
  auto ctx = make_handler(cout, std::filesystem::current_path(),
                          materializer_factory, resolver_factory);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    ASSERT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, MergesItemEnvWithContextEnv) {
  constexpr const char *kExpectedSecret = "SecretPass123";

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  auto resolver = make_env_resolver(
      [expected = std::string(kExpectedSecret)](
          const dto::InstallItem &)
      -> std::optional<std::unordered_map<std::string, std::string>> {
        std::unordered_map<std::string, std::string> env;
        env.emplace("CERTCTRL_PFX_PASSWORD", expected);
        return env;
      });

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t-env-merge";
  it.type = "exec";
  it.env = std::unordered_map<std::string, std::string>{{"KEEP", "yes"}};
  it.cmd_argv = std::vector<std::string>{
      "/bin/sh", "-c",
      "if [ \"$KEEP\" = \"yes\" ] && [ -n \"$CERTCTRL_PFX_PASSWORD\" ]; then exit 0; else exit 7; fi"};
  it.timeout_ms = 2000;
  cfg.installs.push_back(it);

  auto materializer_factory = [materializer = make_default_materializer()]() {
    return materializer;
  };
  auto resolver_factory = [resolver]() { return resolver; };
  auto ctx = make_handler(cout, std::filesystem::current_path(),
                          materializer_factory, resolver_factory);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    ASSERT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, RunsMultipleCommandsFromSingleShellLine) {
  namespace fs = std::filesystem;

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  const auto temp_dir = fs::temp_directory_path() /
      ("certctrl_exec_multi_cmd_test_" +
       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  struct DirCleanup {
    fs::path path;
    ~DirCleanup() {
      std::error_code ec;
      fs::remove_all(path, ec);
    }
  } cleanup{temp_dir};
  fs::create_directories(temp_dir);
  const auto test_file = temp_dir / "testfile";

  {
    std::ofstream ofs(test_file);
    ofs << "placeholder";
  }
  fs::permissions(test_file,
                  fs::perms::owner_read | fs::perms::owner_write |
                      fs::perms::group_read | fs::perms::others_read,
                  fs::perm_options::replace);

  const std::string file_path = test_file.string();

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t-multi-cmd";
  it.type = "exec";
  // Run two shell commands in one line to ensure chaining works: overwrite the file then chmod it.
  it.cmd = std::string("printf 'updated' > '") + file_path + "';chmod 640 '" + file_path + "'";
  it.timeout_ms = 2000;
  cfg.installs.push_back(it);

  auto ctx = make_handler(cout, temp_dir);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    ASSERT_TRUE(result.is_ok());
  });

  {
    std::ifstream verify_in(test_file);
    std::string contents;
    std::getline(verify_in, contents);
    EXPECT_EQ(contents, "updated");
  }

  const auto perms = fs::status(test_file).permissions() & fs::perms::mask;
  const auto expected =
      fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read;
  EXPECT_EQ(perms, expected);
}
#endif

#ifdef _WIN32
namespace {

bool command_exists(const std::string &exe_name) {
  std::string check_cmd = "where " + exe_name + " >nul 2>&1";
  int rc = std::system(check_cmd.c_str());
  return rc == 0;
}

}

TEST(ExecActionTest, WindowsShellCmdRunsUnderCmdExe) {
  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t4";
  it.type = "exec";
  // cmd form on Windows uses the platform shell (cmd.exe /C)
  it.cmd = std::string("echo hello-windows-test");
  it.timeout_ms = 2000;
  cfg.installs.push_back(it);

  auto ctx = make_handler(cout);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, WindowsPwshCmdArgvRunsWhenAvailable) {
  if (!command_exists("pwsh")) {
    GTEST_SKIP() << "pwsh not available on PATH";
  }

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t5";
  it.type = "exec";
  it.cmd_argv = std::vector<std::string>{
      "pwsh", "-NoLogo", "-NoProfile", "-Command", "Write-Output pwsh-test"};
  it.timeout_ms = 5000;
  cfg.installs.push_back(it);

  auto ctx = make_handler(cout);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, WindowsPowerShellCmdArgvRunsWhenAvailable) {
  if (!command_exists("powershell")) {
    GTEST_SKIP() << "Windows PowerShell not available on PATH";
  }

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t6";
  it.type = "exec";
  it.cmd_argv = std::vector<std::string>{
      "powershell", "-NoLogo", "-NonInteractive", "-Command",
      "Write-Output powershell-test"};
  // Powershell.exe can take a few extra seconds to cold-start under load, so
  // give it a little more headroom than pwsh to keep this test stable.
  it.timeout_ms = 10000;
  cfg.installs.push_back(it);

  auto ctx = make_handler(cout);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, WindowsMergesItemEnvWithContextEnv) {
  constexpr const char *kExpectedSecret = "SecretPass123";

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  auto resolver = make_env_resolver(
      [expected = std::string(kExpectedSecret)](
          const dto::InstallItem &)
      -> std::optional<std::unordered_map<std::string, std::string>> {
        std::unordered_map<std::string, std::string> env;
        env.emplace("CERTCTRL_PFX_PASSWORD", expected);
        return env;
      });

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t-env-merge-win";
  it.type = "exec";
  it.env = std::unordered_map<std::string, std::string>{{"KEEP", "yes"}};
  it.cmd_argv = std::vector<std::string>{
      "cmd.exe", "/C",
      "if \"%KEEP%\"==\"yes\" (if not \"%CERTCTRL_PFX_PASSWORD%\"==\"\" exit 0 else exit 7) else exit 7"};
  it.timeout_ms = 4000;
  cfg.installs.push_back(it);

  auto materializer_factory = [materializer = make_default_materializer()]() {
    return materializer;
  };
  auto resolver_factory = [resolver]() { return resolver; };
  auto ctx = make_handler(cout, std::filesystem::current_path(),
                          materializer_factory, resolver_factory);
  ctx.handler->apply(cfg, std::nullopt).run([&](auto result) {
    ASSERT_TRUE(result.is_ok());
  });
}
#endif
