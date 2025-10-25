#include <gtest/gtest.h>

#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/install_action_context.hpp"

#include <sstream>
#include <cstdlib>
#include <filesystem>
#include <mutex>

using namespace certctrl::install_actions;

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

  certctrl::install_actions::InstallActionContext ctx{
      std::filesystem::current_path(), cout,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      }};

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

  apply_exec_actions(ctx, cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, TimesOutOnLongSleep) {
  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  certctrl::install_actions::InstallActionContext ctx{
      std::filesystem::current_path(), cout,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      }};

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

  apply_exec_actions(ctx, cfg, std::nullopt).run([&](auto result) {
    EXPECT_FALSE(result.is_ok());
  });
}

TEST(ExecActionTest, RunsCmdArgvDirectly) {
  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  certctrl::install_actions::InstallActionContext ctx{
      std::filesystem::current_path(), cout,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      }};

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

  apply_exec_actions(ctx, cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

#ifndef _WIN32
TEST(ExecActionTest, SuppliesAdditionalEnvironmentFromContext) {
  constexpr const char *kExpectedSecret = "SecretPass123";

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  certctrl::install_actions::InstallActionContext ctx{
      std::filesystem::current_path(), cout,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      },
      [expected = std::string(kExpectedSecret)](
          const dto::InstallItem &)
          -> std::optional<std::unordered_map<std::string, std::string>> {
        std::unordered_map<std::string, std::string> env;
        env.emplace("CERTCTRL_PFX_PASSWORD", expected);
        return env;
      }};

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

  apply_exec_actions(ctx, cfg, std::nullopt).run([&](auto result) {
    ASSERT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, MergesItemEnvWithContextEnv) {
  constexpr const char *kExpectedSecret = "SecretPass123";

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  certctrl::install_actions::InstallActionContext ctx{
      std::filesystem::current_path(), cout,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      },
      [expected = std::string(kExpectedSecret)](
          const dto::InstallItem &)
          -> std::optional<std::unordered_map<std::string, std::string>> {
        std::unordered_map<std::string, std::string> env;
        env.emplace("CERTCTRL_PFX_PASSWORD", expected);
        return env;
      }};

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

  apply_exec_actions(ctx, cfg, std::nullopt).run([&](auto result) {
    ASSERT_TRUE(result.is_ok());
  });
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

  certctrl::install_actions::InstallActionContext ctx{
      std::filesystem::current_path(), cout,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      }};

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t4";
  it.type = "exec";
  // cmd form on Windows uses the platform shell (cmd.exe /C)
  it.cmd = std::string("echo hello-windows-test");
  it.timeout_ms = 2000;
  cfg.installs.push_back(it);

  apply_exec_actions(ctx, cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, WindowsPwshCmdArgvRunsWhenAvailable) {
  if (!command_exists("pwsh")) {
    GTEST_SKIP() << "pwsh not available on PATH";
  }

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  certctrl::install_actions::InstallActionContext ctx{
      std::filesystem::current_path(), cout,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      }};

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t5";
  it.type = "exec";
  it.cmd_argv = std::vector<std::string>{
      "pwsh", "-NoLogo", "-NoProfile", "-Command", "Write-Output pwsh-test"};
  it.timeout_ms = 5000;
  cfg.installs.push_back(it);

  apply_exec_actions(ctx, cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, WindowsPowerShellCmdArgvRunsWhenAvailable) {
  if (!command_exists("powershell")) {
    GTEST_SKIP() << "Windows PowerShell not available on PATH";
  }

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  certctrl::install_actions::InstallActionContext ctx{
      std::filesystem::current_path(), cout,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      }};

  dto::DeviceInstallConfigDto cfg;
  dto::InstallItem it;
  it.id = "t6";
  it.type = "exec";
  it.cmd_argv = std::vector<std::string>{
      "powershell", "-NoLogo", "-NonInteractive", "-Command",
      "Write-Output powershell-test"};
  it.timeout_ms = 5000;
  cfg.installs.push_back(it);

  apply_exec_actions(ctx, cfg, std::nullopt).run([&](auto result) {
    EXPECT_TRUE(result.is_ok());
  });
}

TEST(ExecActionTest, WindowsMergesItemEnvWithContextEnv) {
  constexpr const char *kExpectedSecret = "SecretPass123";

  TestOutput iout;
  customio::ConsoleOutput cout(iout);

  certctrl::install_actions::InstallActionContext ctx{
      std::filesystem::current_path(), cout,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      },
      [expected = std::string(kExpectedSecret)](
          const dto::InstallItem &)
          -> std::optional<std::unordered_map<std::string, std::string>> {
        std::unordered_map<std::string, std::string> env;
        env.emplace("CERTCTRL_PFX_PASSWORD", expected);
        return env;
      }};

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

  apply_exec_actions(ctx, cfg, std::nullopt).run([&](auto result) {
    ASSERT_TRUE(result.is_ok());
  });
}
#endif
