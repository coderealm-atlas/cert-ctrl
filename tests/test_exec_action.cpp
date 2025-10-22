#include <gtest/gtest.h>

#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/install_action_context.hpp"

#include <sstream>

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
  it.cmd = std::string("/bin/echo hello-from-test");
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
  it.cmd = std::string("/bin/sleep 5");
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

#ifdef _WIN32
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
#endif
