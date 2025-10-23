#include "handlers/install_actions/exec_action.hpp"

#include <chrono>
#include <cstring>
#include <thread>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <unordered_map>

#if !defined(_WIN32)
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#endif

#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace certctrl::install_actions {

#if defined(_WIN32)
#include <windows.h>

namespace {

static std::wstring utf8_to_wide(const std::string &input) {
  if (input.empty()) {
    return L"";
  }
  const int size_needed =
      MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
  if (size_needed <= 1) {
    return L"";
  }
  std::wstring result(static_cast<size_t>(size_needed - 1), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, result.data(), size_needed);
  return result;
}

static std::string wide_to_utf8(const std::wstring &input) {
  if (input.empty()) {
    return std::string();
  }
  const int size_needed =
      WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (size_needed <= 1) {
    return std::string();
  }
  std::string result(static_cast<size_t>(size_needed - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, result.data(), size_needed, nullptr, nullptr);
  return result;
}

static std::wstring quote_windows_arg(const std::wstring &arg) {
  if (arg.empty()) {
    return L"\"\"";
  }
  if (arg.find_first_of(L" \t\"") == std::wstring::npos) {
    return arg;
  }

  std::wstring result;
  result.reserve(arg.size() + 2);
  result.push_back(L'"');
  size_t backslashes = 0;
  for (wchar_t ch : arg) {
    if (ch == L'\\') {
      ++backslashes;
    } else if (ch == L'"') {
      result.append(backslashes * 2 + 1, L'\\');
      result.push_back(L'"');
      backslashes = 0;
    } else {
      if (backslashes > 0) {
        result.append(backslashes, L'\\');
        backslashes = 0;
      }
      result.push_back(ch);
    }
  }
  if (backslashes > 0) {
    result.append(backslashes * 2, L'\\');
  }
  result.push_back(L'"');
  return result;
}

static std::wstring join_command_line(const std::vector<std::string> &args) {
  std::wstring command_line;
  bool first = true;
  for (const auto &arg : args) {
    if (!first) {
      command_line.push_back(L' ');
    }
    first = false;
    command_line += quote_windows_arg(utf8_to_wide(arg));
  }
  return command_line;
}

static std::vector<wchar_t> build_environment_block(
    const std::optional<std::unordered_map<std::string, std::string>> &env) {
  std::vector<wchar_t> block;
  if (!env || env->empty()) {
    return block;
  }
  for (const auto &kv : *env) {
    std::string entry = kv.first + "=" + kv.second;
    std::wstring wentry = utf8_to_wide(entry);
    block.insert(block.end(), wentry.begin(), wentry.end());
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  return block;
}

static std::string format_last_error(DWORD error_code) {
  LPWSTR buffer = nullptr;
  const DWORD chars = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, error_code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
  if (chars == 0 || buffer == nullptr) {
    return std::string("Win32 error ") + std::to_string(error_code);
  }
  std::wstring message(buffer, chars);
  LocalFree(buffer);
  // Trim trailing newlines and carriage returns
  while (!message.empty() &&
         (message.back() == L'\r' || message.back() == L'\n')) {
    message.pop_back();
  }
  return wide_to_utf8(message);
}

} // namespace

static std::optional<std::string> run_item_cmd(const InstallActionContext &context,
                                               const dto::InstallItem &item) {
  (void)context;
  if ((!item.cmd || item.cmd->empty()) && (!item.cmd_argv || item.cmd_argv->empty())) {
    return std::nullopt;
  }

  std::vector<std::string> argv;
  if (item.cmd_argv && !item.cmd_argv->empty()) {
    argv = *item.cmd_argv;
  } else if (item.cmd && !item.cmd->empty()) {
    argv = {"cmd.exe", "/C", *item.cmd};
  }

  std::wstring command_line = join_command_line(argv);
  std::vector<wchar_t> cmd_buffer(command_line.begin(), command_line.end());
  cmd_buffer.push_back(L'\0');

  std::vector<wchar_t> env_block =
      build_environment_block(item.env); // double-null terminated or empty

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  BOOL created = CreateProcessW(
      nullptr, cmd_buffer.data(), nullptr, nullptr, FALSE, 0,
      env_block.empty() ? nullptr : env_block.data(), nullptr, &si, &pi);
  if (!created) {
    DWORD err = GetLastError();
    return std::optional<std::string>(
        std::string("CreateProcess failed: ") + format_last_error(err));
  }

  const DWORD timeout_ms =
      item.timeout_ms.value_or(static_cast<uint32_t>(30000));
  DWORD wait_result = WaitForSingleObject(pi.hProcess, timeout_ms);
  if (wait_result == WAIT_TIMEOUT) {
    TerminateProcess(pi.hProcess, 1u);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    return std::optional<std::string>("command timed out");
  }

  if (wait_result != WAIT_OBJECT_0) {
    DWORD err = GetLastError();
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return std::optional<std::string>(
        std::string("WaitForSingleObject failed: ") + format_last_error(err));
  }

  DWORD exit_code = 0;
  if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
    DWORD err = GetLastError();
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return std::optional<std::string>(
        std::string("GetExitCodeProcess failed: ") + format_last_error(err));
  }

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  if (exit_code != 0) {
    std::ostringstream oss;
    oss << "command exited with code " << exit_code;
    return std::optional<std::string>(oss.str());
  }

  return std::nullopt;
}

#else
// Helper: run a single InstallItem cmd/cmd_argv synchronously with timeout.
// Returns nullopt on success, or an error string on failure.
static std::optional<std::string> run_item_cmd(const InstallActionContext &ctx,
                                               const dto::InstallItem &item) {
  // Determine command form
  std::vector<std::string> argv;
  bool use_shell = false;
  std::string shell_cmd;
  if (item.cmd_argv && !item.cmd_argv->empty()) {
    // we'll exec directly using argv form
    argv = *item.cmd_argv;
  } else if (item.cmd && !item.cmd->empty()) {
    use_shell = true;
    shell_cmd = *item.cmd;
  } else {
    return std::nullopt; // nothing to run
  }

  // Prepare C args
  std::vector<char *> cargv;
  for (auto &s : argv) cargv.push_back(const_cast<char *>(s.c_str()));
  cargv.push_back(nullptr);

  pid_t pid = fork();
  if (pid < 0) {
    return std::optional<std::string>(std::string("fork failed: ") + std::strerror(errno));
  }

  if (pid == 0) {
    // child
    // Optionally switch user
    if (item.run_as && !item.run_as->empty()) {
      struct passwd *pw = getpwnam(item.run_as->c_str());
      if (pw) {
        // setgid then setuid
        if (setgid(pw->pw_gid) != 0) {
          _exit(127);
        }
        if (setuid(pw->pw_uid) != 0) {
          _exit(127);
        }
      } else {
        // unknown user: exit with distinctive code
        _exit(126);
      }
    }

    // Apply env overrides if provided
    if (item.env) {
      // Clear existing environment then set new variables
      ::clearenv();
      for (const auto &kv : *item.env) {
        ::setenv(kv.first.c_str(), kv.second.c_str(), 1);
      }
    }

    // Exec the command
    if (use_shell) {
      execlp("sh", "sh", "-c", shell_cmd.c_str(), (char *)NULL);
      _exit(127);
    }
    execvp(cargv[0], cargv.data());
    // If execvp returns, we have an error
    _exit(127);
  }

  // parent: wait with timeout
  int status = 0;
  auto start = std::chrono::steady_clock::now();
  const auto timeout = std::chrono::milliseconds(item.timeout_ms.value_or(30000));

  while (true) {
    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w == pid) {
      break;
    }
    if (w == -1) {
      return std::optional<std::string>(std::string("waitpid failed: ") + std::strerror(errno));
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    if (elapsed >= timeout) {
      // kill the process
      kill(pid, SIGKILL);
      // reap
      waitpid(pid, &status, 0);
      return std::optional<std::string>("command timed out");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  if (WIFEXITED(status)) {
    int rc = WEXITSTATUS(status);
    if (rc != 0) {
      std::ostringstream oss;
      oss << "command exited with code " << rc;
      return std::optional<std::string>(oss.str());
    }
    return std::nullopt;
  }
  if (WIFSIGNALED(status)) {
    std::ostringstream oss;
    oss << "command killed by signal " << WTERMSIG(status);
    return std::optional<std::string>(oss.str());
  }

  return std::optional<std::string>("unknown command result");
}
#endif

monad::IO<void> apply_exec_actions(
    const InstallActionContext &context,
    const dto::DeviceInstallConfigDto &config,
    std::optional<std::vector<std::string>> allowed_types) {
  using ReturnIO = monad::IO<void>;
  try {
    bool processed_any = false;
    for (const auto &item : config.installs) {
      // If allowed_types specified, skip items not matching
      if (allowed_types) {
        if (!item.ob_type) continue;
        bool matched = false;
        for (const auto &t : *allowed_types) {
          if (*item.ob_type == t) { matched = true; break; }
        }
        if (!matched) continue;
      }

      if ((!item.cmd || item.cmd->empty()) && (!item.cmd_argv || item.cmd_argv->empty())) {
        continue;
      }

      processed_any = true;

      // Ensure resources if referenced
      if (auto err = context.ensure_resource_materialized(item); err.has_value()) {
        if (item.continue_on_error) {
          context.output.logger().warning()
              << "exec item '" << item.id << "' resource materialize failed: " << err->what << std::endl;
          continue;
        }
        return ReturnIO::fail(std::move(*err));
      }

      if (auto err = run_item_cmd(context, item)) {
        if (item.continue_on_error) {
          context.output.logger().warning()
              << "exec item '" << item.id << "' failed: " << *err << std::endl;
          continue;
        }
        return ReturnIO::fail(monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT, *err));
      }

      context.output.logger().info()
          << "Executed exec item '" << item.id << "' successfully" << std::endl;
    }

    if (!processed_any) {
      context.output.logger().debug() << "No exec items present in plan" << std::endl;
    }

    return ReturnIO::pure();
  } catch (const std::exception &ex) {
    return ReturnIO::fail(monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT, ex.what()));
  }
}

} // namespace certctrl::install_actions
