#include "handlers/install_actions/exec_action.hpp"

#include "util/my_logging.hpp"
#include <boost/algorithm/string/join.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <memory>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <crt_externs.h>
#endif
#endif

#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace certctrl::install_actions {

ExecActionHandler::ExecActionHandler(
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    IResourceMaterializer::Factory resource_materializer_factory,
    IExecEnvironmentResolver::Factory exec_env_resolver_factory)
    : config_provider_(config_provider), output_(output),
      runtime_dir_(config_provider.get().runtime_dir),
      resource_materializer_factory_(std::move(resource_materializer_factory)),
      exec_env_resolver_factory_(std::move(exec_env_resolver_factory)) {}

void ExecActionHandler::customize(
    std::filesystem::path runtime_dir,
    IResourceMaterializer::Factory resource_materializer_factory,
    IExecEnvironmentResolver::Factory exec_env_resolver_factory) {
      is_customized_ = true;
  runtime_dir_ = runtime_dir;
  if (resource_materializer_factory) {
    resource_materializer_factory_ = std::move(resource_materializer_factory);
  }
  if (exec_env_resolver_factory) {
    exec_env_resolver_factory_ = std::move(exec_env_resolver_factory);
  }
}

// IResourceMaterializer::Ptr
// ExecActionHandler::make_resource_materializer() const {
//   if (resource_materializer_factory_) {
//     return resource_materializer_factory_();
//   }
//   return nullptr;
// }

// IExecEnvironmentResolver::Ptr
// ExecActionHandler::make_exec_env_resolver() const {
//   if (exec_env_resolver_factory_) {
//     return exec_env_resolver_factory_();
//   }
//   return nullptr;
// }

#if defined(_WIN32)
#include <windows.h>

namespace {

static std::unordered_map<std::string, std::string>
resolve_exec_environment(const IExecEnvironmentResolver::Ptr &resolver,
                         const dto::InstallItem &item) {
  if (!resolver) {
    return {};
  }
  if (auto result = resolver->resolve(item)) {
    return std::move(*result);
  }
  return {};
}

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
  MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, result.data(),
                      size_needed);
  return result;
}

static std::string wide_to_utf8(const std::wstring &input) {
  if (input.empty()) {
    return std::string();
  }
  const int size_needed = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1,
                                              nullptr, 0, nullptr, nullptr);
  if (size_needed <= 1) {
    return std::string();
  }
  std::string result(static_cast<size_t>(size_needed - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, result.data(), size_needed,
                      nullptr, nullptr);
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
    const std::optional<std::unordered_map<std::string, std::string>> &env,
    const std::unordered_map<std::string, std::string> &extra_env) {
  if (!env && extra_env.empty()) {
    return {};
  }

  std::vector<std::pair<std::wstring, std::wstring>> merged;
  merged.reserve((env ? env->size() : 0) + extra_env.size());

  auto merge_in = [&merged](const std::wstring &key,
                            const std::wstring &value) {
    for (auto &entry : merged) {
      if (entry.first == key) {
        entry.second = value;
        return;
      }
    }
    merged.emplace_back(key, value);
  };

  if (env) {
    for (const auto &kv : *env) {
      merge_in(utf8_to_wide(kv.first), utf8_to_wide(kv.second));
    }
  } else {
    LPWCH env_strings = GetEnvironmentStringsW();
    if (env_strings != nullptr) {
      for (LPWCH current = env_strings; *current != L'\0';
           current += std::wcslen(current) + 1) {
        std::wstring entry(current);
        if (entry.empty()) {
          continue;
        }
        auto pos = entry.find(L'=');
        if (pos == std::wstring::npos) {
          continue;
        }
        std::wstring key = entry.substr(0, pos);
        std::wstring value = entry.substr(pos + 1);
        merge_in(key, value);
      }
      FreeEnvironmentStringsW(env_strings);
    }
  }

  for (const auto &kv : extra_env) {
    merge_in(utf8_to_wide(kv.first), utf8_to_wide(kv.second));
  }

  std::vector<wchar_t> block;
  for (const auto &kv : merged) {
    std::wstring entry = kv.first;
    entry.push_back(L'=');
    entry += kv.second;
    block.insert(block.end(), entry.begin(), entry.end());
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

static std::optional<std::string>
run_item_cmd(const dto::InstallItem &item,
             const IExecEnvironmentResolver::Ptr &resolver) {
  if ((!item.cmd || item.cmd->empty()) &&
      (!item.cmd_argv || item.cmd_argv->empty())) {
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

  std::unordered_map<std::string, std::string> extra_env =
      resolve_exec_environment(resolver, item);

  std::vector<wchar_t> env_block = build_environment_block(
      item.env, extra_env); // double-null terminated or empty

  DWORD creation_flags = 0;
  if (!env_block.empty()) {
    creation_flags |= CREATE_UNICODE_ENVIRONMENT;
  }

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  BOOL created = CreateProcessW(
      nullptr, cmd_buffer.data(), nullptr, nullptr, FALSE, creation_flags,
      env_block.empty() ? nullptr : env_block.data(), nullptr, &si, &pi);
  if (!created) {
    DWORD err = GetLastError();
    return std::optional<std::string>(std::string("CreateProcess failed: ") +
                                      format_last_error(err));
  }

  const DWORD timeout_ms = (item.timeout_ms && *item.timeout_ms > 0)
                               ? *item.timeout_ms
                               : static_cast<uint32_t>(30000);
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
static std::unordered_map<std::string, std::string>
resolve_exec_environment(const IExecEnvironmentResolver::Ptr &resolver,
                         const dto::InstallItem &item) {
  if (!resolver) {
    return {};
  }
  if (auto result = resolver->resolve(item)) {
    return std::move(*result);
  }
  return {};
}

static std::optional<std::string>
run_item_cmd(const dto::InstallItem &item,
             const IExecEnvironmentResolver::Ptr &resolver) {
  // Determine command form
  std::vector<std::string> argv;
  bool use_shell = false;
  std::string shell_cmd;
  if (item.cmd_argv && !item.cmd_argv->empty()) {
    // we'll exec directly using argv form
    argv = *item.cmd_argv;
    BOOST_LOG_SEV(app_logger(), boost::log::trivial::info)
        << "Executing command argv: " << boost::algorithm::join(argv, " ");
  } else if (item.cmd && !item.cmd->empty()) {
    use_shell = true;
    shell_cmd = *item.cmd;
    BOOST_LOG_SEV(app_logger(), boost::log::trivial::info)
        << "Executing shell command: " << shell_cmd;
  } else {
    return std::nullopt; // nothing to run
  }

  std::unordered_map<std::string, std::string> extra_env =
      resolve_exec_environment(resolver, item);

  // Prepare C args
  std::vector<char *> cargv;
  for (auto &s : argv)
    cargv.push_back(const_cast<char *>(s.c_str()));
  cargv.push_back(nullptr);

  pid_t pid = fork();
  if (pid < 0) {
    return std::optional<std::string>(std::string("fork failed: ") +
                                      std::strerror(errno));
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
      // Clear existing environment then set new variables. macOS lacks
      // clearenv.
#if defined(__APPLE__)
      auto environ_ptr = *_NSGetEnviron();
      if (environ_ptr != nullptr) {
        std::vector<std::string> existing_keys;
        for (char **entry = environ_ptr; entry != nullptr && *entry != nullptr;
             ++entry) {
          std::string kv(*entry);
          auto pos = kv.find('=');
          if (pos != std::string::npos) {
            existing_keys.emplace_back(kv.substr(0, pos));
          }
        }
        for (const auto &key : existing_keys) {
          ::unsetenv(key.c_str());
        }
      }
#else
      ::clearenv();
#endif
      for (const auto &kv : *item.env) {
        ::setenv(kv.first.c_str(), kv.second.c_str(), 1);
      }
    }

    for (const auto &kv : extra_env) {
      ::setenv(kv.first.c_str(), kv.second.c_str(), 1);
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
  const auto effective_timeout_ms =
      (item.timeout_ms && *item.timeout_ms > 0) ? *item.timeout_ms : 30000;
  const auto timeout = std::chrono::milliseconds(effective_timeout_ms);

  while (true) {
    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w == pid) {
      break;
    }
    if (w == -1) {
      return std::optional<std::string>(std::string("waitpid failed: ") +
                                        std::strerror(errno));
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

monad::IO<void> ExecActionHandler::apply(
    const dto::DeviceInstallConfigDto &config,
    std::optional<std::vector<std::string>> allowed_types) {
  using ReturnIO = monad::IO<void>;
  try {
    auto self = shared_from_this();
    auto resource_materializer = resource_materializer_factory_();
    //  make_resource_materializer();
    // if (!resource_materializer) {
    //   return ReturnIO::fail(
    //       monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
    //                         "ExecActionHandler missing resource materializer"));
    // }

    auto exec_env_resolver = exec_env_resolver_factory_();
    // make_exec_env_resolver();

    auto processed_any = std::make_shared<bool>(false);

    auto is_allowed = [&allowed_types](const dto::InstallItem &item) {
      if (!allowed_types) {
        return true;
      }
      if (!item.ob_type) {
        return false;
      }
      for (const auto &t : *allowed_types) {
        if (*item.ob_type == t) {
          return true;
        }
      }
      return false;
    };

    ReturnIO pipeline = ReturnIO::pure();

    for (const auto &item : config.installs) {
      if (!is_allowed(item)) {
        continue;
      }

      if ((!item.cmd || item.cmd->empty()) &&
          (!item.cmd_argv || item.cmd_argv->empty())) {
        continue;
      }

      auto item_copy = item;
      pipeline =
          pipeline.then([self, processed_any, item_copy, resource_materializer,
                         exec_env_resolver]() mutable {
            using ReturnIO = monad::IO<void>;
            *processed_any = true;
            return resource_materializer->ensure_materialized(item_copy)
                .then([self, resource_materializer, item_copy, exec_env_resolver]() -> ReturnIO {
                  if (auto err = run_item_cmd(item_copy, exec_env_resolver)) {
                    if (item_copy.continue_on_error) {
                      self->output_.logger().warning()
                          << "exec item '" << item_copy.id
                          << "' failed: " << *err << std::endl;
                      return ReturnIO::pure();
                    }
                    auto error_obj = monad::make_error(
                        my_errors::GENERAL::UNEXPECTED_RESULT, *err);
                    error_obj.params["stage"] = "exec";
                    return ReturnIO::fail(std::move(error_obj));
                  }

                  self->output_.logger().info()
                      << "Executed exec item '" << item_copy.id
                      << "' successfully" << std::endl;
                  return ReturnIO::pure();
                })
                .catch_then([self, item_copy, resource_materializer](monad::Error err) -> ReturnIO {
                  if (auto *stage = err.params.if_contains("stage")) {
                    if (stage->is_string() && stage->as_string() == "exec") {
                      return ReturnIO::fail(std::move(err));
                    }
                  }

                  if (item_copy.continue_on_error) {
                    self->output_.logger().warning()
                        << "exec item '" << item_copy.id
                        << "' resource materialize failed: " << err.what
                        << std::endl;
                    return ReturnIO::pure();
                  }
                  return ReturnIO::fail(std::move(err));
                });
          });
    }

    return pipeline.then([self, processed_any]() -> ReturnIO {
      if (!*processed_any) {
        self->output_.logger().debug()
            << "No exec items present in plan" << std::endl;
      }
      return ReturnIO::pure();
    });
  } catch (const std::exception &ex) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT, ex.what()));
  }
}

} // namespace certctrl::install_actions
