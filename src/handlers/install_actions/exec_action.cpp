#include "handlers/install_actions/exec_action.hpp"

#include <chrono>
#include <cstring>
#include <thread>
#include <vector>
#include <sstream>
#include <cstdlib>

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
