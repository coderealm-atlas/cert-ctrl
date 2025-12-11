#include "util/browser_trust_sync.hpp"

#include <algorithm>
#include <array>
#include <boost/log/trivial.hpp>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <optional>

#if defined(__linux__)
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include <fmt/format.h>

#include "util/my_logging.hpp"

namespace certctrl::util {

namespace {

#if defined(__linux__)

struct CommandResult {
  int exit_code{-1};
  std::string stdout_data;
  std::string stderr_data;

  [[nodiscard]] bool success() const { return exit_code == 0; }
};

CommandResult run_command(const std::vector<std::string> &args) {
  if (args.empty()) {
    throw std::invalid_argument("run_command requires arguments");
  }

  int stdout_pipe[2];
  int stderr_pipe[2];
  if (pipe(stdout_pipe) == -1 || pipe(stderr_pipe) == -1) {
    throw std::runtime_error("Failed to create pipes for command execution");
  }

  pid_t pid = fork();
  if (pid == -1) {
    close(stdout_pipe[0]);
    close(stdout_pipe[1]);
    close(stderr_pipe[0]);
    close(stderr_pipe[1]);
    throw std::runtime_error("fork failed while launching certutil");
  }

  if (pid == 0) {
    // child
    if (dup2(stdout_pipe[1], STDOUT_FILENO) == -1 ||
        dup2(stderr_pipe[1], STDERR_FILENO) == -1) {
      _exit(127);
    }
    close(stdout_pipe[0]);
    close(stdout_pipe[1]);
    close(stderr_pipe[0]);
    close(stderr_pipe[1]);

    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (const auto &arg : args) {
      argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);

    execvp(argv[0], argv.data());
    _exit(127);
  }

  close(stdout_pipe[1]);
  close(stderr_pipe[1]);

  auto read_pipe = [](int fd) {
    std::string data;
    char buffer[4096];
    while (true) {
      ssize_t n = read(fd, buffer, sizeof(buffer));
      if (n == 0) {
        break;
      }
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      data.append(buffer, static_cast<std::size_t>(n));
    }
    close(fd);
    return data;
  };

  CommandResult result;
  result.stdout_data = read_pipe(stdout_pipe[0]);
  result.stderr_data = read_pipe(stderr_pipe[0]);

  int status = 0;
  while (waitpid(pid, &status, 0) == -1) {
    if (errno != EINTR) {
      result.exit_code = -1;
      return result;
    }
  }

  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    result.exit_code = -1;
    result.stderr_data.append(
        fmt::format("\nProcess terminated by signal {}", WTERMSIG(status)));
  } else {
    result.exit_code = -1;
  }

  return result;
}

bool is_executable(const std::filesystem::path &candidate) {
  return ::access(candidate.c_str(), X_OK) == 0;
}

std::optional<std::filesystem::path> find_certutil() {
  const char *path_env = std::getenv("PATH");
  if (path_env) {
    std::stringstream ss(path_env);
    std::string segment;
    while (std::getline(ss, segment, ':')) {
      if (segment.empty()) {
        continue;
      }
      std::filesystem::path candidate =
          std::filesystem::path(segment) / "certutil";
      if (is_executable(candidate)) {
        return candidate;
      }
    }
  }

  std::array<const char *, 3> fallbacks{
      "/usr/bin/certutil", "/usr/local/bin/certutil", "/bin/certutil"};
  for (const char *fb : fallbacks) {
    std::filesystem::path candidate(fb);
    if (is_executable(candidate)) {
      return candidate;
    }
  }

  return std::nullopt;
}

struct NssProfile {
  std::filesystem::path db_path;
  uid_t uid;
  gid_t gid;
  std::string owner;
};

bool has_nss_db(const std::filesystem::path &path) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) ||
      !std::filesystem::is_directory(path, ec)) {
    return false;
  }
  if (std::filesystem::exists(path / "cert9.db", ec)) {
    return true;
  }
  if (std::filesystem::exists(path / "pkcs11.txt", ec)) {
    return true;
  }
  if (std::filesystem::exists(path / "cert8.db", ec)) {
    return true;
  }
  return false;
}

void chown_recursive(const std::filesystem::path &root, uid_t uid, gid_t gid) {
  std::error_code ec;
  if (root.empty()) {
    return;
  }
  ::chown(root.c_str(), uid, gid);

  std::filesystem::directory_options opts =
      std::filesystem::directory_options::skip_permission_denied;
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(root, opts, ec)) {
    if (entry.is_symlink(ec)) {
      continue;
    }
    ::chown(entry.path().c_str(), uid, gid);
  }
}

void ensure_directory_ownership(const std::filesystem::path &path, uid_t uid,
                                gid_t gid) {
  if (path.empty()) {
    return;
  }
  ::chown(path.c_str(), uid, gid);
}

std::vector<NssProfile> discover_profiles() {
  std::vector<NssProfile> profiles;
  std::unordered_set<std::string> seen;

  setpwent();
  struct passwd *pwd = nullptr;
  while ((pwd = getpwent()) != nullptr) {
    if (pwd->pw_uid != 0 && pwd->pw_uid < 1000) {
      continue;
    }
    if (!pwd->pw_dir) {
      continue;
    }
    std::filesystem::path home(pwd->pw_dir);
    std::error_code ec;
    if (!std::filesystem::exists(home, ec)) {
      continue;
    }

    auto register_profile = [&](const std::filesystem::path &candidate) {
      std::error_code ec_local;
      if (!std::filesystem::exists(candidate, ec_local)) {
        return;
      }
      if (!std::filesystem::is_directory(candidate, ec_local)) {
        return;
      }
      std::filesystem::path abs =
          std::filesystem::weakly_canonical(candidate, ec_local);
      if (abs.empty()) {
        abs = candidate;
      }
      std::string key = abs.string();
      if (seen.insert(key).second) {
        std::string owner = pwd->pw_name ? std::string(pwd->pw_name)
                                         : fmt::format("uid{}", pwd->pw_uid);
        profiles.push_back(
            {candidate, pwd->pw_uid, pwd->pw_gid, std::move(owner)});
      }
    };

    std::filesystem::path nss_home = home / ".pki" / "nssdb";
    if (!std::filesystem::exists(nss_home, ec)) {
      if (std::filesystem::create_directories(nss_home, ec)) {
        ensure_directory_ownership(nss_home, pwd->pw_uid, pwd->pw_gid);
      }
    }
    register_profile(nss_home);

    const std::vector<std::filesystem::path> config_roots = {
        home / ".config" / "google-chrome", home / ".config" / "chromium",
        home / ".config" / "microsoft-edge", home / ".config" / "brave"};

    for (const auto &config_root : config_roots) {
      std::error_code config_ec;
      if (!std::filesystem::exists(config_root, config_ec) ||
          !std::filesystem::is_directory(config_root, config_ec)) {
        continue;
      }
      for (const auto &entry :
           std::filesystem::directory_iterator(config_root, config_ec)) {
        if (!entry.is_directory(config_ec)) {
          continue;
        }
        if (has_nss_db(entry.path())) {
          register_profile(entry.path());
        }
      }
    }

    const std::vector<std::filesystem::path> snap_roots = {
        home / "snap" / "chromium" / "current" / ".pki" / "nssdb",
        home / "snap" / "chromium" / "common" / ".pki" / "nssdb",
        home / "snap" / "google-chrome" / "current" / ".config" /
            "google-chrome"};

    for (const auto &snap_root : snap_roots) {
      std::error_code snap_ec;
      if (!std::filesystem::exists(snap_root, snap_ec)) {
        continue;
      }
      if (snap_root.filename() == "google-chrome") {
        for (const auto &entry :
             std::filesystem::directory_iterator(snap_root, snap_ec)) {
          if (!entry.is_directory(snap_ec)) {
            continue;
          }
          if (has_nss_db(entry.path())) {
            register_profile(entry.path());
          }
        }
      } else {
        register_profile(snap_root);
      }
    }
  }
  endpwent();

  return profiles;
}

std::optional<std::string>
ensure_db_initialized(const std::filesystem::path &certutil_path,
                      const NssProfile &profile) {
  std::error_code ec;
  if (!std::filesystem::exists(profile.db_path, ec)) {
    return fmt::format("Profile path '{}' missing", profile.db_path.string());
  }
  if (std::filesystem::exists(profile.db_path / "cert9.db", ec)) {
    return std::nullopt;
  }

  std::vector<std::string> args{certutil_path.string(), "-d",
                                "sql:" + profile.db_path.string(), "-N",
                                "--empty-password"};
  auto result = run_command(args);
  if (!result.success()) {
    return fmt::format(
        "certutil -N failed for '{}': {}", profile.db_path.string(),
        result.stderr_data.empty() ? result.stdout_data : result.stderr_data);
  }

  chown_recursive(profile.db_path, profile.uid, profile.gid);
  return std::nullopt;
}

std::optional<std::string>
remove_alias(const std::filesystem::path &certutil_path,
             const NssProfile &profile, const std::string &alias) {
  std::vector<std::string> args{certutil_path.string(),
                                "-d",
                                "sql:" + profile.db_path.string(),
                                "-D",
                                "-n",
                                alias};
  auto result = run_command(args);
  if (!result.success()) {
    std::string combined = result.stderr_data;
    if (combined.empty()) {
      combined = result.stdout_data;
    }
    std::string lowered = combined;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);
    if (lowered.find("not found") != std::string::npos) {
      return std::nullopt;
    }
    return fmt::format("Failed to remove alias '{}' from '{}': {}", alias,
                       profile.db_path.string(), combined);
  }
  chown_recursive(profile.db_path, profile.uid, profile.gid);
  return std::nullopt;
}

bool alias_exists(const std::filesystem::path &certutil_path,
                  const NssProfile &profile, const std::string &alias) {
  std::vector<std::string> args{certutil_path.string(),
                                "-d",
                                "sql:" + profile.db_path.string(),
                                "-L",
                                "-n",
                                alias};
  auto result = run_command(args);
  return result.success();
}

std::optional<std::string>
modify_trust(const std::filesystem::path &certutil_path,
             const NssProfile &profile, const std::string &alias) {
  std::vector<std::string> args{certutil_path.string(),
                                "-d",
                                "sql:" + profile.db_path.string(),
                                "-M",
                                "-n",
                                alias,
                                "-t",
                                "CT,C,C"};
  auto result = run_command(args);
  if (!result.success()) {
    std::string combined =
        result.stderr_data.empty() ? result.stdout_data : result.stderr_data;
    return fmt::format("Failed to update trust bits for alias '{}' in '{}': {}",
                       alias, profile.db_path.string(), combined);
  }
  chown_recursive(profile.db_path, profile.uid, profile.gid);
  return std::nullopt;
}

std::optional<std::string> add_alias(const std::filesystem::path &certutil_path,
                                     const NssProfile &profile,
                                     const std::string &alias,
                                     const std::filesystem::path &ca_pem_path) {
  std::vector<std::string> args{certutil_path.string(),
                                "-d",
                                "sql:" + profile.db_path.string(),
                                "-A",
                                "-n",
                                alias,
                                "-t",
                                "CT,C,C",
                                "-i",
                                ca_pem_path.string()};
  auto result = run_command(args);
  if (!result.success()) {
    std::string combined =
        result.stderr_data.empty() ? result.stdout_data : result.stderr_data;
    return fmt::format("Failed to insert alias '{}' into '{}': {}", alias,
                       profile.db_path.string(), combined);
  }
  chown_recursive(profile.db_path, profile.uid, profile.gid);
  return std::nullopt;
}

#endif // defined(__linux__)

} // namespace

BrowserTrustSync::BrowserTrustSync(customio::ConsoleOutput &output,
                                   std::filesystem::path runtime_dir)
    : output_(output), runtime_dir_(std::move(runtime_dir)) {}

std::optional<std::string>
BrowserTrustSync::sync_ca(const std::string &canonical_name,
                          const std::optional<std::string> &previous_alias,
                          const std::filesystem::path &ca_pem_path) {
#if defined(__linux__)
  (void)runtime_dir_;
  if (canonical_name.empty()) {
    return std::nullopt;
  }
  if (!std::filesystem::exists(ca_pem_path)) {
    return fmt::format("CA material '{}' missing for browser sync",
                       ca_pem_path.string());
  }

  auto certutil_path = find_certutil();
  if (!certutil_path) {
    output_.logger().warning()
        << "certutil (from nss-tools) not found in PATH; install the"
           " NSS tooling suits first, e.g. 'sudo apt install"
           " libnss3-tools', 'sudo dnf install nss-tools', 'sudo zypper"
           " install mozilla-nss-tools', 'sudo pacman -S nss', or 'sudo"
           " apk add nss' to enable browser trust sync"
        << std::endl;
    return std::nullopt;
  }

  auto profiles = discover_profiles();
  if (profiles.empty()) {
    output_.logger().warning()
        << "No NSS profiles detected; skipping browser trust sync" << std::endl;
    return std::nullopt;
  }

  std::vector<std::string> errors;
  for (const auto &profile : profiles) {

    BOOST_LOG_SEV(app_logger(), trivial::info)
        << "Syncing CA '" << canonical_name << "' with NSS db '"
        << profile.db_path << "' (user=" << profile.owner << ")" << std::endl;

    if (previous_alias && *previous_alias != canonical_name) {
      if (auto err = remove_alias(*certutil_path, profile, *previous_alias)) {
        BOOST_LOG_SEV(app_logger(), trivial::warning)
            << "Browser trust removal warning: " << *err;
      }
    }

    if (auto init_err = ensure_db_initialized(*certutil_path, profile)) {
      errors.push_back(*init_err);
      BOOST_LOG_SEV(app_logger(), trivial::info)
          << "Browser trust init warning: " << *init_err;
      continue;
    }

    if (alias_exists(*certutil_path, profile, canonical_name)) {
      if (auto mod_err =
              modify_trust(*certutil_path, profile, canonical_name)) {
        errors.push_back(*mod_err);
        BOOST_LOG_SEV(app_logger(), trivial::warning)
            << "Browser trust update warning: " << *mod_err;
      }
      continue;
    }

    if (auto add_err =
            add_alias(*certutil_path, profile, canonical_name, ca_pem_path)) {
      errors.push_back(*add_err);
      BOOST_LOG_SEV(app_logger(), trivial::warning)
          << "Browser trust add warning: " << *add_err;
      continue;
    }
  }

  if (!errors.empty()) {
    std::string joined;
    for (std::size_t idx = 0; idx < errors.size(); ++idx) {
      if (idx != 0) {
        joined.append("; ");
      }
      joined.append(errors[idx]);
    }
    return joined;
  }
  return std::nullopt;
#else
  (void)canonical_name;
  (void)previous_alias;
  (void)ca_pem_path;
  output_.logger().debug()
      << "Browser trust sync not supported on this platform" << std::endl;
  return std::nullopt;
#endif
}

std::optional<std::string>
BrowserTrustSync::remove_ca_alias(const std::string &alias) {
#if defined(__linux__)
  if (alias.empty()) {
    return std::nullopt;
  }

  auto certutil_path = find_certutil();
  if (!certutil_path) {
    output_.logger().warning()
        << "certutil (from nss-tools) not found in PATH; install the"
           " NSS tooling suits first, e.g. 'sudo apt install"
           " libnss3-tools', 'sudo dnf install nss-tools', 'sudo zypper"
           " install mozilla-nss-tools', 'sudo pacman -S nss', or 'sudo"
           " apk add nss' to enable browser trust removal"
        << std::endl;
    return std::nullopt;
  }

  auto profiles = discover_profiles();
  if (profiles.empty()) {
    output_.logger().warning()
        << "No NSS profiles detected; skipping browser trust removal"
        << std::endl;
    return std::nullopt;
  }

  std::vector<std::string> errors;
  for (const auto &profile : profiles) {
    if (auto err = remove_alias(*certutil_path, profile, alias)) {
      BOOST_LOG_SEV(app_logger(), trivial::warning)
          << "Browser trust removal warning: " << *err;
      errors.push_back(*err);
    }
  }

  if (!errors.empty()) {
    std::string joined;
    for (std::size_t idx = 0; idx < errors.size(); ++idx) {
      if (idx != 0) {
        joined.append("; ");
      }
      joined.append(errors[idx]);
    }
    return joined;
  }
  return std::nullopt;
#else
  (void)alias;
  output_.logger().debug()
      << "Browser trust sync not supported on this platform" << std::endl;
  return std::nullopt;
#endif
}

} // namespace certctrl::util
