#include "handlers/install_actions/import_ca_action.hpp"

#include <chrono>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fmt/format.h>
#include <optional>
#include <random>
#include <string>
#include <system_error>

#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace certctrl::install_actions {

namespace {

struct TrustStoreTarget {
  std::filesystem::path directory;
  std::string update_command;
  std::string description;
};

std::string sanitize_label(std::string_view raw_label,
                           std::int64_t fallback_id) {
  std::string sanitized;
  sanitized.reserve(raw_label.size());
  for (char ch : raw_label) {
    unsigned char uch = static_cast<unsigned char>(ch);
    if (std::isalnum(uch)) {
      sanitized.push_back(static_cast<char>(std::tolower(uch)));
    } else if (ch == '-' || ch == '_' || ch == '.') {
      sanitized.push_back(ch);
    } else {
      sanitized.push_back('-');
    }
  }
  while (!sanitized.empty() && sanitized.front() == '-') {
    sanitized.erase(sanitized.begin());
  }
  while (!sanitized.empty() && sanitized.back() == '-') {
    sanitized.pop_back();
  }
  if (sanitized.empty()) {
    sanitized = fmt::format("ca-{}", fallback_id);
  }
  return sanitized;
}

std::filesystem::perms desired_public_permissions() {
#ifdef _WIN32
  return std::filesystem::perms::owner_all;
#else
  return std::filesystem::perms::owner_read |
         std::filesystem::perms::owner_write |
         std::filesystem::perms::group_read |
         std::filesystem::perms::others_read;
#endif
}

std::filesystem::perms default_directory_perms() {
#ifdef _WIN32
  return std::filesystem::perms::owner_all;
#else
  return std::filesystem::perms::owner_read |
         std::filesystem::perms::owner_write |
         std::filesystem::perms::owner_exec |
         std::filesystem::perms::group_read |
         std::filesystem::perms::group_exec;
#endif
}

std::string generate_temp_suffix() {
  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<std::uint64_t> dist;
  std::uint64_t random_part = dist(gen);
  return fmt::format("{}.{}", now, random_part);
}

std::optional<std::string> copy_ca_material(
    const std::filesystem::path &source,
    const std::filesystem::path &destination) {
  try {
    if (!std::filesystem::exists(source)) {
      return fmt::format("CA source '{}' not found", source.string());
    }

    auto parent = destination.parent_path();
    if (!parent.empty()) {
      std::filesystem::create_directories(parent);
#ifndef _WIN32
      std::filesystem::permissions(parent, default_directory_perms(),
                                   std::filesystem::perm_options::add);
#endif
    }

    auto temp_dest = destination;
    temp_dest += ".tmp-";
    temp_dest += generate_temp_suffix();

    std::filesystem::copy_file(source, temp_dest,
                               std::filesystem::copy_options::overwrite_existing);

#ifndef _WIN32
    std::filesystem::permissions(temp_dest, desired_public_permissions(),
                                 std::filesystem::perm_options::replace);
#endif

    if (std::filesystem::exists(destination)) {
      auto backup = destination;
      backup += ".bak";
      backup += generate_temp_suffix();
      std::error_code ec;
      std::filesystem::rename(destination, backup, ec);
    }

    std::filesystem::rename(temp_dest, destination);

#ifndef _WIN32
    std::filesystem::permissions(destination, desired_public_permissions(),
                                 std::filesystem::perm_options::replace);
#endif

    return std::nullopt;
  } catch (const std::exception &ex) {
    return ex.what();
  }
}

std::optional<TrustStoreTarget> trust_store_from_env() {
  if (const char *dir = std::getenv("CERTCTRL_CA_IMPORT_DIR")) {
    TrustStoreTarget target;
    target.directory = std::filesystem::path(dir);
    if (const char *cmd = std::getenv("CERTCTRL_CA_UPDATE_COMMAND")) {
      target.update_command = cmd;
    }
    target.description = "environment override";
    return target;
  }
  return std::nullopt;
}

std::optional<TrustStoreTarget> detect_system_trust_store() {
  if (auto override_target = trust_store_from_env()) {
    return override_target;
  }

#if defined(__linux__)
  struct Candidate {
    const char *dir;
    const char *cmd;
    const char *desc;
  };

  constexpr Candidate candidates[] = {
      {"/usr/local/share/ca-certificates", "update-ca-certificates",
       "Debian/Ubuntu trust store"},
      {"/etc/pki/ca-trust/source/anchors", "update-ca-trust extract",
       "RHEL/Fedora trust store"},
      {"/usr/share/pki/trust/anchors", "update-ca-certificates",
       "SUSE trust store"},
  };

  for (const auto &candidate : candidates) {
    std::filesystem::path dir(candidate.dir);
    if (std::filesystem::exists(dir)) {
      TrustStoreTarget target;
      target.directory = std::move(dir);
      target.update_command = candidate.cmd;
      target.description = candidate.desc;
      return target;
    }
  }
#elif defined(_WIN32)
  if (auto override_target = trust_store_from_env()) {
    return override_target;
  }
#elif defined(__APPLE__)
  if (auto override_target = trust_store_from_env()) {
    return override_target;
  }
#endif

  return std::nullopt;
}

std::filesystem::path resource_root_for(const InstallActionContext &context,
                                        const dto::InstallItem &item) {
  std::filesystem::path root = context.runtime_dir / "resources";
  if (item.ob_type && *item.ob_type == "ca" && item.ob_id) {
    root /= "cas";
    root /= std::to_string(*item.ob_id);
    root /= "current";
    return root;
  }
  return {};
}

monad::Error make_error(int code, std::string message) {
  return monad::Error{.code = code, .what = std::move(message)};
}

bool should_skip_item(const dto::InstallItem &item,
                      const std::optional<std::string> &target_ob_type,
                      std::optional<std::int64_t> target_ob_id) {
  if (!item.ob_type || !item.ob_id) {
    return true;
  }
  if (target_ob_type && *item.ob_type != *target_ob_type) {
    return true;
  }
  if (target_ob_id && *item.ob_id != *target_ob_id) {
    return true;
  }
  return false;
}

void log_warning(const InstallActionContext &context,
                 const dto::InstallItem &item, std::string_view message) {
  context.output.logger().warning()
      << "import_ca item '" << item.id << "': " << message << std::endl;
}

} // namespace

monad::IO<void> apply_import_ca_actions(
    const InstallActionContext &context,
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id) {
  using ReturnIO = monad::IO<void>;

  try {
    bool processed_any = false;

    for (const auto &item : config.installs) {
      if (item.type != "import_ca") {
        continue;
      }

      processed_any = true;

      if (should_skip_item(item, target_ob_type, target_ob_id)) {
        continue;
      }

      if (!item.ob_type || *item.ob_type != "ca" || !item.ob_id) {
        auto err = make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                              "import_ca item requires ob_type 'ca' and ob_id");
        if (item.continue_on_error) {
          log_warning(context, item, err.what);
          continue;
        }
        return ReturnIO::fail(std::move(err));
      }

      auto trust_store = detect_system_trust_store();
      if (!trust_store) {
        auto err = make_error(my_errors::GENERAL::NOT_IMPLEMENTED,
                              "unable to locate a supported trust store directory; set CERTCTRL_CA_IMPORT_DIR to override");
        if (item.continue_on_error) {
          log_warning(context, item, err.what);
          continue;
        }
        return ReturnIO::fail(std::move(err));
      }

      if (auto ensure_err = context.ensure_resource_materialized(item);
          ensure_err.has_value()) {
        if (item.continue_on_error) {
          log_warning(context, item, ensure_err->what);
          continue;
        }
        return ReturnIO::fail(std::move(*ensure_err));
      }

      auto resource_root = resource_root_for(context, item);
      if (resource_root.empty()) {
        auto err = make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                              "unable to resolve resource root for CA");
        if (item.continue_on_error) {
          log_warning(context, item, err.what);
          continue;
        }
        return ReturnIO::fail(std::move(err));
      }

      auto ca_pem_path = resource_root / "ca.pem";
      if (!std::filesystem::exists(ca_pem_path)) {
        auto err = make_error(my_errors::GENERAL::FILE_NOT_FOUND,
                              fmt::format("expected CA PEM missing: {}",
                                          ca_pem_path.string()));
        if (item.continue_on_error) {
          log_warning(context, item, err.what);
          continue;
        }
        return ReturnIO::fail(std::move(err));
      }

      auto label = item.ob_name.value_or(std::string{});
      auto sanitized = sanitize_label(label, *item.ob_id);
      auto destination = trust_store->directory / (sanitized + ".crt");

      if (auto err = copy_ca_material(ca_pem_path, destination)) {
        auto error_obj = make_error(my_errors::GENERAL::FILE_READ_WRITE, *err);
        if (item.continue_on_error) {
          log_warning(context, item, error_obj.what);
          continue;
        }
        return ReturnIO::fail(std::move(error_obj));
      }

      context.output.logger().info()
          << "Imported CA '" << sanitized << "' into "
          << trust_store->directory << std::endl;

      if (!trust_store->update_command.empty()) {
        int rc = std::system(trust_store->update_command.c_str());
        if (rc != 0) {
          auto err = make_error(
              my_errors::GENERAL::UNEXPECTED_RESULT,
              fmt::format("command '{}' exited with status {}",
                          trust_store->update_command, rc));
          if (item.continue_on_error) {
            log_warning(context, item, err.what);
            continue;
          }
          return ReturnIO::fail(std::move(err));
        }
      }
    }

    if (!processed_any) {
      context.output.logger().debug()
          << "No import_ca items present in plan" << std::endl;
    }

    return ReturnIO::pure();
  } catch (const std::exception &ex) {
    return ReturnIO::fail(make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                                     ex.what()));
  }
}

} // namespace certctrl::install_actions
