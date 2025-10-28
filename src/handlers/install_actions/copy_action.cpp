#include "handlers/install_actions/copy_action.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fmt/format.h>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace certctrl::install_actions {

namespace {

constexpr std::size_t kMaxBackupsPerFile = 5;

std::string generate_temp_suffix() {
  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<std::uint64_t> dist;
  std::uint64_t random_part = dist(gen);
  return fmt::format("{}.{}", now, random_part);
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

std::filesystem::path resource_root_for(const InstallActionContext &context,
                                        const std::string &ob_type,
                                        std::int64_t ob_id) {
  std::filesystem::path resource_root = context.runtime_dir / "resources";
  if (ob_type == "cert") {
    resource_root /= "certs";
  } else if (ob_type == "ca") {
    resource_root /= "cas";
  } else {
    resource_root /= "unknown";
  }
  resource_root /= std::to_string(ob_id);
  resource_root /= "current";
  return resource_root;
}

bool is_private_material_name(const std::string &name) {
  return name == "private.key" || name == "bundle.pfx" ||
         name == "certificate.pfx";
}

std::filesystem::perms desired_permissions(bool private_material) {
#ifdef _WIN32
  return std::filesystem::perms::owner_all;
#else
  if (private_material) {
    return std::filesystem::perms::owner_read |
           std::filesystem::perms::owner_write;
  }
  return std::filesystem::perms::owner_read |
         std::filesystem::perms::owner_write |
         std::filesystem::perms::group_read |
         std::filesystem::perms::others_read;
#endif
}

std::optional<std::string> perform_copy_operation(
    const InstallActionContext &context, const std::filesystem::path &source,
    const std::filesystem::path &destination, bool private_material) {
  try {
    if (!std::filesystem::exists(source)) {
      return fmt::format("Source file '{}' not found", source.string());
    }

    auto dest_dir = destination.parent_path();
    if (!dest_dir.empty()) {
      std::filesystem::create_directories(dest_dir);
#ifndef _WIN32
      std::filesystem::permissions(dest_dir, default_directory_perms(),
                                   std::filesystem::perm_options::add);
#endif
    }

    auto temp_dest = destination;
    temp_dest += ".tmp-";
    temp_dest += generate_temp_suffix();

    std::filesystem::copy_file(
        source, temp_dest, std::filesystem::copy_options::overwrite_existing);

#ifndef _WIN32
    std::filesystem::permissions(temp_dest,
                                 desired_permissions(private_material),
                                 std::filesystem::perm_options::replace);
#endif

    if (std::filesystem::exists(destination)) {
      const auto backup_dir = destination.parent_path() / ".certctrl-backups";
      std::error_code dir_ec;
      std::filesystem::create_directories(backup_dir, dir_ec);
#ifndef _WIN32
      if (!dir_ec) {
        std::filesystem::permissions(backup_dir, default_directory_perms(),
                                     std::filesystem::perm_options::add);
      }
#endif

      const auto base_name = destination.filename().string();
      std::filesystem::path backup;
      bool using_subdir = !dir_ec;
      if (using_subdir) {
        backup = backup_dir / (base_name + "." + generate_temp_suffix());
      } else {
        backup = destination;
        backup += ".bak";
        backup += generate_temp_suffix();
      }
      std::error_code ec;
      std::filesystem::rename(destination, backup, ec);
      if (ec) {
        context.output.logger().warning()
            << "Failed to create backup for '" << destination
            << "': " << ec.message() << std::endl;
      } else if (using_subdir) {
        struct BackupInfo {
          std::filesystem::path path;
          std::filesystem::file_time_type timestamp;
        };
        std::vector<BackupInfo> backups;
        const std::string prefix = base_name + ".";
        std::error_code iter_ec;
        for (const auto &entry : std::filesystem::directory_iterator(backup_dir, iter_ec)) {
          if (!entry.is_regular_file()) {
            continue;
          }
          const auto name = entry.path().filename().string();
          if (name.rfind(prefix, 0) == 0) {
            std::error_code ts_ec;
            auto ts = std::filesystem::last_write_time(entry.path(), ts_ec);
            if (ts_ec) {
              ts = std::filesystem::file_time_type::min();
            }
            backups.push_back({entry.path(), ts});
          }
        }
        if (iter_ec) {
          context.output.logger().warning()
              << "Failed to enumerate backups in '" << backup_dir
              << "': " << iter_ec.message() << std::endl;
        }

        if (backups.size() > kMaxBackupsPerFile) {
          std::sort(backups.begin(), backups.end(),
                    [](const BackupInfo &lhs, const BackupInfo &rhs) {
                      return lhs.timestamp > rhs.timestamp;
                    });

          for (std::size_t idx = kMaxBackupsPerFile; idx < backups.size(); ++idx) {
            std::error_code rm_ec;
            std::filesystem::remove(backups[idx].path, rm_ec);
            if (rm_ec) {
              context.output.logger().warning()
                  << "Failed to prune backup '" << backups[idx].path
                  << "': " << rm_ec.message() << std::endl;
              break;
            }
          }
        }
      }
    }

    std::filesystem::rename(temp_dest, destination);

#ifndef _WIN32
    std::filesystem::permissions(destination,
                                 desired_permissions(private_material),
                                 std::filesystem::perm_options::replace);
#endif

    return std::nullopt;
  } catch (const std::exception &e) {
    return std::string(e.what());
  }
}

} // namespace

monad::IO<void>
apply_copy_actions(const InstallActionContext &context,
                   const dto::DeviceInstallConfigDto &config,
                   const std::optional<std::string> &target_ob_type,
                   std::optional<std::int64_t> target_ob_id) {
  using ReturnIO = monad::IO<void>;

  try {
    std::vector<std::string> failure_messages;

    for (const auto &item : config.installs) {
      if (item.type != "copy") {
        continue;
      }

      if (target_ob_type) {
        if (!item.ob_type || *item.ob_type != *target_ob_type) {
          continue;
        }
        if (target_ob_id && (!item.ob_id || *item.ob_id != *target_ob_id)) {
          continue;
        }
      }

      if (!item.from || item.from->empty()) {
        std::string msg = fmt::format("copy item '{}' missing from entries",
                                      item.id);
        context.output.logger().error() << msg << std::endl;
        failure_messages.push_back(std::move(msg));
        continue;
      }

      if (!item.to || item.to->empty()) {
        context.output.logger().info()
            << "Skipping copy item '" << item.id
            << "' due to empty destination list" << std::endl;
        continue;
      }

      if (item.from->size() != item.to->size()) {
        std::string msg = fmt::format(
            "copy item '{}' from/to length mismatch", item.id);
        context.output.logger().error() << msg << std::endl;
        failure_messages.push_back(std::move(msg));
        continue;
      }

      if (!item.ob_type || !item.ob_id) {
        std::string msg = fmt::format(
            "copy item '{}' missing ob_type/ob_id", item.id);
        context.output.logger().error() << msg << std::endl;
        failure_messages.push_back(std::move(msg));
        continue;
      }

      if (auto ensure_err = context.ensure_resource_materialized(item);
          ensure_err.has_value()) {
        std::string msg = fmt::format(
            "copy item '{}': {}", item.id, ensure_err->what);
        context.output.logger().error() << msg << std::endl;
        failure_messages.push_back(std::move(msg));
        continue;
      }

      auto resource_root =
          resource_root_for(context, *item.ob_type, *item.ob_id);

      for (std::size_t i = 0; i < item.from->size(); ++i) {
        const auto &virtual_name = item.from->at(i);
        const auto &dest_path_str = item.to->at(i);

        if(dest_path_str.empty()) {
          context.output.logger().debug()
              << "Skipping copy of '" << virtual_name
              << "' due to empty destination path" << std::endl;
          continue;
        }

        std::filesystem::path source_path = resource_root / virtual_name;
        std::filesystem::path dest_path(dest_path_str);

        if (!dest_path.is_absolute()) {
          std::string msg = fmt::format(
              "copy item '{}': destination path '{}' is not absolute",
              item.id, dest_path.string());
          context.output.logger().error() << msg << std::endl;
          failure_messages.push_back(std::move(msg));
          continue;
        }

        bool private_material = is_private_material_name(virtual_name);
        if (auto err = perform_copy_operation(context, source_path, dest_path,
                                              private_material)) {
          std::string msg = fmt::format(
              "copy item '{}': failed to copy '{}' -> '{}': {}", item.id,
              source_path.string(), dest_path.string(), *err);
          context.output.logger().error() << msg << std::endl;
          failure_messages.push_back(std::move(msg));
          continue;
        }

        context.output.logger().info() << "Copied '" << source_path << "' -> '"
                                       << dest_path << "'" << std::endl;
      }
    }

    if (!failure_messages.empty()) {
      std::ostringstream oss;
      oss << "copy actions encountered " << failure_messages.size()
          << " failure(s): ";
      for (std::size_t i = 0; i < failure_messages.size(); ++i) {
        if (i != 0) {
          oss << "; ";
        }
        oss << failure_messages[i];
      }
      oss << ".****** If in linux system, it's most likely permission issue"
             " need to add ReadWritePaths in systemd service file. ******";
      auto err = monad::make_error(my_errors::GENERAL::FILE_READ_WRITE,
                                   oss.str());
      // log a square error message, if in linux system, it's most likely permission issue
      // need to add ReadWritePaths in systemd service file
      return ReturnIO::fail(std::move(err));
    }

    return ReturnIO::pure();
  } catch (const std::exception &e) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT, e.what()));
  }
}

} // namespace certctrl::install_actions
