#include "handlers/install_actions/copy_action.hpp"

#include <chrono>
#include <filesystem>
#include <fmt/format.h>
#include <optional>
#include <random>
#include <string>

#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace certctrl::install_actions {

namespace {

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
      auto backup = destination;
      backup += ".bak";
      backup += generate_temp_suffix();
      std::error_code ec;
      std::filesystem::rename(destination, backup, ec);
      if (ec) {
        context.output.logger().warning()
            << "Failed to create backup for '" << destination
            << "': " << ec.message() << std::endl;
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
        return ReturnIO::fail(
            monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                              "copy item missing from entries"));
      }

      if (!item.to || item.to->empty()) {
        context.output.logger().info()
            << "Skipping copy item '" << item.id
            << "' due to empty destination list" << std::endl;
        continue;
      }

      if (item.from->size() != item.to->size()) {
        return ReturnIO::fail(
            monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                              "copy item from/to length mismatch"));
      }

      if (!item.ob_type || !item.ob_id) {
        return ReturnIO::fail(
            monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                              "copy item missing ob_type/ob_id"));
      }

      if (auto ensure_err = context.ensure_resource_materialized(item);
          ensure_err.has_value()) {
        return ReturnIO::fail(std::move(*ensure_err));
      }

      auto resource_root =
          resource_root_for(context, *item.ob_type, *item.ob_id);

      for (std::size_t i = 0; i < item.from->size(); ++i) {
        const auto &virtual_name = item.from->at(i);
        const auto &dest_path_str = item.to->at(i);

        if(dest_path_str.empty()) {
          context.output.logger().info()
              << "Skipping copy of '" << virtual_name
              << "' due to empty destination path" << std::endl;
          continue;
        }

        std::filesystem::path source_path = resource_root / virtual_name;
        std::filesystem::path dest_path(dest_path_str);

        if (!dest_path.is_absolute()) {
          return ReturnIO::fail(monad::make_error(
              my_errors::GENERAL::INVALID_ARGUMENT,
              fmt::format("Destination path '{}' is not absolute",
                          dest_path.string())));
        }

        bool private_material = is_private_material_name(virtual_name);
        if (auto err = perform_copy_operation(context, source_path, dest_path,
                                              private_material)) {
          return ReturnIO::fail(
              monad::make_error(my_errors::GENERAL::FILE_READ_WRITE, *err));
        }

        context.output.logger().info() << "Copied '" << source_path << "' -> '"
                                       << dest_path << "'" << std::endl;
      }
    }

    return ReturnIO::pure();
  } catch (const std::exception &e) {
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT, e.what()));
  }
}

} // namespace certctrl::install_actions
