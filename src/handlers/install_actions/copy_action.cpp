#include "handlers/install_actions/copy_action.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fmt/format.h>
#include <boost/json.hpp>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "util/my_logging.hpp"

namespace certctrl::install_actions {

namespace {

constexpr std::size_t kMaxBackupsPerFile = 5;

std::string generate_temp_suffix()
{
  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<std::uint64_t> dist;
  std::uint64_t random_part = dist(gen);
  return fmt::format("{}.{}", now, random_part);
}

std::filesystem::perms default_directory_perms()
{
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

std::filesystem::perms desired_permissions(bool private_material)
{
#ifdef _WIN32
  return std::filesystem::perms::owner_all;
#else
  if (private_material)
  {
    return std::filesystem::perms::owner_read |
           std::filesystem::perms::owner_write;
  }
  return std::filesystem::perms::owner_read |
         std::filesystem::perms::owner_write |
         std::filesystem::perms::group_read |
         std::filesystem::perms::others_read;
#endif
}

std::filesystem::path resource_root_for(const std::filesystem::path &runtime_dir,
                                        const std::string &ob_type,
                                        std::int64_t ob_id)
{
  std::filesystem::path resource_root = runtime_dir / "resources";
  if (ob_type == "cert")
  {
    resource_root /= "certs";
  }
  else if (ob_type == "ca")
  {
    resource_root /= "cas";
  }
  else
  {
    resource_root /= "unknown";
  }
  resource_root /= std::to_string(ob_id);
  resource_root /= "current";
  return resource_root;
}

bool is_private_material_name(const std::string &name)
{
  return name == "private.key" || name == "bundle.pfx" ||
         name == "certificate.pfx";
}

std::optional<std::string> perform_copy_operation(
    customio::ConsoleOutput &output, const std::filesystem::path &source,
    const std::filesystem::path &destination, bool private_material)
{
  try
  {
    if (!std::filesystem::exists(source))
    {
      return fmt::format("Source file '{}' not found", source.string());
    }

    auto dest_dir = destination.parent_path();
    if (!dest_dir.empty())
    {
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

    if (std::filesystem::exists(destination))
    {
      const auto backup_dir = destination.parent_path() / ".certctrl-backups";
      std::error_code dir_ec;
      std::filesystem::create_directories(backup_dir, dir_ec);
#ifndef _WIN32
      if (!dir_ec)
      {
        std::filesystem::permissions(backup_dir, default_directory_perms(),
                                     std::filesystem::perm_options::add);
      }
#endif

      const auto base_name = destination.filename().string();
      std::filesystem::path backup;
      const bool using_subdir = !dir_ec;
      if (using_subdir)
      {
        backup = backup_dir / (base_name + "." + generate_temp_suffix());
      }
      else
      {
        backup = destination;
        backup += ".bak";
        backup += generate_temp_suffix();
      }
      std::error_code ec;
      std::filesystem::rename(destination, backup, ec);
      if (ec)
      {
        output.logger().warning()
            << "Failed to create backup for '" << destination
            << "': " << ec.message() << std::endl;
      }
      else if (using_subdir)
      {
        struct BackupInfo
        {
          std::filesystem::path path;
          std::filesystem::file_time_type timestamp;
        };
        std::vector<BackupInfo> backups;
        const std::string prefix = base_name + ".";
        std::error_code iter_ec;
        for (const auto &entry :
             std::filesystem::directory_iterator(backup_dir, iter_ec))
        {
          if (!entry.is_regular_file())
          {
            continue;
          }
          const auto name = entry.path().filename().string();
          if (name.rfind(prefix, 0) == 0)
          {
            std::error_code ts_ec;
            auto ts = std::filesystem::last_write_time(entry.path(), ts_ec);
            if (ts_ec)
            {
              ts = std::filesystem::file_time_type::min();
            }
            backups.push_back({entry.path(), ts});
          }
        }
        if (iter_ec)
        {
          output.logger().warning()
              << "Failed to enumerate backups in '" << backup_dir
              << "': " << iter_ec.message() << std::endl;
        }

        if (backups.size() > kMaxBackupsPerFile)
        {
          std::sort(backups.begin(), backups.end(),
                    [](const BackupInfo &lhs, const BackupInfo &rhs)
                    {
                      return lhs.timestamp > rhs.timestamp;
                    });

          for (std::size_t idx = kMaxBackupsPerFile; idx < backups.size(); ++idx)
          {
            std::error_code rm_ec;
            std::filesystem::remove(backups[idx].path, rm_ec);
            if (rm_ec)
            {
              output.logger().warning()
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
  }
  catch (const std::exception &e)
  {
    return std::string(e.what());
  }
}

} // namespace

CopyActionHandler::CopyActionHandler(
    std::filesystem::path runtime_dir, customio::ConsoleOutput &output,
    IResourceMaterializer::Ptr resource_materializer)
    : runtime_dir_(std::move(runtime_dir)),
      output_(output),
      resource_materializer_(std::move(resource_materializer))
{}

monad::IO<void> CopyActionHandler::apply(
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id)
{
  using ReturnIO = monad::IO<void>;

  if (!resource_materializer_)
  {
    return ReturnIO::fail(monad::make_error(
        my_errors::GENERAL::INVALID_ARGUMENT,
        "CopyActionHandler missing resource materializer"));
  }

  try
  {
    struct SharedState
    {
      std::filesystem::path runtime_dir;
      customio::ConsoleOutput *output;
      IResourceMaterializer::Ptr materializer;
    };

    auto state = std::make_shared<SharedState>(SharedState{
        runtime_dir_, &output_, resource_materializer_});

    auto failure_messages =
        std::make_shared<std::vector<std::string>>();
    auto target_ob_type_copy = target_ob_type;

    auto append_failure = [state, failure_messages](std::string msg)
    {
      state->output->logger().error() << msg << std::endl;
      failure_messages->push_back(std::move(msg));
    };

    auto process_item =
        [state, failure_messages, target_ob_type_copy, target_ob_id,
         append_failure](const dto::InstallItem &item) -> ReturnIO
        {
          if (item.type != "copy")
          {
            return ReturnIO::pure();
          }

          if (target_ob_type_copy)
          {
            if (!item.ob_type || *item.ob_type != *target_ob_type_copy)
            {
              return ReturnIO::pure();
            }
            if (target_ob_id && (!item.ob_id || *item.ob_id != *target_ob_id))
            {
              return ReturnIO::pure();
            }
          }

          if (!item.from || item.from->empty())
          {
            append_failure(
                fmt::format("copy item '{}' missing from entries", item.id));
            return ReturnIO::pure();
          }

          if (!item.to || item.to->empty())
          {
            state->output->logger().info()
                << "Skipping copy item '" << item.id
                << "' due to empty destination list" << std::endl;
            return ReturnIO::pure();
          }

          if (item.from->size() != item.to->size())
          {
            append_failure(fmt::format(
                "copy item '{}': from/to length mismatch", item.id));
            return ReturnIO::pure();
          }

          if (!item.ob_type || !item.ob_id)
          {
            append_failure(
                fmt::format("copy item '{}' missing ob_type/ob_id", item.id));
            return ReturnIO::pure();
          }

          const std::string ob_type = *item.ob_type;
          const std::int64_t ob_id = *item.ob_id;

          return state->materializer->ensure_materialized(item)
              .then([state, append_failure, item, ob_type,
                     ob_id]() -> ReturnIO
                    {
                auto resource_root =
                    resource_root_for(state->runtime_dir, ob_type, ob_id);

                for (std::size_t i = 0; i < item.from->size(); ++i)
                {
                  const auto &virtual_name = item.from->at(i);
                  const auto &dest_path_str = item.to->at(i);

                  if (dest_path_str.empty())
                  {
                    BOOST_LOG_SEV(app_logger(), trivial::trace)
                        << "Empty destination path, skip copying "
                        << virtual_name;
                    continue;
                  }

                  std::filesystem::path source_path =
                      resource_root / virtual_name;
                  std::filesystem::path dest_path(dest_path_str);

                  if (!dest_path.is_absolute())
                  {
                    auto msg = fmt::format(
                        "copy item '{}': destination path '{}' is not absolute",
                        item.id, dest_path.string());
                    append_failure(std::move(msg));
                    continue;
                  }

                  bool private_material =
                      is_private_material_name(virtual_name);
                  if (auto err = perform_copy_operation(
                          *state->output, source_path, dest_path,
                          private_material))
                  {
                    auto msg = fmt::format(
                        "copy item '{}': failed to copy '{}' -> '{}': {}",
                        item.id, source_path.string(), dest_path.string(),
                        *err);
                    append_failure(std::move(msg));
                    continue;
                  }

                  state->output->logger().info()
                      << "Copied '" << source_path << "' -> '"
                      << dest_path << "'" << std::endl;
                }

                return ReturnIO::pure(); })
              .catch_then([append_failure,
                           item](monad::Error err) -> ReturnIO
                          {
                auto msg =
                    fmt::format("copy item '{}': {}", item.id, err.what);
                append_failure(std::move(msg));
                return ReturnIO::pure(); });
        };

    ReturnIO pipeline = ReturnIO::pure();
    for (const auto &item : config.installs)
    {
      auto item_copy = item;
      pipeline = pipeline.then([process_item, item_copy]() mutable
                               { return process_item(item_copy); });
    }

    return pipeline.then([failure_messages]() -> ReturnIO
                         {
      if (!failure_messages->empty())
      {
        BOOST_LOG_SEV(app_logger(), trivial::trace)
            << "copy actions encountered " << failure_messages->size()
            << " failure(s)";
        std::ostringstream oss;
        oss << "copy actions encountered " << failure_messages->size()
            << " failure(s): ";
        for (std::size_t i = 0; i < failure_messages->size(); ++i)
        {
          if (i != 0)
          {
            oss << ", ";
          }
          oss << failure_messages->at(i);
        }
        oss << ".****** If in linux system, it's most likely permission issue"
               " need to add ReadWritePaths in systemd service file. ******";
        auto err = monad::make_error(my_errors::GENERAL::FILE_READ_WRITE,
                                     oss.str());
        return ReturnIO::fail(std::move(err));
      }

      BOOST_LOG_SEV(app_logger(), trivial::trace)
          << "copy actions completed successfully with no failures";
      return ReturnIO::pure();
    }).catch_then([](monad::Error err) -> ReturnIO
                  {
      BOOST_LOG_SEV(app_logger(), trivial::error)
          << "copy actions pipeline failed code=" << err.code
          << " status=" << err.response_status
          << " what=" << err.what
          << " params=" << boost::json::serialize(err.params);
      return ReturnIO::fail(std::move(err));
    });
  }
  catch (const std::exception &e)
  {
    BOOST_LOG_SEV(app_logger(), trivial::error)
        << "CopyActionHandler::apply caught exception: " << e.what();
    return ReturnIO::fail(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT, e.what()));
  }
}

} // namespace certctrl::install_actions
