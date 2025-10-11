#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/data_shape.hpp"
#include "data/install_config_dto.hpp"
#include "http_client_manager.hpp"
#include "io_monad.hpp"

namespace certctrl {

class InstallConfigManager {
public:
  using FetchOverrideFn = std::function<
      monad::IO<dto::DeviceInstallConfigDto>(
          std::optional<std::int64_t> expected_version,
          const std::optional<std::string> &expected_hash)>;

  using ResourceFetchOverrideFn =
    std::function<std::optional<std::string>(const dto::InstallItem &item)>;

  InstallConfigManager(
      const std::filesystem::path &runtime_dir,
      certctrl::ICertctrlConfigProvider &config_provider,
      customio::ConsoleOutput &output,
    client_async::HttpClientManager *http_client,
    FetchOverrideFn fetch_override = nullptr,
    ResourceFetchOverrideFn resource_fetch_override = nullptr);

  const std::filesystem::path &runtime_dir() const { return runtime_dir_; }

  std::optional<std::int64_t> local_version() const { return local_version_; }

  monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
  ensure_config_version(std::optional<std::int64_t> expected_version,
                        const std::optional<std::string> &expected_hash);

  monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
  ensure_cached_config();

  monad::IO<void> apply_copy_actions(
      const dto::DeviceInstallConfigDto &config,
      const std::optional<std::string> &target_ob_type,
      std::optional<std::int64_t> target_ob_id);

  monad::IO<void> apply_import_ca_actions(
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id);

  monad::IO<void> apply_copy_actions_for_signal(
    const ::data::DeviceUpdateSignal &signal);

  void clear_cache();

private:
  monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
  refresh_from_remote(std::optional<std::int64_t> expected_version,
                      const std::optional<std::string> &expected_hash);

  std::optional<dto::DeviceInstallConfigDto> load_from_disk();

  monad::IO<void> persist_config(const dto::DeviceInstallConfigDto &config);

  std::optional<std::string> load_access_token() const;

  std::filesystem::path state_dir() const;
  std::filesystem::path config_file_path() const;
  std::filesystem::path version_file_path() const;
  std::filesystem::path resource_current_dir(const std::string &ob_type,
                                             std::int64_t ob_id) const;

  std::optional<monad::Error>
  ensure_resource_materialized_sync(const dto::InstallItem &item);

private:
  std::filesystem::path runtime_dir_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager *http_client_{nullptr};
  FetchOverrideFn fetch_override_;
  ResourceFetchOverrideFn resource_fetch_override_;

  std::shared_ptr<dto::DeviceInstallConfigDto> cached_config_;
  std::optional<std::int64_t> local_version_;
  mutable std::optional<std::string> cached_access_token_;
  mutable std::optional<std::filesystem::file_time_type>
      cached_access_token_mtime_;
};

} // namespace certctrl
