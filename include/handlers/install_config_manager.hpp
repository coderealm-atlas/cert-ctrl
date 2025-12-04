#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/data_shape.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/exec_environment_resolver.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "handlers/install_actions/install_resource_materializer.hpp"
#include "handlers/install_actions/materialize_password_manager.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "handlers/session_refresher.hpp"
#include "http_client_manager.hpp"
#include "install_config_fetcher.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "resource_fetcher.hpp"
#include "util/my_logging.hpp"

namespace certctrl {

// Lifetime: usually injected as a Boost.DI singleton within the App injector.
// InstallConfigHandler may also create a per-handler shared_ptr instance.
// Ensure the instance outlives any async monad pipelines started from its
// member functions, as they capture `this` directly.
class InstallConfigManager {
public:
  InstallConfigManager(
      cjj365::IoContextManager &io_context_manager,       //
      certctrl::ICertctrlConfigProvider &config_provider, //
      customio::ConsoleOutput &output,                    //
      client_async::HttpClientManager &http_client,       //
      install_actions::IResourceMaterializer::Factory
          resource_materializer_factory,
      install_actions::ImportCaActionHandler::Factory
          import_ca_action_handler_factory,
      install_actions::ExecActionHandler::Factory exec_handler_factory,
      certctrl::install_actions::CopyActionHandler::Factory
          copy_handler_factory,
      install_actions::IExecEnvironmentResolver::Factory
          exec_env_resolver_factory,
      install_actions::IDeviceInstallConfigFetcher &config_fetcher,
      install_actions::IAccessTokenLoader &access_token_loader,
    install_actions::IMaterializePasswordManager &password_manager,
    std::shared_ptr<ISessionRefresher> session_refresher);

  ~InstallConfigManager();

  const std::filesystem::path &runtime_dir() const { return runtime_dir_; }

  std::optional<std::int64_t> local_version() const { return local_version_; }

  monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
  ensure_config_version(std::optional<std::int64_t> expected_version,
                        const std::optional<std::string> &expected_hash);

  monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
  ensure_cached_config();

  monad::IO<void>
  apply_copy_actions(const dto::DeviceInstallConfigDto &config,
                     const std::optional<std::string> &target_ob_type,
                     std::optional<std::int64_t> target_ob_id);

  monad::IO<void>
  apply_import_ca_actions(const dto::DeviceInstallConfigDto &config,
                          const std::optional<std::string> &target_ob_type,
                          std::optional<std::int64_t> target_ob_id);

  monad::IO<void>
  apply_copy_actions_for_signal(const ::data::DeviceUpdateSignal &signal);

  monad::IO<void> handle_ca_assignment(
      std::int64_t ca_id, std::optional<std::string> ca_name);
    monad::IO<void> handle_ca_unassignment(
      std::int64_t ca_id, std::optional<std::string> ca_name);

  std::shared_ptr<dto::DeviceInstallConfigDto> cached_config_snapshot();

  void clear_cache();
    void invalidate_all_caches();
    void invalidate_resource_cache(const std::string &ob_type,
                     std::int64_t ob_id);

private:
  monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
  refresh_from_remote(std::optional<std::int64_t> expected_version,
                      const std::optional<std::string> &expected_hash);

  monad::IO<std::shared_ptr<const dto::DeviceInstallConfigDto>>
  refresh_from_remote_with_retry(
      std::optional<std::int64_t> expected_version,
      const std::optional<std::string> &expected_hash, bool attempted_refresh);

  std::optional<dto::DeviceInstallConfigDto> load_from_disk();

  monad::IO<void> persist_config(const dto::DeviceInstallConfigDto &config);

  //   std::optional<std::string> load_access_token() const;

  std::filesystem::path state_dir() const;
  std::filesystem::path config_file_path() const;
  std::filesystem::path version_file_path() const;
  std::filesystem::path resource_current_dir(const std::string &ob_type,
                                             std::int64_t ob_id) const;
    void remove_cached_resource_scope(const std::filesystem::path &root);
    void remove_file_quiet(const std::filesystem::path &file_path);

  std::optional<std::unordered_map<std::string, std::string>>
  resolve_exec_env_for_item(const dto::InstallItem &item);

private:
  std::filesystem::path runtime_dir_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;
  install_actions::IDeviceInstallConfigFetcher &config_fetcher_;
  certctrl::install_actions::ImportCaActionHandler::Factory
      import_ca_action_handler_factory_;

  std::shared_ptr<dto::DeviceInstallConfigDto> cached_config_;
  std::optional<std::int64_t> local_version_;
  logsrc::severity_logger<trivial::severity_level> lg;

  install_actions::IResourceMaterializer::Factory
      resource_materializer_factory_;
  install_actions::ExecActionHandler::Factory exec_handler_factory_;
  install_actions::IExecEnvironmentResolver::Factory exec_env_resolver_factory_;
  certctrl::install_actions::CopyActionHandler::Factory copy_handler_factory_;
  boost::asio::io_context &io_context_;
  install_actions::IAccessTokenLoader &access_token_loader_;
  install_actions::IMaterializePasswordManager &password_manager_;
    std::shared_ptr<ISessionRefresher> session_refresher_;
};

} // namespace certctrl
