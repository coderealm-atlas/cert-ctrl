#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/data_shape.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/exec_environment_resolver.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "http_client_manager.hpp"
#include "io_monad.hpp"
#include "util/my_logging.hpp"

namespace certctrl {

// Lifetime: usually injected as a Boost.DI singleton within the App injector.
// InstallConfigHandler may also create a per-handler shared_ptr instance.
// Ensure the instance outlives any async monad pipelines started from its
// member functions, as they capture `this` directly.
class InstallConfigManager {
public:
  using FetchOverrideFn = std::function<monad::IO<dto::DeviceInstallConfigDto>(
      std::optional<std::int64_t> expected_version,
      const std::optional<std::string> &expected_hash)>;

  using ResourceFetchOverrideFn =
      std::function<std::optional<std::string>(const dto::InstallItem &item)>;

  InstallConfigManager(
      certctrl::ICertctrlConfigProvider &config_provider, //
      customio::ConsoleOutput &output,                    //
      client_async::HttpClientManager *http_client,       //
      install_actions::IResourceMaterializer::Factory
          resource_materializer_factory, //
      install_actions::ImportCaActionHandler::Factory
          import_ca_action_handler_factory,                             //
      install_actions::ExecActionHandler::Factory exec_handler_factory, //
      certctrl::install_actions::CopyActionHandler::Factory
          copy_handler_factory, //
      install_actions::IExecEnvironmentResolver::Factory
          exec_env_resolver_factory,
      boost::asio::io_context *io_context = nullptr);

  ~InstallConfigManager();

  void customize(std::filesystem::path runtime_dir,
                 FetchOverrideFn fetch_override = nullptr,
                 ResourceFetchOverrideFn resource_fetch_override = nullptr);

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

  std::shared_ptr<dto::DeviceInstallConfigDto> cached_config_snapshot();

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

  //   monad::IO<void> ensure_resource_materialized(const dto::InstallItem
  //   &item);

  //   std::optional<monad::Error>
  //   ensure_resource_materialized_impl(const dto::InstallItem &item);

  std::optional<std::unordered_map<std::string, std::string>>
  resolve_exec_env_for_item(const dto::InstallItem &item);

  std::optional<std::string> lookup_bundle_password(const std::string &ob_type,
                                                    std::int64_t ob_id) const;
  void remember_bundle_password(const std::string &ob_type, std::int64_t ob_id,
                                const std::string &password);
  void forget_bundle_password(const std::string &ob_type, std::int64_t ob_id);

  //   void configure_resource_materializer(
  //       const install_actions::IResourceMaterializer::Ptr &materializer);
  //   install_actions::IResourceMaterializer::Ptr make_resource_materializer();

private:
  std::filesystem::path runtime_dir_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager *http_client_{nullptr};
  FetchOverrideFn fetch_override_;
  ResourceFetchOverrideFn resource_fetch_override_;
  certctrl::install_actions::ImportCaActionHandler::Factory
      import_ca_action_handler_factory_;
  bool customized_{false};

  std::shared_ptr<dto::DeviceInstallConfigDto> cached_config_;
  std::optional<std::int64_t> local_version_;
  mutable std::optional<std::string> cached_access_token_;
  mutable std::optional<std::filesystem::file_time_type>
      cached_access_token_mtime_;
  logsrc::severity_logger<trivial::severity_level> lg;

  std::unordered_map<std::string, std::unordered_map<std::int64_t, std::string>>
      bundle_passwords_;
  install_actions::IResourceMaterializer::Factory
      resource_materializer_factory_;
  install_actions::ExecActionHandler::Factory exec_handler_factory_;
  install_actions::IExecEnvironmentResolver::Factory exec_env_resolver_factory_;
  certctrl::install_actions::CopyActionHandler::Factory copy_handler_factory_;
  boost::asio::io_context *io_context_{nullptr};
  std::unique_ptr<boost::asio::io_context> owned_io_context_;
  std::unique_ptr<
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>
      owned_io_work_guard_;
  std::thread owned_io_thread_;
};

} // namespace certctrl
