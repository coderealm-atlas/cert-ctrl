#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <unordered_map>

#include <boost/program_options.hpp>

#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/function_adapters.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "handlers/install_actions/install_resource_materializer.hpp"
#include "handlers/install_actions/materialize_password_manager.hpp"
#include "handlers/install_config_manager.hpp"
#include "handlers/session_refresher.hpp"
#include "install_config_manager_test_utils.hpp"
#include "certctrl_common.hpp"
#include "state/device_state_store.hpp"
#include "test_config_utils.hpp"

struct InstallManagerDiHarness {
  InstallManagerDiHarness(
      std::filesystem::path config_dir, std::filesystem::path runtime_dir,
      std::string base_url,
      certctrl::install_actions::IDeviceInstallConfigFetcher &fetcher,
      certctrl::install_actions::IResourceFetcher &resource_fetcher,
      int http_threads = 1,
      certctrl::install_actions::IAccessTokenLoader *token_loader_override =
          nullptr) {
    config_dir_ = std::move(config_dir);
    runtime_dir_ = std::move(runtime_dir);

    fetcher_ = &fetcher;
    resource_fetcher_ = &resource_fetcher;

    testinfra::ConfigFileOptions cfg_opts;
    cfg_opts.base_url = base_url;
    cfg_opts.runtime_dir = runtime_dir_;
    cfg_opts.http_threads = http_threads;
    cfg_opts.ioc_name = "install-config-test-ioc";
    cfg_opts.ioc_threads = 1;
    testinfra::write_basic_config_files(config_dir_, cfg_opts);

    config_sources_holder_ = testinfra::make_config_sources({config_dir_}, {});
    config_sources_ = config_sources_holder_.get();

    // SessionRefresher depends on CliCtx; provide a minimal default for tests
    // that don't care about CLI options.
    certctrl::CliParams cli_params{};
    cli_params.subcmd = "install";
    cli_params.config_dirs = {config_dir_};
    cli_ctx_storage_ = std::make_unique<certctrl::CliCtx>(
      boost::program_options::variables_map{}, std::vector<std::string>{},
      std::vector<std::string>{}, std::move(cli_params));

    auto injector = di::make_injector(
      testinfra::build_base_injector(*config_sources_),
      di::bind<certctrl::CliCtx>().to(*cli_ctx_storage_),
      di::bind<certctrl::install_actions::IDeviceInstallConfigFetcher>.to(
        fetcher),
      di::bind<certctrl::install_actions::IResourceFetcher>.to(
        resource_fetcher));

    auto inj_holder = std::make_shared<decltype(injector)>(std::move(injector));
    injector_holder_ = inj_holder;
    auto &inj = *inj_holder;

    output_ = &inj.create<customio::ConsoleOutput &>();
    auto config_provider_impl =
        inj.create<std::unique_ptr<certctrl::CertctrlConfigProviderFile>>();
    config_provider_owner_ = std::unique_ptr<certctrl::ICertctrlConfigProvider>(
        std::move(config_provider_impl));
    config_provider_ = config_provider_owner_.get();

    io_context_manager_owner_ =
        inj.create<std::unique_ptr<cjj365::IoContextManager>>();
    io_context_manager_ = io_context_manager_owner_.get();

    http_client_manager_owner_ =
        inj.create<std::unique_ptr<client_async::HttpClientManager>>();
    http_client_manager_ = http_client_manager_owner_.get();

    session_refresher_ =
      inj.create<std::shared_ptr<certctrl::ISessionRefresher>>();
    state_store_ = &inj.create<certctrl::IDeviceStateStore &>();

    if (token_loader_override) {
      token_loader_ = token_loader_override;
    } else {
      auto token_loader_impl = inj.create<
          std::unique_ptr<certctrl::install_actions::AccessTokenLoaderFile>>();
      token_loader_owner_ =
          std::unique_ptr<certctrl::install_actions::IAccessTokenLoader>(
              std::move(token_loader_impl));
      token_loader_ = token_loader_owner_.get();
    }

    password_manager_owner_ = std::make_unique<
        certctrl::install_actions::MaterializePasswordManager>();
    password_manager_ = password_manager_owner_.get();

    resource_factory = make_resource_factory();
    exec_env_factory = make_exec_env_factory();
    import_ca_handler_factory = make_import_factory();
    copy_action_handler_factory = make_copy_factory();
    exec_action_handler_factory = make_exec_factory();

    install_manager_storage_ = std::make_unique<certctrl::InstallConfigManager>(
        *io_context_manager_, *config_provider_, *output_,
        *http_client_manager_, resource_factory, import_ca_handler_factory,
        exec_action_handler_factory, copy_action_handler_factory,
      exec_env_factory, *fetcher_, *token_loader_, *password_manager_,
      session_refresher_);
    install_manager_ = install_manager_storage_.get();
  }

  ~InstallManagerDiHarness() {
    install_manager_storage_.reset();
    if (io_context_manager_) {
      io_context_manager_->stop();
    }
    if (http_client_manager_) {
      http_client_manager_->stop();
    }
    token_loader_owner_.reset();
    http_client_manager_owner_.reset();
    io_context_manager_owner_.reset();
    config_provider_owner_.reset();
    state_store_ = nullptr;
    cjj365::ConfigSources::instance_count.store(0);
    std::error_code ec;
    if (cleanup_config_) {
      std::filesystem::remove_all(config_dir_, ec);
    }
    if (cleanup_runtime_) {
      std::filesystem::remove_all(runtime_dir_, ec);
    }
  }

  certctrl::ICertctrlConfigProvider &config_provider() {
    return *config_provider_;
  }

  certctrl::IDeviceStateStore &state_store() { return *state_store_; }

  customio::ConsoleOutput &output() { return *output_; }

  cjj365::IoContextManager &io_context_manager() {
    return *io_context_manager_;
  }

  client_async::HttpClientManager &http_client_manager() {
    return *http_client_manager_;
  }

  certctrl::InstallConfigManager &install_manager() {
    return *install_manager_;
  }

  const std::filesystem::path &runtime_dir() const { return runtime_dir_; }

  certctrl::install_actions::ImportCaActionHandler::Factory
      import_ca_handler_factory;
  certctrl::install_actions::IResourceMaterializer::Factory resource_factory;
  certctrl::install_actions::IExecEnvironmentResolver::Factory exec_env_factory;
  certctrl::install_actions::CopyActionHandler::Factory
      copy_action_handler_factory;
  certctrl::install_actions::ExecActionHandler::Factory
      exec_action_handler_factory;

  void disable_runtime_cleanup() { cleanup_runtime_ = false; }

private:
  std::unique_ptr<certctrl::CliCtx> cli_ctx_storage_;
  certctrl::install_actions::IResourceMaterializer::Factory
  make_resource_factory() {
    return certctrl::install_actions::IResourceMaterializer::Factory([this]() {
      return std::make_shared<
          certctrl::install_actions::InstallResourceMaterializer>(
          *io_context_manager_, *config_provider_, *output_, *resource_fetcher_,
          *http_client_manager_, *token_loader_, *password_manager_,
          session_refresher_);
    });
  }

  certctrl::install_actions::IExecEnvironmentResolver::Factory
  make_exec_env_factory() {
    using Resolver = certctrl::install_actions::FunctionExecEnvironmentResolver;
    return certctrl::install_actions::IExecEnvironmentResolver::Factory([]() {
      return std::make_shared<Resolver>(
          [](const dto::InstallItem &)
              -> std::optional<std::unordered_map<std::string, std::string>> {
            return std::nullopt;
          });
    });
  }

  certctrl::install_actions::ImportCaActionHandler::Factory
  make_import_factory() {
    auto resource_factory_copy = resource_factory;
    return certctrl::install_actions::ImportCaActionHandler::Factory(
        [this, resource_factory_copy]() {
          return std::make_shared<
              certctrl::install_actions::ImportCaActionHandler>(
              *config_provider_, *output_, resource_factory_copy);
        });
  }

  certctrl::install_actions::CopyActionHandler::Factory make_copy_factory() {
    auto resource_factory_copy = resource_factory;
    return certctrl::install_actions::CopyActionHandler::Factory(
        [this, resource_factory_copy]() {
          return std::make_shared<certctrl::install_actions::CopyActionHandler>(
              *config_provider_, *output_, resource_factory_copy);
        });
  }

  certctrl::install_actions::ExecActionHandler::Factory make_exec_factory() {
    auto resource_factory_copy = resource_factory;
    auto exec_env_factory_copy = exec_env_factory;
    return certctrl::install_actions::ExecActionHandler::Factory(
        [this, resource_factory_copy, exec_env_factory_copy]() {
          return std::make_shared<certctrl::install_actions::ExecActionHandler>(
              *config_provider_, *output_, resource_factory_copy,
              exec_env_factory_copy);
        });
  }

  std::filesystem::path config_dir_{};
  std::filesystem::path runtime_dir_{};
  customio::ConsoleOutput *output_{nullptr};
  std::unique_ptr<cjj365::ConfigSources> config_sources_holder_{};
  cjj365::ConfigSources *config_sources_{nullptr};
  std::shared_ptr<void> injector_holder_{};
  certctrl::ICertctrlConfigProvider *config_provider_{nullptr};
  cjj365::IoContextManager *io_context_manager_{nullptr};
  client_async::HttpClientManager *http_client_manager_{nullptr};
  certctrl::IDeviceStateStore *state_store_{nullptr};
  std::unique_ptr<certctrl::ICertctrlConfigProvider> config_provider_owner_{};
  std::unique_ptr<cjj365::IoContextManager> io_context_manager_owner_{};
  std::unique_ptr<client_async::HttpClientManager> http_client_manager_owner_{};
  std::shared_ptr<certctrl::ISessionRefresher> session_refresher_{};
  std::unique_ptr<certctrl::install_actions::IAccessTokenLoader>
      token_loader_owner_{};
  std::unique_ptr<certctrl::install_actions::MaterializePasswordManager>
      password_manager_owner_{};
  certctrl::install_actions::IMaterializePasswordManager *password_manager_{};
  certctrl::InstallConfigManager *install_manager_{nullptr};
  certctrl::install_actions::IDeviceInstallConfigFetcher *fetcher_{nullptr};
  certctrl::install_actions::IResourceFetcher *resource_fetcher_{nullptr};
  certctrl::install_actions::IAccessTokenLoader *token_loader_{nullptr};
  std::unique_ptr<certctrl::InstallConfigManager> install_manager_storage_{};
  bool cleanup_config_{true};
  bool cleanup_runtime_{true};
};
