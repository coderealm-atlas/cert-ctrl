#pragma once

#include <filesystem>
#include <memory>

#include "customio/console_output.hpp"
#include "install_config_manager_test_utils.hpp"
#include "test_config_utils.hpp"

struct InstallManagerDiHarness {
  InstallManagerDiHarness(
      std::filesystem::path config_dir, std::filesystem::path runtime_dir,
      std::string base_url,
      certctrl::install_actions::IDeviceInstallConfigFetcher &fetcher,
      certctrl::install_actions::IResourceFetcher &resource_fetcher,
      int http_threads = 1) {
    config_dir_ = std::move(config_dir);
    runtime_dir_ = std::move(runtime_dir);

    testinfra::ConfigFileOptions cfg_opts;
    cfg_opts.base_url = base_url;
    cfg_opts.runtime_dir = runtime_dir_;
    cfg_opts.http_threads = http_threads;
    cfg_opts.ioc_name = "install-config-test-ioc";
    cfg_opts.ioc_threads = 1;
    testinfra::write_basic_config_files(config_dir_, cfg_opts);

    config_sources_holder_ =
        testinfra::make_config_sources({config_dir_}, {});
    config_sources_ = config_sources_holder_.get();

    auto injector = di::make_injector(
        testinfra::build_base_injector(*config_sources_),
        di::bind<certctrl::install_actions::IDeviceInstallConfigFetcher>.to(
            fetcher),
        di::bind<certctrl::install_actions::IResourceFetcher>.to(
            resource_fetcher));

    auto inj_holder = std::make_shared<decltype(injector)>(std::move(injector));
    injector_holder_ = inj_holder;
    auto &inj = *inj_holder;

    output_ = &inj.create<customio::ConsoleOutput &>();
    config_provider_ = &inj.create<certctrl::ICertctrlConfigProvider &>();
    io_context_manager_ = &inj.create<cjj365::IoContextManager &>();
    http_client_manager_ = &inj.create<client_async::HttpClientManager &>();
    install_manager_ = &inj.create<certctrl::InstallConfigManager &>();
    import_ca_handler_factory =
        inj.create<certctrl::install_actions::ImportCaActionHandler::Factory>();
    resource_factory =
        inj.create<certctrl::install_actions::IResourceMaterializer::Factory>();
    exec_env_factory = inj.create<
        certctrl::install_actions::IExecEnvironmentResolver::Factory>();
    copy_action_handler_factory =
        inj.create<certctrl::install_actions::CopyActionHandler::Factory>();
    exec_action_handler_factory =
        inj.create<certctrl::install_actions::ExecActionHandler::Factory>();
  }

  ~InstallManagerDiHarness() {
    if (io_context_manager_) {
      io_context_manager_->stop();
    }
    if (http_client_manager_) {
      http_client_manager_->stop();
    }
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
  std::filesystem::path config_dir_{};
  std::filesystem::path runtime_dir_{};
  customio::ConsoleOutput *output_{nullptr};
  std::shared_ptr<certctrl::CliCtx> cli_ctx_{};
  std::unique_ptr<cjj365::ConfigSources> config_sources_holder_{};
  cjj365::ConfigSources *config_sources_{nullptr};
  std::shared_ptr<void> injector_holder_{};
  certctrl::ICertctrlConfigProvider *config_provider_{nullptr};
  cjj365::IoContextManager *io_context_manager_{nullptr};
  client_async::HttpClientManager *http_client_manager_{nullptr};
  certctrl::InstallConfigManager *install_manager_{nullptr};
  bool cleanup_config_{true};
  bool cleanup_runtime_{true};
};
