#pragma once

#include <memory>

#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/exec_environment_resolver.hpp"
#include "handlers/install_actions/function_adapters.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "io_monad.hpp"

namespace certctrl::test_utils {

inline certctrl::install_actions::IResourceMaterializer::Factory
make_fixed_resource_factory(
    certctrl::install_actions::IResourceMaterializer::Ptr materializer) {
  return certctrl::install_actions::IResourceMaterializer::Factory{
      [materializer]() { return materializer; }};
}

inline certctrl::install_actions::IResourceMaterializer::Factory
make_default_resource_factory() {
  using certctrl::install_actions::FunctionResourceMaterializer;
  return certctrl::install_actions::IResourceMaterializer::Factory{[]() {
    return std::make_shared<FunctionResourceMaterializer>(
        [](const dto::InstallItem &) -> monad::IO<void> {
          return monad::IO<void>::pure();
        });
  }};
}

inline certctrl::install_actions::IExecEnvironmentResolver::Factory
make_default_exec_env_factory() {
  return certctrl::install_actions::IExecEnvironmentResolver::Factory{[]() {
    return certctrl::install_actions::IExecEnvironmentResolver::Ptr{};
  }};
}

inline certctrl::install_actions::ImportCaActionHandler::Factory
make_import_ca_handler_factory(
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    certctrl::install_actions::IResourceMaterializer::Factory
        resource_materializer_factory) {
  return certctrl::install_actions::ImportCaActionHandler::Factory{
      [&config_provider, &output, resource_materializer_factory]() {
        return std::make_shared<
            certctrl::install_actions::ImportCaActionHandler>(
            config_provider, output, resource_materializer_factory);
      }};
}

inline certctrl::install_actions::ExecActionHandler::Factory
make_exec_action_handler_factory(
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    certctrl::install_actions::IResourceMaterializer::Factory
        resource_materializer_factory,
    certctrl::install_actions::IExecEnvironmentResolver::Factory
        exec_env_resolver_factory) {
  return certctrl::install_actions::ExecActionHandler::Factory{
      [&config_provider, &output, resource_materializer_factory,
       exec_env_resolver_factory]() {
        return std::make_shared<certctrl::install_actions::ExecActionHandler>(
            config_provider, output, resource_materializer_factory,
            exec_env_resolver_factory);
      }};
}

struct InstallManagerFactories {
  certctrl::install_actions::IResourceMaterializer::Factory
      resource_materializer_factory;
  certctrl::install_actions::ImportCaActionHandler::Factory
      import_ca_handler_factory;
  certctrl::install_actions::ExecActionHandler::Factory
      exec_action_handler_factory;
  certctrl::install_actions::IExecEnvironmentResolver::Factory
      exec_env_resolver_factory;
  certctrl::install_actions::CopyActionHandler::Factory
      copy_action_handler_factory;
};

inline InstallManagerFactories make_default_install_manager_factories(
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    certctrl::install_actions::IResourceMaterializer::Factory
        resource_materializer_factory = {},
    certctrl::install_actions::IExecEnvironmentResolver::Factory
        exec_env_resolver_factory = {}) {
  if (!resource_materializer_factory) {
    resource_materializer_factory = make_default_resource_factory();
  }
  if (!exec_env_resolver_factory) {
    exec_env_resolver_factory = make_default_exec_env_factory();
  }
  auto import_factory = make_import_ca_handler_factory(
      config_provider, output, resource_materializer_factory);
  auto exec_factory = make_exec_action_handler_factory(
      config_provider, output, resource_materializer_factory,
      exec_env_resolver_factory);
  auto copy_factory = certctrl::install_actions::CopyActionHandler::Factory{
      [&config_provider, &output, resource_materializer_factory]() {
        return std::make_shared<certctrl::install_actions::CopyActionHandler>(
            config_provider, output, resource_materializer_factory);
      }};
  return {resource_materializer_factory, import_factory, exec_factory,
          exec_env_resolver_factory, copy_factory};
}

} // namespace certctrl::test_utils
