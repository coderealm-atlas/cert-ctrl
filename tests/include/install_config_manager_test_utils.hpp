#pragma once

#include "boost/di.hpp"
#include "conf/certctrl_config.hpp"
#include "handlers/install_actions/copy_action.hpp"
#include "handlers/install_actions/exec_action.hpp"
#include "handlers/install_actions/function_adapters.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "handlers/install_actions/install_resource_materializer.hpp"
#include "http_client_config_provider.hpp"
#include "io_context_manager.hpp"
#include "log_stream.hpp"

namespace di = boost::di;

namespace testinfra {

inline customio::ConsoleOutputWithColor &shared_output() {
  static customio::ConsoleOutputWithColor out(5);
  return out;
}

// Base injector for handler/service integration tests
inline auto build_base_injector(cjj365::ConfigSources &config_sources) {
  return di::make_injector(
      di::bind<cjj365::ConfigSources>().to(config_sources),
      di::bind<customio::IOutput>().to(shared_output()),
      di::bind<cjj365::IHttpclientConfigProvider>()
          .to<cjj365::HttpclientConfigProviderFile>(),
      di::bind<cjj365::IIocConfigProvider>()
          .to<cjj365::IocConfigProviderFile>(),
      di::bind<certctrl::ICertctrlConfigProvider>()
          .to<certctrl::CertctrlConfigProviderFile>()
          .in(di::singleton),

      di::bind<certctrl::install_actions::InstallResourceMaterializer>().in(
          di::unique),
      di::bind<certctrl::install_actions::IResourceMaterializer::Factory>().to(
          [](const auto &inj) {
            return certctrl::install_actions::IResourceMaterializer::Factory{
                [&inj]() {
                  return inj.template create<
                      std::shared_ptr<certctrl::install_actions::
                                          InstallResourceMaterializer>>();
                }};
          }),
      di::bind<certctrl::install_actions::CopyActionHandler>().in(di::unique),
      di::bind<certctrl::install_actions::CopyActionHandler::Factory>().to(
          [](const auto &inj) {
            return certctrl::install_actions::CopyActionHandler::Factory{
                [&inj]() {
                  return inj.template create<std::shared_ptr<
                      certctrl::install_actions::CopyActionHandler>>();
                }};
          }),
      di::bind<certctrl::install_actions::IExecEnvironmentResolver::Factory>()
          .to([](const auto &inj) {
            return certctrl::install_actions::IExecEnvironmentResolver::Factory{
                [&inj]() {
                  return inj.template create<
                      std::shared_ptr<certctrl::install_actions::
                                          FunctionExecEnvironmentResolver>>();
                }};
          }),
      di::bind<certctrl::install_actions::ExecActionHandler>().in(di::unique),
      di::bind<certctrl::install_actions::ExecActionHandler::Factory>().to(
          [](const auto &inj) {
            return certctrl::install_actions::ExecActionHandler::Factory{
                [&inj]() {
                  return inj.template create<std::shared_ptr<
                      certctrl::install_actions::ExecActionHandler>>();
                }};
          }),
      di::bind<certctrl::install_actions::ImportCaActionHandler>().in(
          di::unique),
      di::bind<certctrl::install_actions::ImportCaActionHandler::Factory>().to(
          [](const auto &inj) {
            return certctrl::install_actions::ImportCaActionHandler::Factory{
                [&inj]() {
                  return inj.template create<std::shared_ptr<
                      certctrl::install_actions::ImportCaActionHandler>>();
                }};
          }),
      di::bind<cjj365::IIoContextManager>().to<cjj365::IoContextManager>().in(
          di::singleton));
}

// Mock session alias for convenience
// using MockSession = httphandler::MockHttpSession;

} // namespace testinfra
