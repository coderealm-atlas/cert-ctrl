#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/exec_environment_resolver.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "io_monad.hpp"

namespace certctrl::install_actions {

// Lifetime: instantiated by InstallConfigManager when exec steps are required
// after copy/import phases. Intended to be short-lived and scoped to a single
// pipeline execution.
class ExecActionHandler
    : public std::enable_shared_from_this<ExecActionHandler> {
public:
  using Factory = std::function<std::shared_ptr<ExecActionHandler>()>;

  ExecActionHandler(
      certctrl::ICertctrlConfigProvider &config_provider,
      customio::ConsoleOutput &output,
      IResourceMaterializer::Factory resource_materializer_factory,
      IExecEnvironmentResolver::Factory exec_env_resolver_factory);

  // void customize(std::filesystem::path runtime_dir,
  //                IResourceMaterializer::Factory
  //                resource_materializer_factory,
  //                IExecEnvironmentResolver::Factory
  //                exec_env_resolver_factory);

  monad::IO<void>
  apply(const dto::DeviceInstallConfigDto &config,
        std::optional<std::vector<std::string>> allowed_types = std::nullopt);

private:
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  std::filesystem::path runtime_dir_;
  // bool is_customized_{false};
  IResourceMaterializer::Factory resource_materializer_factory_;
  IExecEnvironmentResolver::Factory exec_env_resolver_factory_;
  IResourceMaterializer::Ptr resource_materializer_;
  IExecEnvironmentResolver::Ptr exec_env_resolver_;
  std::vector<std::string> failure_messages_;

  monad::IO<void> process_one_item(const dto::InstallItem &item);
};

} // namespace certctrl::install_actions
