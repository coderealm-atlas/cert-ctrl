#pragma once

#include <optional>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <filesystem>

#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/exec_environment_resolver.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "io_monad.hpp"

namespace certctrl::install_actions {

// Lifetime: instantiated by InstallConfigManager when exec steps are required
// after copy/import phases. Intended to be short-lived and scoped to a single
// pipeline execution.
class ExecActionHandler {
public:
    using Factory = std::function<std::unique_ptr<ExecActionHandler>()>;

    ExecActionHandler(std::filesystem::path runtime_dir,
                      customio::ConsoleOutput &output,
                      IResourceMaterializer::Ptr resource_materializer,
                      IExecEnvironmentResolver::Ptr exec_env_resolver);

    monad::IO<void> apply(const dto::DeviceInstallConfigDto &config,
                          std::optional<std::vector<std::string>> allowed_types =
                              std::nullopt);

private:
    std::filesystem::path runtime_dir_;
    customio::ConsoleOutput &output_;
    IResourceMaterializer::Ptr resource_materializer_;
    IExecEnvironmentResolver::Ptr exec_env_resolver_;
};

} // namespace certctrl::install_actions
