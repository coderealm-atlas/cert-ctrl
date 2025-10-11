#pragma once

#include <optional>
#include <string>
#include <vector>

#include "handlers/install_actions/install_action_context.hpp"

namespace certctrl::install_actions {

monad::IO<void> apply_exec_actions(
    const InstallActionContext &context,
    const dto::DeviceInstallConfigDto &config,
    std::optional<std::vector<std::string>> allowed_types = std::nullopt);

} // namespace certctrl::install_actions
