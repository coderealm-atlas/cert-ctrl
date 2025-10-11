#pragma once

#include <optional>
#include <string>

#include "handlers/install_actions/install_action_context.hpp"

namespace certctrl::install_actions {

monad::IO<void> apply_copy_actions(
    const InstallActionContext &context,
    const dto::DeviceInstallConfigDto &config,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id);

} // namespace certctrl::install_actions
