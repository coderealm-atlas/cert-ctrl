#include "handlers/install_actions/exec_action.hpp"

namespace certctrl::install_actions {

monad::IO<void> apply_exec_actions(
    const InstallActionContext &/*context*/,
    const dto::DeviceInstallConfigDto &/*config*/,
    std::optional<std::vector<std::string>> /*allowed_types*/) {
  return monad::IO<void>::pure();
}

} // namespace certctrl::install_actions
