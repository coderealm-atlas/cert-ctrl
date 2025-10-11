#pragma once

#include <filesystem>
#include <functional>
#include <optional>

#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "io_monad.hpp"

namespace certctrl::install_actions {

struct InstallActionContext {
  std::filesystem::path runtime_dir;
  customio::ConsoleOutput &output;
  std::function<std::optional<monad::Error>(const dto::InstallItem &item)>
      ensure_resource_materialized;
};

} // namespace certctrl::install_actions
