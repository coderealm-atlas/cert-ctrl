#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include "data/install_config_dto.hpp"

namespace certctrl::install_actions {

class IExecEnvironmentResolver {
public:
  using Ptr = std::shared_ptr<IExecEnvironmentResolver>;
  using Factory = std::function<Ptr()>;

  virtual ~IExecEnvironmentResolver() = default;
  virtual std::optional<std::unordered_map<std::string, std::string>>
  resolve(const dto::InstallItem &item) = 0;
};

} // namespace certctrl::install_actions
