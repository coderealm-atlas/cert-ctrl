#pragma once

#include <functional>
#include <memory>

#include "data/install_config_dto.hpp"
#include "io_monad.hpp"

namespace certctrl::install_actions {

class IResourceMaterializer {
public:
  using Ptr = std::shared_ptr<IResourceMaterializer>;
  using Factory = std::function<Ptr()>;

  virtual ~IResourceMaterializer() = default;
  virtual monad::IO<void> ensure_materialized(const dto::InstallItem &item) = 0;
};

} // namespace certctrl::install_actions
