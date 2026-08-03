#pragma once

#include <functional>
#include <memory>

#include <boost/asio/awaitable.hpp>

#include "data/install_config_dto.hpp"
#include "result_monad.hpp"

namespace certctrl::install_actions {

class IResourceMaterializer {
public:
  using Ptr = std::shared_ptr<IResourceMaterializer>;
  using Factory = std::function<Ptr()>;

  virtual ~IResourceMaterializer() = default;
  virtual boost::asio::awaitable<monad::MyResult<void>>
  ensure_materialized(const dto::InstallItem &item) = 0;
};

} // namespace certctrl::install_actions
