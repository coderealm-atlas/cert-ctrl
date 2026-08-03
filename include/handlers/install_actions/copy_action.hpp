#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <boost/asio/awaitable.hpp>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "result_monad.hpp"

namespace certctrl::install_actions {

class CopyActionHandler
    : public std::enable_shared_from_this<CopyActionHandler> {
public:
  using Factory = std::function<std::shared_ptr<CopyActionHandler>()>;

  CopyActionHandler(
      certctrl::ICertctrlConfigProvider &config_provider,
      customio::ConsoleOutput &output,
      IResourceMaterializer::Factory resource_materializer_factory);

  boost::asio::awaitable<monad::MyResult<void>>
  apply(const dto::DeviceInstallConfigDto &config,
        const std::optional<std::string> &target_ob_type,
        std::optional<std::int64_t> target_ob_id);

private:
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  std::filesystem::path runtime_dir_;
  IResourceMaterializer::Factory resource_materializer_factory_;
  IResourceMaterializer::Ptr resource_materializer_;
  std::vector<std::string> failure_messages_;
  boost::asio::awaitable<monad::MyResult<void>>
  process_one_item(const dto::InstallItem &item,
                   IResourceMaterializer::Ptr resource_materializer,
                   const std::optional<std::string> &target_ob_type,
                   std::optional<std::int64_t> target_ob_id);
};

} // namespace certctrl::install_actions
