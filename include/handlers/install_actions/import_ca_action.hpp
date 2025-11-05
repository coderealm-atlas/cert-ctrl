#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "io_monad.hpp"

namespace certctrl::install_actions {

// Lifetime: created on demand for each apply_import_ca_actions call. Captured
// by value in the async chain and destroyed once that pipeline completes.
class ImportCaActionHandler: public std::enable_shared_from_this<ImportCaActionHandler> {
public:
  using Factory = std::function<std::shared_ptr<ImportCaActionHandler>()>;

  ImportCaActionHandler(
      certctrl::ICertctrlConfigProvider &config_provider,
      customio::ConsoleOutput &output,
    install_actions::IResourceMaterializer::Factory resource_materializer_factory);

  monad::IO<void> apply(const dto::DeviceInstallConfigDto &config,
                        const std::optional<std::string> &target_ob_type,
                        std::optional<std::int64_t> target_ob_id);

private:
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  std::filesystem::path runtime_dir_;
  install_actions::IResourceMaterializer::Factory resource_materializer_factory_;
  monad::IO<void>
  process_one_item(const dto::InstallItem &item,
                   const std::optional<std::string> &target_ob_type,
                   std::optional<std::int64_t> target_ob_id);
  install_actions::IResourceMaterializer::Ptr resource_materializer_;
};

#if defined(__APPLE__)
namespace detail {
struct MacTrustStoreProbe {
  std::filesystem::path directory;
  std::string update_command;
  bool uses_native_import;
};

std::optional<MacTrustStoreProbe> detect_mac_trust_store_for_test();
} // namespace detail
#endif

} // namespace certctrl::install_actions
