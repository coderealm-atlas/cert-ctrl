#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "io_monad.hpp"

namespace certctrl::install_actions {

// Lifetime: created on demand for each apply_import_ca_actions call. Captured
// by value in the async chain and destroyed once that pipeline completes.
class ImportCaActionHandler {
public:
    using Factory = std::function<std::unique_ptr<ImportCaActionHandler>()>;

    ImportCaActionHandler(std::filesystem::path runtime_dir,
                                                customio::ConsoleOutput &output,
                                                IResourceMaterializer::Ptr resource_materializer);

    monad::IO<void> apply(const dto::DeviceInstallConfigDto &config,
                                                const std::optional<std::string> &target_ob_type,
                                                std::optional<std::int64_t> target_ob_id);

private:
    std::filesystem::path runtime_dir_;
    customio::ConsoleOutput &output_;
    IResourceMaterializer::Ptr resource_materializer_;
};

} // namespace certctrl::install_actions
