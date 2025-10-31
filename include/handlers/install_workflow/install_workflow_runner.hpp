#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "customio/console_output.hpp"
#include "handlers/install_config_manager.hpp"
#include "io_monad.hpp"

namespace certctrl {


// Lifetime: provided by DI as a singleton shared_ptr (matching the
// InstallConfigManager singleton). May also be constructed manually in tests.
// Instances rely on shared_from_this when launching async workflows, so ensure
// they are always managed by std::shared_ptr.
class InstallWorkflowRunner {
 public:
  struct Options {
    std::optional<std::string> target_ob_type;
    std::optional<std::int64_t> target_ob_id;
  };

  InstallWorkflowRunner(std::unique_ptr<InstallConfigManager> manager,
                        customio::ConsoleOutput& output);

  monad::IO<void> start(const Options& options = Options{});

 private:
  std::unique_ptr<InstallConfigManager> manager_;
  customio::ConsoleOutput& output_;
};

}  // namespace certctrl
