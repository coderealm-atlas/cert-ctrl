#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "customio/console_output.hpp"
#include "io_monad.hpp"

namespace certctrl {

class InstallConfigManager;

// Lifetime: provided by DI as a singleton shared_ptr (matching the
// InstallConfigManager singleton). May also be constructed manually in tests.
// Instances rely on shared_from_this when launching async workflows, so ensure
// they are always managed by std::shared_ptr.
class InstallWorkflowRunner
    : public std::enable_shared_from_this<InstallWorkflowRunner> {
 public:
  struct Options {
    std::optional<std::string> target_ob_type;
    std::optional<std::int64_t> target_ob_id;
  };

  InstallWorkflowRunner(std::shared_ptr<InstallConfigManager> manager,
                        customio::ConsoleOutput& output);

  monad::IO<void> start(const Options& options = Options{});

 private:
  std::shared_ptr<InstallConfigManager> manager_;
  customio::ConsoleOutput& output_;
};

}  // namespace certctrl
