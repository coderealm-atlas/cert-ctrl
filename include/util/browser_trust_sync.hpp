#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "customio/console_output.hpp"

namespace certctrl::util {

class BrowserTrustSync {
 public:
  BrowserTrustSync(customio::ConsoleOutput &output,
                   std::filesystem::path runtime_dir);

  std::optional<std::string> sync_ca(
      const std::string &canonical_name,
      const std::optional<std::string> &previous_alias,
      const std::filesystem::path &ca_pem_path);

 private:
  customio::ConsoleOutput &output_;
  std::filesystem::path runtime_dir_;
};

}  // namespace certctrl::util
