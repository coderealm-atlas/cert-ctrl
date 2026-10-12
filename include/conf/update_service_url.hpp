#pragma once

#include <string>
#include <string_view>

namespace certctrl {

inline constexpr const char *kDefaultUpdateCheckUrl =
    "https://install.never-lost.app/api/version/check";

// Installers preserve application configuration during upgrades. Recognize only
// the former public default, leaving disabled checks and custom mirrors alone.
inline std::string migrate_update_check_url(std::string url) {
  for (const std::string_view legacy : {
           "https://install.lets-script.com/api/version/check",
           "http://install.lets-script.com/api/version/check"}) {
    if (url.compare(0, legacy.size(), legacy) != 0) {
      continue;
    }
    const auto suffix = std::string_view(url).substr(legacy.size());
    if (suffix.empty() || suffix.front() == '?' || suffix.front() == '#') {
      return std::string(kDefaultUpdateCheckUrl) + std::string(suffix);
    }
  }
  return url;
}

} // namespace certctrl
