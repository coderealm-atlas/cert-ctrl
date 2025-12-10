#pragma once

#include <chrono>
#include <string_view>

#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace certctrl::session_refresh {

inline constexpr std::chrono::milliseconds kInitialRetryDelay{
    std::chrono::seconds(5)};
inline constexpr std::chrono::milliseconds kMaxRetryDelay{
    std::chrono::seconds(300)};

inline bool is_retryable_error(const monad::Error &err) {
  if (err.code == my_errors::GENERAL::INVALID_ARGUMENT) {
    return false;
  }
  if (err.response_status >= 400 && err.response_status < 500 &&
      err.response_status != 429) {
    return false;
  }

  const std::string_view what = err.what;
  if (what.find("no refresh token") != std::string_view::npos ||
      what.find("missing tokens") != std::string_view::npos ||
      what.find("Refresh response missing tokens") !=
          std::string_view::npos ||
      what.find("Refresh token response missing required session tokens") !=
          std::string_view::npos) {
    return false;
  }

  return true;
}

} // namespace certctrl::session_refresh
