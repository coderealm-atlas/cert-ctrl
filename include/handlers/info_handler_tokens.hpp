#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "state/device_state_store.hpp"

namespace certctrl {

struct SessionTokenSnapshot {
  std::optional<std::string> access_token;
  std::optional<std::string> refresh_token;

  bool has_access() const { return access_token.has_value(); }
  bool has_refresh() const { return refresh_token.has_value(); }
};

inline SessionTokenSnapshot
load_session_tokens_from_state(const std::filesystem::path &runtime_dir,
                               certctrl::IDeviceStateStore &state_store) {
  (void)runtime_dir;
  SessionTokenSnapshot snapshot{};

  if (auto token = state_store.get_access_token(); token && !token->empty()) {
    snapshot.access_token = token;
  }
  if (auto token = state_store.get_refresh_token(); token && !token->empty()) {
    snapshot.refresh_token = token;
  }

  if (snapshot.has_access() && snapshot.has_refresh()) {
    return snapshot;
  }

  return snapshot;
}

} // namespace certctrl
