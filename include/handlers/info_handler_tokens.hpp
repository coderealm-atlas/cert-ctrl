#pragma once

#include <filesystem>
#include <fstream>
#include <iterator>
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

namespace info_handler_detail {
inline std::optional<std::string>
read_trimmed_token_file(const std::filesystem::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    return std::nullopt;
  }
  std::string contents((std::istreambuf_iterator<char>(ifs)), {});
  auto first = contents.find_first_not_of(" \t\r\n\f\v");
  if (first == std::string::npos) {
    return std::nullopt;
  }
  auto last = contents.find_last_not_of(" \t\r\n\f\v");
  if (last == std::string::npos || last < first) {
    return std::nullopt;
  }
  return contents.substr(first, last - first + 1);
}
} // namespace info_handler_detail

inline SessionTokenSnapshot
load_session_tokens_from_state(const std::filesystem::path &runtime_dir,
                               certctrl::IDeviceStateStore &state_store) {
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

  if (!runtime_dir.empty()) {
    const auto state_dir = runtime_dir / "state";
    if (!snapshot.access_token) {
      snapshot.access_token = info_handler_detail::read_trimmed_token_file(
          state_dir / "access_token.txt");
    }
    if (!snapshot.refresh_token) {
      snapshot.refresh_token = info_handler_detail::read_trimmed_token_file(
          state_dir / "refresh_token.txt");
    }
  }

  return snapshot;
}

} // namespace certctrl
