#pragma once

#include <boost/json.hpp>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace certctrl::data {

struct AgentUpdateCheckResponse {
  std::string current_version;
  std::string latest_version;
  bool newer_version_available{false};
  std::string platform;
  std::string architecture;
  std::optional<std::string> changelog_url;
  std::optional<bool> security_update;
  std::optional<std::string> minimum_supported_version;
  std::optional<std::string> update_urgency;
  std::vector<std::string> deprecation_warnings;
  std::map<std::string, std::string> download_urls;
};

inline AgentUpdateCheckResponse tag_invoke(
    const boost::json::value_to_tag<AgentUpdateCheckResponse>&,
    const boost::json::value& jv) {
  using namespace boost::json;

  if (!jv.is_object()) {
    throw std::runtime_error("AgentUpdateCheckResponse expects JSON object");
  }
  const auto& obj = jv.as_object();
  AgentUpdateCheckResponse resp{};

  if (auto* p = obj.if_contains("current_version")) {
    resp.current_version = value_to<std::string>(*p);
  }
  if (auto* p = obj.if_contains("latest_version")) {
    resp.latest_version = value_to<std::string>(*p);
  }
  if (auto* p = obj.if_contains("newer_version_available")) {
    resp.newer_version_available = value_to<bool>(*p);
  }
  if (auto* p = obj.if_contains("platform")) {
    resp.platform = value_to<std::string>(*p);
  }
  if (auto* p = obj.if_contains("architecture")) {
    resp.architecture = value_to<std::string>(*p);
  }
  if (auto* p = obj.if_contains("changelog_url")) {
    if (!p->is_null()) {
      resp.changelog_url = value_to<std::string>(*p);
    }
  }
  if (auto* p = obj.if_contains("security_update")) {
    if (!p->is_null()) {
      resp.security_update = value_to<bool>(*p);
    }
  }
  if (auto* p = obj.if_contains("minimum_supported_version")) {
    if (!p->is_null()) {
      resp.minimum_supported_version = value_to<std::string>(*p);
    }
  }
  if (auto* p = obj.if_contains("update_urgency")) {
    if (!p->is_null()) {
      resp.update_urgency = value_to<std::string>(*p);
    }
  }
  if (auto* p = obj.if_contains("deprecation_warnings")) {
    if (p->is_array()) {
      resp.deprecation_warnings = value_to<std::vector<std::string>>(*p);
    }
  }
  if (auto* p = obj.if_contains("download_urls")) {
    if (p->is_object()) {
      const auto& map_obj = p->as_object();
      for (const auto& [key, value] : map_obj) {
        if (value.is_string()) {
          resp.download_urls.emplace(key, value.as_string().c_str());
        }
      }
    }
  }

  return resp;
}

}  // namespace certctrl::data
