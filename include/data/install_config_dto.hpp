#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <unordered_map>
#include <boost/json.hpp>

namespace dto {

namespace json = boost::json;

// Minimal server-side install item shape per DEVICE_INSTALL_CONFIGS_DESIGN.md
// Common fields + type-specific optional fields. Keep server minimal; agent enforces modes/ownership.
struct InstallItem {
  // Common
  std::string id;                            // stable id within plan
  std::string type;                          // "copy" | "exec"
  bool continue_on_error{false};
  std::vector<std::string> depends_on;       // ids of prior items
  std::vector<std::string> tags;             // optional grouping labels

  // Resource reference (optional per item)
  std::optional<std::string> ob_type;        // "cert" | "ca"
  std::optional<std::int64_t> ob_id;        // resource id
  std::optional<std::string> ob_name;        // human label

  // Copy fields
  std::optional<std::vector<std::string>> from; // virtual filenames
  std::optional<std::vector<std::string>> to;   // absolute destinations (1:1 with from)

  // Exec fields
  std::optional<std::string> cmd;                // single string form
  std::optional<std::vector<std::string>> cmd_argv; // argv form
  std::optional<std::int64_t> timeout_ms;
  std::optional<std::string> run_as;
  std::optional<std::unordered_map<std::string, std::string>> env;

  // Optional verification spec (kept minimal)
  std::optional<json::object> verify;
};

struct DeviceInstallConfigDto {
  std::int64_t id{};                       // config id (0 for default)
  std::int64_t user_device_id{};           // device id
  std::int64_t version{};                  // version (0 for default)
  std::vector<InstallItem> installs;        // the v0 plan items
  std::string installs_hash;                // optional hash (empty for default)
  std::optional<std::string> updated_by;    // optional user name/id
  std::int64_t created_at{};               // epoch seconds
  std::int64_t updated_at{};               // epoch seconds
};

// ---------------- Boost.JSON serializers/deserializers -----------------

inline InstallItem tag_invoke(boost::json::value_to_tag<InstallItem>,
                              boost::json::value const& jv) {
  InstallItem item{};
  if (auto const* obj = jv.if_object()) {
    if (auto const* id_p = obj->if_contains("id")) {
      if (id_p->is_string()) item.id = json::value_to<std::string>(*id_p);
    }
    if (auto const* type_p = obj->if_contains("type")) {
      if (type_p->is_string()) item.type = json::value_to<std::string>(*type_p);
    }
    if (auto const* coe_p = obj->if_contains("continue_on_error")) {
      if (coe_p->is_bool()) item.continue_on_error = coe_p->as_bool();
    }
    if (auto const* depends_p = obj->if_contains("depends_on")) {
      if (depends_p->is_array()) {
        item.depends_on =
            json::value_to<std::vector<std::string>>(*depends_p);
      }
    }
    if (auto const* tags_p = obj->if_contains("tags")) {
      if (tags_p->is_array()) {
        item.tags = json::value_to<std::vector<std::string>>(*tags_p);
      }
    }

    if (auto const* ob_type_p = obj->if_contains("ob_type")) {
      if (ob_type_p->is_string()) {
        item.ob_type = json::value_to<std::string>(*ob_type_p);
      }
    }
    if (auto const* ob_id_p = obj->if_contains("ob_id")) {
      if (ob_id_p->is_int64()) {
        item.ob_id = ob_id_p->as_int64();
      } else if (ob_id_p->is_uint64()) {
        item.ob_id = static_cast<std::int64_t>(ob_id_p->as_uint64());
      }
    }
    if (auto const* ob_name_p = obj->if_contains("ob_name")) {
      if (ob_name_p->is_string()) {
        item.ob_name = json::value_to<std::string>(*ob_name_p);
      }
    }

    if (auto const* from_p = obj->if_contains("from")) {
      if (from_p->is_array()) {
        item.from = json::value_to<std::vector<std::string>>(*from_p);
      }
    }
    if (auto const* to_p = obj->if_contains("to")) {
      if (to_p->is_array()) {
        item.to = json::value_to<std::vector<std::string>>(*to_p);
      }
    }

    if (auto const* cmd_p = obj->if_contains("cmd")) {
      if (cmd_p->is_array()) {
        item.cmd_argv = json::value_to<std::vector<std::string>>(*cmd_p);
      } else if (cmd_p->is_string()) {
        item.cmd = json::value_to<std::string>(*cmd_p);
      }
    }

    if (auto const* timeout_p = obj->if_contains("timeout_ms")) {
      if (timeout_p->is_int64()) {
        item.timeout_ms = timeout_p->as_int64();
      } else if (timeout_p->is_uint64()) {
        item.timeout_ms = static_cast<std::int64_t>(timeout_p->as_uint64());
      }
    }
    if (auto const* run_as_p = obj->if_contains("run_as")) {
      if (run_as_p->is_string()) {
        item.run_as = json::value_to<std::string>(*run_as_p);
      }
    }
    if (auto const* env_p = obj->if_contains("env")) {
      if (env_p->is_object()) {
        std::unordered_map<std::string, std::string> env_map;
        for (auto const& kv : env_p->as_object()) {
          if (kv.value().is_string()) {
            env_map.emplace(kv.key_c_str(),
                            json::value_to<std::string>(kv.value()));
          }
        }
        if (!env_map.empty()) item.env = std::move(env_map);
      }
    }
    if (auto const* verify_p = obj->if_contains("verify")) {
      if (verify_p->is_object()) {
        item.verify = verify_p->as_object();
      }
    }
  }
  return item;
}

inline void tag_invoke(boost::json::value_from_tag, boost::json::value& v,
                       InstallItem const& x) {
  json::object o;
  o["id"] = x.id;
  o["type"] = x.type;
  o["continue_on_error"] = x.continue_on_error;
  o["depends_on"] = json::value_from(x.depends_on);
  o["tags"] = json::value_from(x.tags);
  o["ob_type"] = x.ob_type && !x.ob_type->empty()
                     ? json::value_from(*x.ob_type)
                     : json::value_from(std::string{});
  o["ob_id"] = static_cast<std::int64_t>(x.ob_id.value_or(0));
  o["ob_name"] = x.ob_name && !x.ob_name->empty()
                      ? json::value_from(*x.ob_name)
                      : json::value_from(std::string{});

  const auto empty_paths = std::vector<std::string>{};
  o["from"] = json::value_from(x.from ? *x.from : empty_paths);
  o["to"] = json::value_from(x.to ? *x.to : empty_paths);

  if (x.cmd_argv && !x.cmd_argv->empty()) {
    o["cmd"] = json::value_from(*x.cmd_argv);
  } else {
    o["cmd"] = x.cmd && !x.cmd->empty() ? json::value_from(*x.cmd)
                                          : json::value_from(std::string{});
  }
  o["cmd_argv"] = json::value_from(x.cmd_argv ? *x.cmd_argv
                                               : std::vector<std::string>{});

  o["timeout_ms"] = static_cast<std::int64_t>(x.timeout_ms.value_or(0));
  o["run_as"] = x.run_as && !x.run_as->empty()
                     ? json::value_from(*x.run_as)
                     : json::value_from(std::string{});

  if (x.env && !x.env->empty()) {
    json::object env_o;
    for (auto const& [k, vstr] : *x.env) env_o[k] = vstr;
    o["env"] = std::move(env_o);
  } else {
    o["env"] = json::object{};
  }

  o["verify"] = x.verify && !x.verify->empty() ? json::value_from(*x.verify)
                                                : json::value_from(json::object{});
  v = std::move(o);
}

inline void tag_invoke(boost::json::value_from_tag, boost::json::value& v,
                       DeviceInstallConfigDto const& x) {
  json::object o;
  o["id"] = static_cast<std::int64_t>(x.id);
  o["user_device_id"] = static_cast<std::int64_t>(x.user_device_id);
  o["version"] = static_cast<std::int64_t>(x.version);
  o["installs"] = json::value_from(x.installs);
  // Back-compat for older clients/tests expecting a string field
  o["installs_json"] = boost::json::serialize(json::value_from(x.installs));
  o["installs_hash"] = x.installs_hash;
  if (x.updated_by && !x.updated_by->empty()) o["updated_by"] = *x.updated_by;
  o["created_at"] = static_cast<std::int64_t>(x.created_at);
  o["updated_at"] = static_cast<std::int64_t>(x.updated_at);
  v = std::move(o);
}

}  // namespace dto
