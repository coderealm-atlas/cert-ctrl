#pragma once

#include "api_handler_base.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include <boost/json.hpp>
#include <optional>
#include <variant>

namespace data {
namespace json = boost::json;

// => 200  (Set-Cookie: cjj365=<opaque-session-id>; Path=/; ...)
// {
//   "data": {
//     "user": {"id": 1, "email": "u@example.com", "roles": []},
//     "to": "/"
//   }
// }

struct LoginUser {
  int64_t id;
  std::string email; // key=value only
  std::vector<std::string> roles;

  friend LoginUser tag_invoke(const json::value_to_tag<LoginUser> &,
                              const json::value &jv) {
    try {
      if (auto *jo_p = jv.if_object()) {
        LoginUser lu{};
        lu.id = jo_p->at("id").as_int64();
        lu.email = jo_p->at("email").as_string().c_str();
        if (auto roles = jo_p->at("roles").if_array()) {
          for (auto &r : *roles) {
            if (r.is_string())
              lu.roles.push_back(json::value_to<std::string>(r));
          }
        }
        return lu;
      } else {
        throw std::runtime_error("LoginUser is not an object");
      }
    } catch (...) {
      std::cerr << "jv: " << boost::json::serialize(jv) << std::endl;
      throw std::runtime_error("error in parsing LoginUser");
    }
  }
};

struct LoginSuccess {
  LoginUser user;
  std::string to;
  std::string session_cookie; // not from json, but from HTTP header

  friend LoginSuccess tag_invoke(const json::value_to_tag<LoginSuccess> &,
                                 const json::value &jv) {
    try {
      if (auto *jo_p = jv.if_object()) {
        LoginSuccess ls{};
        ls.user = json::value_to<LoginUser>(jo_p->at("user"));
        ls.to = jo_p->at("to").as_string().c_str();
        return ls;
      } else {
        throw std::runtime_error("LoginSuccess is not an object");
      }
    } catch (...) {
      std::cerr << "jv: " << boost::json::serialize(jv) << std::endl;
      throw std::runtime_error("error in parsing LoginSuccess");
    }
  }
};

// ---------------------------------------------------------------------------
// Device Updates Polling Response Shapes ( /apiv1/devices/self/updates )
// ---------------------------------------------------------------------------
// Raw shape (200):
// {
//   "data": {
//     "cursor": "1736900123.42-9",
//     "signals": [ { "type": "install.updated", "ts_ms": 173..., "ref": { ... } }, ... ]
//   }
// }
// 204 uses only ETag header (handled outside JSON parsing) so no structure.

// Ref objects differ by signal type. We keep a permissive representation plus
// typed convenience variants. Unknown fields/types should not break parsing.

struct InstallUpdatedRef {
  int64_t config_id{};
  int version{};
  // Optional base64 hash, may be null or missing
  std::optional<std::string> installs_hash_b64;
};

struct CertRenewedRef {
  int64_t cert_id{};
  std::optional<std::string> serial; // optional
};

struct CertRevokedRef {
  int64_t cert_id{};
};

// A generic signal; "ref" will be preserved as an object for forward
// compatibility. A derived typed_ref variant is populated when type matches a
// known enumerated signal.
struct DeviceUpdateSignal {
  std::string type;      // e.g. install.updated, cert.renewed
  int64_t ts_ms{};       // event time
  json::object ref;      // original lightweight reference object
  std::variant<std::monostate, InstallUpdatedRef, CertRenewedRef, CertRevokedRef>
      typed_ref;         // convenience decoded form (monostate if unknown)

  friend DeviceUpdateSignal tag_invoke(
      const json::value_to_tag<DeviceUpdateSignal> &, const json::value &jv) {
    if (!jv.is_object()) {
      throw std::runtime_error("DeviceUpdateSignal not an object");
    }
    const auto &jo = jv.as_object();
    DeviceUpdateSignal s{};
    // Required fields
    s.type = json::value_to<std::string>(jo.at("type"));
    s.ts_ms = jo.at("ts_ms").to_number<int64_t>();
    if (auto *ref_p = jo.if_contains("ref")) {
      if (ref_p->is_object()) {
        s.ref = ref_p->as_object();
      } else {
        // Keep empty object if malformed
        s.ref = {};
      }
    } else {
      s.ref = {};
    }
    // Populate typed_ref for known signal types
    try {
      if (s.type == "install.updated") {
        InstallUpdatedRef r{};
        if (auto *cfg_id = s.ref.if_contains("config_id")) {
          r.config_id = json::value_to<int64_t>(*cfg_id);
        }
        if (auto *ver = s.ref.if_contains("version")) {
          r.version = json::value_to<int>(*ver);
        }
        if (auto *hash_p = s.ref.if_contains("installs_hash_b64")) {
          if (hash_p->is_string()) {
            r.installs_hash_b64 = json::value_to<std::string>(*hash_p);
          } else if (hash_p->is_null()) {
            r.installs_hash_b64 = std::nullopt;
          }
        }
        s.typed_ref = r;
      } else if (s.type == "cert.renewed") {
        CertRenewedRef r{};
        if (auto *cid = s.ref.if_contains("cert_id")) {
          r.cert_id = json::value_to<int64_t>(*cid);
        }
        if (auto *serial = s.ref.if_contains("serial")) {
          if (serial->is_string()) {
            r.serial = json::value_to<std::string>(*serial);
          }
        }
        s.typed_ref = r;
      } else if (s.type == "cert.revoked") {
        CertRevokedRef r{};
        if (auto *cid = s.ref.if_contains("cert_id")) {
          r.cert_id = json::value_to<int64_t>(*cid);
        }
        s.typed_ref = r;
      } else {
        // Unknown type -> leave monostate
      }
    } catch (const std::exception &e) {
      // Do not throw for partial ref errors; preserve raw ref for higher-level handling
    }
    return s;
  }
};

struct DeviceUpdatesData {
  std::string cursor; // opaque cursor
  std::vector<DeviceUpdateSignal> signals;

  friend DeviceUpdatesData tag_invoke(
      const json::value_to_tag<DeviceUpdatesData> &, const json::value &jv) {
    if (!jv.is_object()) {
      throw std::runtime_error("DeviceUpdatesData not an object");
    }
    const auto &jo = jv.as_object();
    DeviceUpdatesData d{};
    d.cursor = json::value_to<std::string>(jo.at("cursor"));
    if (auto *sig_p = jo.if_contains("signals")) {
      if (sig_p->is_array()) {
        for (auto &sv : sig_p->as_array()) {
          d.signals.push_back(json::value_to<DeviceUpdateSignal>(sv));
        }
      }
    }
    return d;
  }
};

struct DeviceUpdatesResponse {
  DeviceUpdatesData data;
  friend DeviceUpdatesResponse tag_invoke(
      const json::value_to_tag<DeviceUpdatesResponse> &,
      const json::value &jv) {
    if (!jv.is_object()) {
      throw std::runtime_error("DeviceUpdatesResponse not an object");
    }
    const auto &jo = jv.as_object();
    DeviceUpdatesResponse r{};
    r.data = json::value_to<DeviceUpdatesData>(jo.at("data"));
    return r;
  }
};

// Helper utilities (inline) for consumers
inline bool is_install_updated(const DeviceUpdateSignal &s) {
  return std::holds_alternative<InstallUpdatedRef>(s.typed_ref);
}
inline bool is_cert_renewed(const DeviceUpdateSignal &s) {
  return std::holds_alternative<CertRenewedRef>(s.typed_ref);
}
inline bool is_cert_revoked(const DeviceUpdateSignal &s) {
  return std::holds_alternative<CertRevokedRef>(s.typed_ref);
}

inline std::optional<InstallUpdatedRef>
get_install_updated(const DeviceUpdateSignal &s) {
  if (auto p = std::get_if<InstallUpdatedRef>(&s.typed_ref))
    return *p;
  return std::nullopt;
}
inline std::optional<CertRenewedRef>
get_cert_renewed(const DeviceUpdateSignal &s) {
  if (auto p = std::get_if<CertRenewedRef>(&s.typed_ref))
    return *p;
  return std::nullopt;
}
inline std::optional<CertRevokedRef>
get_cert_revoked(const DeviceUpdateSignal &s) {
  if (auto p = std::get_if<CertRevokedRef>(&s.typed_ref))
    return *p;
  return std::nullopt;
}

} // namespace data