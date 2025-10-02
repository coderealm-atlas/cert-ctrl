#pragma once

#include <boost/json.hpp>

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dto {

namespace json = boost::json;

namespace detail {

inline std::optional<std::int64_t> parse_int64(const json::value& v) {
  if (v.is_int64()) {
    return v.as_int64();
  }
  if (v.is_uint64()) {
    return static_cast<std::int64_t>(v.as_uint64());
  }
  if (v.is_double()) {
    return static_cast<std::int64_t>(v.as_double());
  }
  if (v.is_string()) {
    auto s = v.as_string();
    std::string_view sv{s.data(), s.size()};
    std::int64_t out{};
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), out);
    if (ec == std::errc{} && ptr == sv.data() + sv.size()) {
      return out;
    }
  }
  return std::nullopt;
}

inline std::optional<std::string> parse_string(const json::value& v) {
  if (v.is_string()) {
    return json::value_to<std::string>(v);
  }
  return std::nullopt;
}

inline void set_if(json::object& obj, std::string_view key,
                   const std::optional<std::int64_t>& value) {
  if (value) {
    obj[std::string(key)] = *value;
  }
}

inline void set_if(json::object& obj, std::string_view key,
                   const std::optional<std::string>& value) {
  if (value) {
    obj[std::string(key)] = *value;
  }
}

}  // namespace detail

struct DeviceUpdateSignalRef {
  std::optional<std::int64_t> config_id;
  std::optional<std::int64_t> version;
  std::optional<std::string> installs_hash_b64;

  std::optional<std::int64_t> cert_id;
  std::optional<std::string> serial;

  std::optional<std::string> device_keyfp_b64;
  std::optional<std::string> wrap_alg;

  json::object extras{};
};

struct DeviceUpdateSignal {
  std::string type;
  std::optional<std::int64_t> ts_ms;
  DeviceUpdateSignalRef ref;
};

struct DeviceUpdatesData {
  std::optional<std::string> cursor;
  std::vector<DeviceUpdateSignal> signals;
};

struct DeviceUpdatesResponseDto {
  std::optional<DeviceUpdatesData> data;
};

// ---------------- Boost.JSON conversions ----------------

inline DeviceUpdateSignalRef tag_invoke(
    json::value_to_tag<DeviceUpdateSignalRef>, const json::value& jv) {
  DeviceUpdateSignalRef ref;
  if (!jv.is_object()) {
    return ref;
  }
  json::object extras{jv.as_object()};

  if (auto* v = extras.if_contains("config_id")) {
    ref.config_id = detail::parse_int64(*v);
    extras.erase("config_id");
  }
  if (auto* v = extras.if_contains("version")) {
    ref.version = detail::parse_int64(*v);
    extras.erase("version");
  }
  if (auto* v = extras.if_contains("installs_hash_b64")) {
    ref.installs_hash_b64 = detail::parse_string(*v);
    extras.erase("installs_hash_b64");
  }
  if (auto* v = extras.if_contains("cert_id")) {
    ref.cert_id = detail::parse_int64(*v);
    extras.erase("cert_id");
  }
  if (auto* v = extras.if_contains("serial")) {
    ref.serial = detail::parse_string(*v);
    extras.erase("serial");
  }
  if (auto* v = extras.if_contains("device_keyfp_b64")) {
    ref.device_keyfp_b64 = detail::parse_string(*v);
    extras.erase("device_keyfp_b64");
  }
  if (auto* v = extras.if_contains("wrap_alg")) {
    ref.wrap_alg = detail::parse_string(*v);
    extras.erase("wrap_alg");
  }

  ref.extras = std::move(extras);
  return ref;
}

inline void tag_invoke(json::value_from_tag, json::value& jv,
                       const DeviceUpdateSignalRef& ref) {
  json::object obj{ref.extras};
  detail::set_if(obj, "config_id", ref.config_id);
  detail::set_if(obj, "version", ref.version);
  detail::set_if(obj, "installs_hash_b64", ref.installs_hash_b64);
  detail::set_if(obj, "cert_id", ref.cert_id);
  detail::set_if(obj, "serial", ref.serial);
  detail::set_if(obj, "device_keyfp_b64", ref.device_keyfp_b64);
  detail::set_if(obj, "wrap_alg", ref.wrap_alg);
  jv = std::move(obj);
}

inline DeviceUpdateSignal tag_invoke(
    json::value_to_tag<DeviceUpdateSignal>, const json::value& jv) {
  DeviceUpdateSignal sig;
  if (auto const* obj = jv.if_object()) {
    if (auto* type = obj->if_contains("type")) {
      if (auto type_str = detail::parse_string(*type)) {
        sig.type = std::move(*type_str);
      }
    }
    if (auto* ts = obj->if_contains("ts_ms")) {
      sig.ts_ms = detail::parse_int64(*ts);
    }
    if (auto* ref_obj = obj->if_contains("ref")) {
      sig.ref = json::value_to<DeviceUpdateSignalRef>(*ref_obj);
    }
  }
  return sig;
}

inline void tag_invoke(json::value_from_tag, json::value& jv,
                       const DeviceUpdateSignal& sig) {
  json::object obj;
  if (!sig.type.empty()) {
    obj["type"] = sig.type;
  }
  if (sig.ts_ms) {
    obj["ts_ms"] = *sig.ts_ms;
  }
  obj["ref"] = json::value_from(sig.ref);
  jv = std::move(obj);
}

inline DeviceUpdatesData tag_invoke(
    json::value_to_tag<DeviceUpdatesData>, const json::value& jv) {
  DeviceUpdatesData data;
  if (auto const* obj = jv.if_object()) {
    if (auto* cursor = obj->if_contains("cursor")) {
      data.cursor = detail::parse_string(*cursor);
    }
    if (auto* sigs = obj->if_contains("signals")) {
      if (sigs->is_array()) {
        data.signals.reserve(sigs->as_array().size());
        for (auto const& entry : sigs->as_array()) {
          data.signals.emplace_back(
              json::value_to<DeviceUpdateSignal>(entry));
        }
      }
    }
  }
  return data;
}

inline void tag_invoke(json::value_from_tag, json::value& jv,
                       const DeviceUpdatesData& data) {
  json::object obj;
  if (data.cursor) {
    obj["cursor"] = *data.cursor;
  }
  obj["signals"] = json::value_from(data.signals);
  jv = std::move(obj);
}

inline DeviceUpdatesResponseDto tag_invoke(
    json::value_to_tag<DeviceUpdatesResponseDto>, const json::value& jv) {
  DeviceUpdatesResponseDto resp;
  if (auto const* obj = jv.if_object()) {
    if (auto* data = obj->if_contains("data")) {
      if (data->is_object()) {
        resp.data = json::value_to<DeviceUpdatesData>(*data);
      }
    }
  }
  return resp;
}

inline void tag_invoke(json::value_from_tag, json::value& jv,
                       const DeviceUpdatesResponseDto& resp) {
  json::object obj;
  if (resp.data) {
    obj["data"] = json::value_from(*resp.data);
  }
  jv = std::move(obj);
}

}  // namespace dto
