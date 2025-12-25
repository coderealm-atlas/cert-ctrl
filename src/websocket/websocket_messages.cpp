#include "websocket/websocket_messages.hpp"

#include <fmt/format.h>
#include <stdexcept>

namespace certctrl {
namespace json = boost::json;

namespace {

const json::object &RequireObject(const json::value &jv, const char *ctx) {
  if (!jv.is_object()) {
    throw std::runtime_error(fmt::format("{} must be an object", ctx));
  }
  return jv.as_object();
}

std::string RequireString(const json::object &obj, const char *key,
                          const char *ctx) {
  if (auto *p = obj.if_contains(key)) {
    if (p->is_string()) {
      return std::string(p->as_string().c_str());
    }
  }
  throw std::runtime_error(fmt::format("{} missing string field '{}'", ctx, key));
}

int RequireInt(const json::object &obj, const char *key, const char *ctx) {
  if (auto *p = obj.if_contains(key)) {
    if (p->is_int64()) {
      return static_cast<int>(p->as_int64());
    }
    if (p->is_uint64()) {
      return static_cast<int>(p->as_uint64());
    }
  }
  throw std::runtime_error(fmt::format("{} missing integer field '{}'", ctx, key));
}

std::unordered_map<std::string, std::string>
ParseHeaderMap(const json::value &jv, const char *ctx) {
  std::unordered_map<std::string, std::string> headers;
  if (!jv.is_object()) {
    throw std::runtime_error(fmt::format("{} headers must be object", ctx));
  }
  for (const auto &kv : jv.as_object()) {
    if (!kv.value().is_string()) {
      throw std::runtime_error(fmt::format("{} header '{}' is not string",
                                           ctx, kv.key()));
    }
    headers.emplace(std::string(kv.key()),
                    std::string(kv.value().as_string().c_str()));
  }
  return headers;
}

json::object HeaderMapToJson(
    const std::unordered_map<std::string, std::string> &headers) {
  json::object obj;
  for (const auto &kv : headers) {
    obj[kv.first] = kv.second;
  }
  return obj;
}

} // namespace

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const WebsocketHello &hello) {
  jv = json::object{{"type", "hello"}, {"connection_id", hello.connection_id}};
}

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const WebsocketRequest &req) {
  jv = json::object{{"type", "request"},
                    {"id", req.id},
                    {"method", req.method},
                    {"path", req.path},
                    {"headers", HeaderMapToJson(req.headers)},
                    {"body", req.body}};
}

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const WebsocketResponse &res) {
  jv = json::object{{"type", "response"},
                    {"id", res.id},
                    {"status", res.status},
                    {"headers", HeaderMapToJson(res.headers)},
                    {"body", res.body}};
}

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const WebsocketPing &ping) {
  jv = json::object{{"type", "ping"}, {"ts", ping.ts}};
}

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const WebsocketPong &pong) {
  jv = json::object{{"type", "pong"}, {"ts", pong.ts}};
}

WebsocketHello tag_invoke(const json::value_to_tag<WebsocketHello> &,
                          const json::value &jv) {
  const auto &obj = RequireObject(jv, "WebsocketHello");
  WebsocketHello hello;
  hello.connection_id = RequireString(obj, "connection_id", "WebsocketHello");
  return hello;
}

WebsocketRequest tag_invoke(const json::value_to_tag<WebsocketRequest> &,
                            const json::value &jv) {
  const auto &obj = RequireObject(jv, "WebsocketRequest");
  WebsocketRequest req;
  req.id = RequireString(obj, "id", "WebsocketRequest");
  req.method = RequireString(obj, "method", "WebsocketRequest");
  req.path = RequireString(obj, "path", "WebsocketRequest");
  req.body = obj.if_contains("body") && obj.at("body").is_string()
                 ? std::string(obj.at("body").as_string().c_str())
                 : std::string{};
  if (auto *headers = obj.if_contains("headers")) {
    req.headers = ParseHeaderMap(*headers, "WebsocketRequest");
  }
  return req;
}

WebsocketResponse tag_invoke(const json::value_to_tag<WebsocketResponse> &,
                             const json::value &jv) {
  const auto &obj = RequireObject(jv, "WebsocketResponse");
  WebsocketResponse res;
  res.id = RequireString(obj, "id", "WebsocketResponse");
  res.status = RequireInt(obj, "status", "WebsocketResponse");
  res.body = obj.if_contains("body") && obj.at("body").is_string()
                 ? std::string(obj.at("body").as_string().c_str())
                 : std::string{};
  if (auto *headers = obj.if_contains("headers")) {
    res.headers = ParseHeaderMap(*headers, "WebsocketResponse");
  }
  return res;
}

WebsocketPing tag_invoke(const json::value_to_tag<WebsocketPing> &,
                         const json::value &jv) {
  const auto &obj = RequireObject(jv, "WebsocketPing");
  WebsocketPing ping;
  ping.ts = obj.if_contains("ts") ? obj.at("ts").to_number<std::uint64_t>()
                                   : 0;
  return ping;
}

WebsocketPong tag_invoke(const json::value_to_tag<WebsocketPong> &,
                         const json::value &jv) {
  const auto &obj = RequireObject(jv, "WebsocketPong");
  WebsocketPong pong;
  pong.ts = obj.if_contains("ts") ? obj.at("ts").to_number<std::uint64_t>()
                                   : 0;
  return pong;
}

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const WebsocketEventEnvelope &env) {
  json::object obj;
  obj["type"] = "event";
  obj["name"] = env.name;
  if (env.id && !env.id->empty()) {
    obj["id"] = *env.id;
  }
  if (env.resume_token && !env.resume_token->empty()) {
    obj["resume_token"] = *env.resume_token;
  }
  if (env.ts_ms) {
    obj["ts_ms"] = *env.ts_ms;
  }
  obj["payload"] = env.payload;
  jv = std::move(obj);
}

WebsocketEventEnvelope
tag_invoke(const json::value_to_tag<WebsocketEventEnvelope> &,
           const json::value &jv) {
  const auto &obj = RequireObject(jv, "WebsocketEventEnvelope");
  WebsocketEventEnvelope env;

  // type is optional but must be "event" if present
  if (auto *type_p = obj.if_contains("type")) {
    if (!type_p->is_string()) {
      throw std::runtime_error("WebsocketEventEnvelope type is not string");
    }
    const std::string type = std::string(type_p->as_string().c_str());
    if (type != "event") {
      throw std::runtime_error("WebsocketEventEnvelope type must be 'event'");
    }
    env.type = type;
  }

  env.name = RequireString(obj, "name", "WebsocketEventEnvelope");

  if (auto *id_p = obj.if_contains("id")) {
    if (id_p->is_string()) {
      env.id = std::string(id_p->as_string().c_str());
    }
  }
  if (auto *token_p = obj.if_contains("resume_token")) {
    if (token_p->is_string()) {
      env.resume_token = std::string(token_p->as_string().c_str());
    }
  }
  if (auto *ts_p = obj.if_contains("ts_ms")) {
    if (ts_p->is_uint64() || ts_p->is_int64() || ts_p->is_double()) {
      env.ts_ms = ts_p->to_number<std::uint64_t>();
    }
  }
  if (auto *payload_p = obj.if_contains("payload")) {
    env.payload = *payload_p;
  }
  return env;
}

std::optional<json::value>
TryConvertEventEnvelopeToLegacyMessage(const WebsocketEventEnvelope &env) {
  json::object legacy;

  // Allow either {payload:{...}} or treat null as empty object
  json::object payload_obj;
  if (env.payload.is_object()) {
    payload_obj = env.payload.as_object();
  }

  auto with_type = [&](const char *type) -> json::value {
    json::object out = payload_obj;
    out["type"] = type;
    if (env.id && !env.id->empty() && !out.if_contains("id")) {
      out["id"] = *env.id;
    }
    if (env.ts_ms && !out.if_contains("ts")) {
      // legacy ping/pong uses 'ts'
      out["ts"] = *env.ts_ms;
    }
    return out;
  };

  if (env.name == "http.request" || env.name == "tunnel.http.request") {
    return with_type("request");
  }
  if (env.name == "http.response" || env.name == "tunnel.http.response") {
    return with_type("response");
  }
  if (env.name == "lifecycle.hello") {
    return with_type("hello");
  }
  if (env.name == "lifecycle.ping") {
    return with_type("ping");
  }
  if (env.name == "lifecycle.pong") {
    return with_type("pong");
  }

  // No legacy equivalent.
  return std::nullopt;
}

} // namespace certctrl
