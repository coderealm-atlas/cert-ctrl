#include "tunnel/tunnel_messages.hpp"

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
                const TunnelHello &hello) {
  jv = json::object{{"type", "hello"},
                    {"tunnel_id", hello.tunnel_id},
                    {"local_base_url", hello.local_base_url}};
}

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const TunnelRequest &req) {
  jv = json::object{{"type", "request"},
                    {"id", req.id},
                    {"method", req.method},
                    {"path", req.path},
                    {"headers", HeaderMapToJson(req.headers)},
                    {"body", req.body}};
}

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const TunnelResponse &res) {
  jv = json::object{{"type", "response"},
                    {"id", res.id},
                    {"status", res.status},
                    {"headers", HeaderMapToJson(res.headers)},
                    {"body", res.body}};
}

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const TunnelPing &ping) {
  jv = json::object{{"type", "ping"}, {"ts", ping.ts}};
}

void tag_invoke(const json::value_from_tag &, json::value &jv,
                const TunnelPong &pong) {
  jv = json::object{{"type", "pong"}, {"ts", pong.ts}};
}

TunnelHello tag_invoke(const json::value_to_tag<TunnelHello> &,
                       const json::value &jv) {
  const auto &obj = RequireObject(jv, "TunnelHello");
  TunnelHello hello;
  hello.tunnel_id = RequireString(obj, "tunnel_id", "TunnelHello");
  hello.local_base_url = RequireString(obj, "local_base_url", "TunnelHello");
  return hello;
}

TunnelRequest tag_invoke(const json::value_to_tag<TunnelRequest> &,
                         const json::value &jv) {
  const auto &obj = RequireObject(jv, "TunnelRequest");
  TunnelRequest req;
  req.id = RequireString(obj, "id", "TunnelRequest");
  req.method = RequireString(obj, "method", "TunnelRequest");
  req.path = RequireString(obj, "path", "TunnelRequest");
  req.body = obj.if_contains("body") && obj.at("body").is_string()
                 ? std::string(obj.at("body").as_string().c_str())
                 : std::string{};
  if (auto *headers = obj.if_contains("headers")) {
    req.headers = ParseHeaderMap(*headers, "TunnelRequest");
  }
  return req;
}

TunnelResponse tag_invoke(const json::value_to_tag<TunnelResponse> &,
                          const json::value &jv) {
  const auto &obj = RequireObject(jv, "TunnelResponse");
  TunnelResponse res;
  res.id = RequireString(obj, "id", "TunnelResponse");
  res.status = RequireInt(obj, "status", "TunnelResponse");
  res.body = obj.if_contains("body") && obj.at("body").is_string()
                 ? std::string(obj.at("body").as_string().c_str())
                 : std::string{};
  if (auto *headers = obj.if_contains("headers")) {
    res.headers = ParseHeaderMap(*headers, "TunnelResponse");
  }
  return res;
}

TunnelPing tag_invoke(const json::value_to_tag<TunnelPing> &,
                      const json::value &jv) {
  const auto &obj = RequireObject(jv, "TunnelPing");
  TunnelPing ping;
  ping.ts = obj.if_contains("ts") ? obj.at("ts").to_number<std::uint64_t>()
                                   : 0;
  return ping;
}

TunnelPong tag_invoke(const json::value_to_tag<TunnelPong> &,
                      const json::value &jv) {
  const auto &obj = RequireObject(jv, "TunnelPong");
  TunnelPong pong;
  pong.ts = obj.if_contains("ts") ? obj.at("ts").to_number<std::uint64_t>()
                                   : 0;
  return pong;
}

} // namespace certctrl
