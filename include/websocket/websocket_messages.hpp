#pragma once

#include <boost/json.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace certctrl {

using HeaderMap = std::unordered_map<std::string, std::string>;

struct WebsocketHello {
  std::string type{"hello"};
  std::string connection_id;
};

struct WebsocketRequest {
  std::string type{"request"};
  std::string id;
  std::string method;
  std::string path;
  HeaderMap headers;
  std::string body;
};

struct WebsocketResponse {
  std::string type{"response"};
  std::string id;
  int status{200};
  HeaderMap headers;
  std::string body;
};

struct WebsocketPing {
  std::string type{"ping"};
  std::uint64_t ts{0};
};

struct WebsocketPong {
  std::string type{"pong"};
  std::uint64_t ts{0};
};

// Generic envelope for multiplexing multiple event branches over the same
// websocket connection.
//
// Backward compatibility: the current protocol uses {"type":"request"},
// {"type":"hello"}, ... directly. The new envelope uses {"type":"event"}
// plus a stable event name, and can be translated into legacy shapes.
struct WebsocketEventEnvelope {
  std::string type{"event"};
  std::string name; // e.g. "http.request", "updates.signal", "lifecycle.hello"
  std::optional<std::string> id;
  // Stream position token for reliable resume after reconnect.
  // Optional and may be omitted by servers that do not support resume.
  std::optional<std::string> resume_token;
  std::optional<std::uint64_t> ts_ms;
  boost::json::value payload{boost::json::object{}};
};

void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const WebsocketHello &hello);
void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const WebsocketRequest &req);
void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const WebsocketResponse &res);
void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const WebsocketPing &ping);
void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const WebsocketPong &pong);

WebsocketHello tag_invoke(const boost::json::value_to_tag<WebsocketHello> &,
                          const boost::json::value &jv);
WebsocketRequest tag_invoke(const boost::json::value_to_tag<WebsocketRequest> &,
                            const boost::json::value &jv);
WebsocketResponse tag_invoke(const boost::json::value_to_tag<WebsocketResponse> &,
                             const boost::json::value &jv);
WebsocketPing tag_invoke(const boost::json::value_to_tag<WebsocketPing> &,
                         const boost::json::value &jv);
WebsocketPong tag_invoke(const boost::json::value_to_tag<WebsocketPong> &,
                         const boost::json::value &jv);

void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const WebsocketEventEnvelope &env);
WebsocketEventEnvelope
tag_invoke(const boost::json::value_to_tag<WebsocketEventEnvelope> &,
           const boost::json::value &jv);

// If `env` corresponds to a legacy message shape, return a legacy JSON object
// (with `type` = hello/request/ping/pong/response). Otherwise return nullopt.
std::optional<boost::json::value>
TryConvertEventEnvelopeToLegacyMessage(const WebsocketEventEnvelope &env);

} // namespace certctrl
