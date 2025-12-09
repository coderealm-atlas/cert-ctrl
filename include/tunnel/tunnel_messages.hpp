#pragma once

#include <boost/json.hpp>
#include <string>
#include <unordered_map>

namespace certctrl {

using HeaderMap = std::unordered_map<std::string, std::string>;

struct TunnelHello {
  std::string type{"hello"};
  std::string tunnel_id;
  std::string local_base_url;
};

struct TunnelRequest {
  std::string type{"request"};
  std::string id;
  std::string method;
  std::string path;
  HeaderMap headers;
  std::string body;
};

struct TunnelResponse {
  std::string type{"response"};
  std::string id;
  int status{200};
  HeaderMap headers;
  std::string body;
};

struct TunnelPing {
  std::string type{"ping"};
  std::uint64_t ts{0};
};

struct TunnelPong {
  std::string type{"pong"};
  std::uint64_t ts{0};
};

void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const TunnelHello &hello);
void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const TunnelRequest &req);
void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const TunnelResponse &res);
void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const TunnelPing &ping);
void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                const TunnelPong &pong);

TunnelHello tag_invoke(const boost::json::value_to_tag<TunnelHello> &,
                       const boost::json::value &jv);
TunnelRequest tag_invoke(const boost::json::value_to_tag<TunnelRequest> &,
                         const boost::json::value &jv);
TunnelResponse tag_invoke(const boost::json::value_to_tag<TunnelResponse> &,
                          const boost::json::value &jv);
TunnelPing tag_invoke(const boost::json::value_to_tag<TunnelPing> &,
                      const boost::json::value &jv);
TunnelPong tag_invoke(const boost::json::value_to_tag<TunnelPong> &,
                      const boost::json::value &jv);

} // namespace certctrl
