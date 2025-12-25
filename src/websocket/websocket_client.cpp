#include "websocket/websocket_client.hpp"

#include "websocket/websocket_messages.hpp"

#include "data/data_shape.hpp"
#include "simple_data.hpp"
#include "handlers/install_config_manager.hpp"
#include "handlers/signal_dispatcher.hpp"
#include "handlers/signal_handlers/ca_assigned_handler.hpp"
#include "handlers/signal_handlers/ca_unassigned_handler.hpp"
#include "handlers/signal_handlers/cert_updated_handler.hpp"
#include "handlers/signal_handlers/cert_unassigned_handler.hpp"
#include "handlers/signal_handlers/config_updated_handler.hpp"
#include "handlers/signal_handlers/install_updated_handler.hpp"
#include "handlers/signal_handlers/acme_http01_challenge_handler.hpp"
#include "handlers/signal_handlers/acme_http01_stop_handler.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/json.hpp>
#include <boost/url.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <deque>
#include <fstream>
#include <filesystem>
#include <fmt/format.h>
#include <openssl/err.h>
#include <random>
#include <string_view>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <jwt-cpp/jwt.h>

#include "handlers/session_refresher.hpp"

namespace certctrl {
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
namespace json = boost::json;
namespace urls = boost::urls;
namespace http = beast::http;
using tcp = net::ip::tcp;

namespace {

struct EndpointParts {
  bool secure{true};
  std::string host;
  std::string port{"443"};
  std::string target{"/"};
};

struct LocalEndpointParts {
  std::string host;
  std::string port{"80"};
  std::string base_path{"/"};
  std::string host_header;
};

std::optional<std::string> DecodeDeviceIdFromJwt(const std::string &token) {
  try {
    auto decoded = jwt::decode(token);
    boost::system::error_code ec;
    auto jv = boost::json::parse(decoded.get_payload(), ec);
    if (!ec && jv.is_object()) {
      const auto &obj = jv.as_object();
      if (auto *did = obj.if_contains("device_id")) {
        if (did->is_int64()) {
          return std::to_string(did->as_int64());
        }
        if (did->is_uint64()) {
          return std::to_string(did->as_uint64());
        }
        if (did->is_string()) {
          return std::string(did->as_string().c_str());
        }
      }
    }
  } catch (...) {
  }
  return std::nullopt;
}

bool IsJwtExpiringSoon(const std::string &token, std::chrono::seconds skew) {
  try {
    auto decoded = jwt::decode(token);
    if (!decoded.has_payload_claim("exp")) {
      return false;
    }
    const auto exp_time = decoded.get_payload_claim("exp").as_date();
    const auto now = std::chrono::system_clock::now();
    return exp_time <= now + skew;
  } catch (...) {
    // If token cannot be decoded, treat it as unusable and attempt refresh.
    return true;
  }
}

bool QueryHasKey(std::string_view query, std::string_view key) {
  while (!query.empty()) {
    const auto amp = query.find('&');
    std::string_view part = (amp == std::string_view::npos)
                                ? query
                                : query.substr(0, amp);
    const auto eq = part.find('=');
    std::string_view k = (eq == std::string_view::npos) ? part : part.substr(0, eq);
    if (k == key) {
      return true;
    }
    if (amp == std::string_view::npos) {
      break;
    }
    query.remove_prefix(amp + 1);
  }
  return false;
}

std::string EnsureQueryParam(std::string target, std::string_view key,
                             std::string_view value) {
  const auto qm = target.find('?');
  std::string_view query = (qm == std::string::npos)
                               ? std::string_view{}
                               : std::string_view(target).substr(qm + 1);
  if (!query.empty() && QueryHasKey(query, key)) {
    return target;
  }
  if (qm == std::string::npos) {
    target.append("?");
  } else if (qm + 1 != target.size()) {
    target.append("&");
  }
  target.append(key);
  target.append("=");
  target.append(value);
  return target;
}

std::string EnsureDeviceIdPath(std::string target, std::string_view device_id) {
  const auto qm = target.find('?');
  const std::string query = (qm == std::string::npos) ? std::string{}
                                                      : target.substr(qm);
  std::string path = (qm == std::string::npos) ? target : target.substr(0, qm);
  if (path.empty()) {
    path = "/";
  }
  // Avoid double-appending if already present.
  const std::string suffix = std::string("/") + std::string(device_id);
  if (path.size() >= suffix.size() &&
      path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0) {
    return path + query;
  }
  if (!path.empty() && path.back() != '/') {
    path.push_back('/');
  }
  path.append(device_id);
  return path + query;
}

std::string ParseIngressPath(const std::string &webhook_base_url) {
  auto parsed = urls::parse_uri(webhook_base_url);
  if (!parsed) {
    throw std::runtime_error(
        fmt::format("invalid webhook_base_url '{}': {}", webhook_base_url,
                    parsed.error().message()));
  }
  const auto &url = parsed.value();
  std::string path = std::string(url.encoded_path());
  if (path.empty()) {
    path = "/";
  }
  while (path.size() > 1 && path.back() == '/') {
    path.pop_back();
  }
  return path;
}

EndpointParts ParseEndpoint(const std::string &endpoint) {
  auto parsed = urls::parse_uri(endpoint);
  if (!parsed) {
    throw std::runtime_error(fmt::format("invalid websocket endpoint '{}': {}",
                                         endpoint, parsed.error().message()));
  }
  const auto &url = parsed.value();
  if (!url.has_authority() || url.host().empty()) {
    throw std::runtime_error(
        fmt::format("websocket endpoint missing host: '{}'", endpoint));
  }

  EndpointParts parts;
  const auto scheme = url.scheme();
  if (scheme != "wss") {
    throw std::runtime_error(fmt::format(
        "websocket endpoint must use wss:// scheme (got '{}')", scheme));
  }
  parts.host = std::string(url.host());
  parts.port = url.has_port() ? std::string(url.port()) : std::string("443");
  std::string target = std::string(url.encoded_path());
  if (target.empty()) {
    target = "/";
  }
  if (url.has_query()) {
    target += "?";
    target += std::string(url.encoded_query());
  }
  parts.target = target;
  return parts;
}

LocalEndpointParts ParseLocalEndpoint(const std::string &endpoint) {
  auto parsed = urls::parse_uri(endpoint);
  if (!parsed) {
    throw std::runtime_error(fmt::format("invalid local_base_url '{}': {}",
                                         endpoint, parsed.error().message()));
  }
  const auto &url = parsed.value();
  if (!url.has_authority() || url.host().empty()) {
    throw std::runtime_error(
        fmt::format("local_base_url missing host: '{}'", endpoint));
  }
  if (url.scheme() != "http") {
    throw std::runtime_error(fmt::format(
        "local_base_url must use http:// scheme (got '{}')", url.scheme()));
  }
  LocalEndpointParts parts;
  parts.host = std::string(url.host());
  parts.port = url.has_port() ? std::string(url.port()) : std::string("80");
  std::string base_path = std::string(url.encoded_path());
  if (base_path.empty()) {
    base_path = "/";
  }
  parts.base_path = base_path;
  parts.host_header = parts.host;
  if (url.has_port() && parts.port != "80") {
    parts.host_header += ':';
    parts.host_header += parts.port;
  }
  return parts;
}

std::string ToLowerCopy(std::string value) {
  std::transform(
      value.begin(), value.end(), value.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

std::shared_ptr<std::unordered_set<std::string>>
BuildHeaderAllowlist(const std::vector<std::string> &names) {
  auto set = std::make_shared<std::unordered_set<std::string>>();
  set->reserve(names.size());
  for (const auto &name : names) {
    set->insert(ToLowerCopy(name));
  }
  return set;
}

std::string NormalizeIncomingPath(const std::string &path) {
  if (path.empty()) {
    return "/";
  }
  if (path[0] != '/') {
    return '/' + path;
  }
  return path;
}

bool StartsWith(std::string_view value, std::string_view prefix) {
  return value.size() >= prefix.size() &&
         value.substr(0, prefix.size()) == prefix;
}

struct PathAndQuery {
  std::string_view path;
  std::string_view query; // includes leading '?', or empty
};

PathAndQuery SplitPathAndQuery(std::string_view incoming) {
  const auto pos = incoming.find('?');
  if (pos == std::string_view::npos) {
    return PathAndQuery{incoming, std::string_view{}};
  }
  return PathAndQuery{incoming.substr(0, pos), incoming.substr(pos)};
}

std::string JoinLocalPath(const std::string &base_path,
                          const std::string &incoming) {
  const std::string normalized = NormalizeIncomingPath(incoming);
  if (base_path.empty() || base_path == "/") {
    return normalized;
  }
  if (base_path.back() == '/') {
    if (normalized.size() > 1) {
      return base_path + normalized.substr(1);
    }
    return base_path;
  }
  if (normalized == "/") {
    return base_path;
  }
  return base_path + normalized;
}

std::uint64_t NowMillis() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

} // namespace

class WebsocketClient::Session
    : public std::enable_shared_from_this<WebsocketClient::Session> {
public:
  Session(WebsocketClient &client, WebsocketConfig config, EndpointParts endpoint,
          LocalEndpointParts local_endpoint, std::string auth_token)
      : client_(client), config_(std::move(config)),
        endpoint_(std::move(endpoint)),
        local_endpoint_(std::move(local_endpoint)),
      webhook_ingress_path_(ParseIngressPath(config_.webhook_base_url)),
      compiled_routes_(CompileRoutes(config_.tunnel, local_endpoint_)),
      header_allowlist_(BuildHeaderAllowlist(config_.tunnel.header_allowlist)),
        auth_token_(std::move(auth_token)),
        max_payload_bytes_(
            static_cast<std::size_t>(std::max(0, config_.max_payload_bytes))),
        resolver_(net::make_strand(client.ioc_)),
        ssl_ctx_(ssl::context::tls_client),
        ws_(net::make_strand(client.ioc_), ssl_ctx_), ping_timer_(client.ioc_) {
    ConfigureSsl();
    ws_.text(true);
  }

  void Start() { Resolve(); }

  void Stop() {
    closing_ = true;
    CancelLocalCalls();
    resolver_.cancel();
    ping_timer_.cancel();
    if (ws_.is_open()) {
      ws_.async_close(
          websocket::close_code::normal,
          beast::bind_front_handler(&Session::OnClose, shared_from_this()));
    } else {
      NotifyClosed(false);
    }
  }

private:
  struct CompiledRoute {
    std::string match_prefix;
    bool has_override_endpoint{false};
    LocalEndpointParts endpoint;
    bool has_rewrite{false};
    std::string rewrite_prefix;
  };

  struct ResolvedLocalTarget {
    LocalEndpointParts endpoint;
    std::string target;
  };

  static std::vector<CompiledRoute>
  CompileRoutes(const WebsocketConfig::Tunnel &tunnel,
                const LocalEndpointParts &default_endpoint) {
    std::vector<CompiledRoute> compiled;
    compiled.reserve(tunnel.routes.size());
    for (const auto &rule : tunnel.routes) {
      if (rule.match_prefix.empty()) {
        continue;
      }
      CompiledRoute out;
      out.match_prefix = NormalizeIncomingPath(rule.match_prefix);
      out.endpoint = default_endpoint;
      if (rule.local_base_url.has_value() && !rule.local_base_url->empty()) {
        out.endpoint = ParseLocalEndpoint(*rule.local_base_url);
        out.has_override_endpoint = true;
      }
      if (rule.rewrite_prefix.has_value()) {
        out.has_rewrite = true;
        if (rule.rewrite_prefix->empty()) {
          out.rewrite_prefix.clear();
        } else {
          out.rewrite_prefix = NormalizeIncomingPath(*rule.rewrite_prefix);
        }
      }
      compiled.push_back(std::move(out));
    }
    return compiled;
  }

  ResolvedLocalTarget ResolveLocalTarget(const std::string &incoming) const {
    std::string normalized = NormalizeIncomingPath(incoming);
    const auto parts = SplitPathAndQuery(std::string_view(normalized));
    const std::string original_path_only(parts.path);
    std::string effective_path_only = original_path_only;

    if (!websocket_id_.empty() && !webhook_ingress_path_.empty()) {
      const std::string prefix =
          JoinLocalPath(webhook_ingress_path_, "/" + websocket_id_);
      if (StartsWith(std::string_view(effective_path_only), prefix)) {
        const auto next_pos = prefix.size();
        if (effective_path_only.size() == next_pos) {
          effective_path_only = "/";
        } else if (effective_path_only[next_pos] == '/') {
          effective_path_only = effective_path_only.substr(next_pos);
        }
      }
    }

    const std::string_view path_only = std::string_view(effective_path_only);

    for (const auto &route : compiled_routes_) {
      if (!StartsWith(path_only, route.match_prefix)) {
        continue;
      }

      std::string effective_path;
      if (!route.has_rewrite) {
        effective_path.assign(path_only);
      } else {
        std::string_view remainder = path_only.substr(route.match_prefix.size());
        if (remainder.empty()) {
          remainder = "/";
        }
        if (route.rewrite_prefix.empty()) {
          effective_path.assign(remainder);
        } else {
          effective_path = JoinLocalPath(route.rewrite_prefix,
                                         std::string(remainder));
        }
      }

      std::string target =
          JoinLocalPath(route.endpoint.base_path, effective_path);
      if (!parts.query.empty()) {
        target += std::string(parts.query);
      }

      return ResolvedLocalTarget{route.endpoint, std::move(target)};
    }

    std::string target = JoinLocalPath(local_endpoint_.base_path, original_path_only);
    if (!parts.query.empty()) {
      target += std::string(parts.query);
    }
    return ResolvedLocalTarget{local_endpoint_, std::move(target)};
  }

  class LocalCall : public std::enable_shared_from_this<LocalCall> {
  public:
    LocalCall(std::shared_ptr<Session> session, WebsocketRequest request,
              LocalEndpointParts local_endpoint, std::string local_target)
        : session_(session), request_(std::move(request)),
          local_endpoint_(std::move(local_endpoint)),
          local_target_(std::move(local_target)),
          max_payload_bytes_(session->max_payload_bytes_),
          request_timeout_seconds_(
              std::max(1, session->config_.request_timeout_seconds)),
          resolver_(net::make_strand(session->client_.ioc_)),
          stream_(net::make_strand(session->client_.ioc_)),
          deadline_(session->client_.ioc_) {}

    const std::string &Id() const { return request_.id; }

    void Start() {
      auto self = shared_from_this();
      if (request_timeout_seconds_ > 0) {
        deadline_.expires_after(std::chrono::seconds(request_timeout_seconds_));
        deadline_.async_wait(
            beast::bind_front_handler(&LocalCall::OnTimeout, self));
      }
      if (auto session = session_.lock()) {
        BuildHttpRequest(*session);
        resolver_.async_resolve(
            local_endpoint_.host, local_endpoint_.port,
            beast::bind_front_handler(&LocalCall::OnResolve, self));
      }
    }

    void Cancel() {
      completed_ = true;
      deadline_.cancel();
      resolver_.cancel();
      beast::error_code ec;
      auto cancelled = stream_.socket().cancel(ec);
      auto closed = stream_.socket().close(ec);
      (void)cancelled;
      (void)closed;
    }

  private:
    void BuildHttpRequest(Session &session) {
      http_request_.version(11);
      auto verb = http::string_to_verb(request_.method);
      if (verb == http::verb::unknown) {
        http_request_.method(http::verb::unknown);
        http_request_.method_string(request_.method);
      } else {
        http_request_.method(verb);
      }
      http_request_.target(local_target_);
      http_request_.body() = request_.body;
      http_request_.prepare_payload();
      const std::string host_value = local_endpoint_.host_header.empty()
                                         ? local_endpoint_.host
                                         : local_endpoint_.host_header;
      http_request_.set(http::field::host, host_value);
      http_request_.set(http::field::user_agent,
                        "cert-ctrl-websocket/local-forwarder");
      http_request_.set(http::field::connection, "close");
      session.ApplyAllowlistedHeaders(http_request_, request_.headers);
    }

    void OnResolve(const beast::error_code &ec,
                   tcp::resolver::results_type results) {
      if (ec) {
        Fail(502, fmt::format("local resolve failed: {}", ec.message()));
        return;
      }
      stream_.expires_after(std::chrono::seconds(request_timeout_seconds_));
      stream_.async_connect(
          results,
          beast::bind_front_handler(&LocalCall::OnConnect, shared_from_this()));
    }

    void OnConnect(const beast::error_code &ec,
                   const tcp::resolver::results_type::endpoint_type &) {
      if (ec) {
        Fail(502, fmt::format("local connect failed: {}", ec.message()));
        return;
      }
      http::async_write(
          stream_, http_request_,
          beast::bind_front_handler(&LocalCall::OnWrite, shared_from_this()));
    }

    void OnWrite(const beast::error_code &ec, std::size_t) {
      if (ec) {
        Fail(502, fmt::format("local write failed: {}", ec.message()));
        return;
      }
      http::async_read(
          stream_, buffer_, http_response_,
          beast::bind_front_handler(&LocalCall::OnRead, shared_from_this()));
    }

    void OnRead(const beast::error_code &ec, std::size_t) {
      if (ec) {
        Fail(502, fmt::format("local read failed: {}", ec.message()));
        return;
      }
      if (http_response_.body().size() > max_payload_bytes_) {
        Fail(502, "local response exceeded payload limit");
        return;
      }
      WebsocketResponse res;
      res.id = request_.id;
      res.status = http_response_.result_int();
      res.body = std::move(http_response_.body());
      for (const auto &field : http_response_) {
        res.headers.emplace(std::string(field.name_string()),
                            std::string(field.value()));
      }
      CompleteSuccess(std::move(res));
    }

    void OnTimeout(const beast::error_code &ec) {
      if (ec == net::error::operation_aborted) {
        return;
      }
      beast::error_code ignore;
      auto cancelled = stream_.socket().cancel(ignore);
      (void)cancelled;
      Fail(504, "local request timeout");
    }

    void CompleteSuccess(WebsocketResponse &&res) {
      if (completed_) {
        return;
      }
      completed_ = true;
      deadline_.cancel();
      if (auto session = session_.lock()) {
        session->OnLocalCallSuccess(std::move(res));
      }
    }

    void Fail(int status, std::string message) {
      if (completed_) {
        return;
      }
      completed_ = true;
      deadline_.cancel();
      if (auto session = session_.lock()) {
        session->OnLocalCallFailure(request_.id, status, std::move(message));
      }
    }

    std::weak_ptr<Session> session_;
    WebsocketRequest request_;
    LocalEndpointParts local_endpoint_;
    std::string local_target_;
    std::size_t max_payload_bytes_{0};
    int request_timeout_seconds_{0};
    tcp::resolver resolver_;
    beast::tcp_stream stream_;
    net::steady_timer deadline_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> http_request_;
    http::response<http::string_body> http_response_;
    bool completed_{false};
  };

  void ConfigureSsl() {
    if (config_.verify_tls) {
      try {
        ssl_ctx_.set_default_verify_paths();
        ws_.next_layer().set_verify_mode(ssl::verify_peer);
      } catch (const std::exception &ex) {
        client_.output_.logger().warning()
            << "Websocket TLS verify setup failed, continuing: " << ex.what()
            << std::endl;
      }
    } else {
      ws_.next_layer().set_verify_mode(ssl::verify_none);
    }
  }

  void Resolve() {
    client_.output_.logger().info() << "Websocket resolving " << endpoint_.host
                                    << ':' << endpoint_.port << std::endl;
    resolver_.async_resolve(
        endpoint_.host, endpoint_.port,
        beast::bind_front_handler(&Session::OnResolve, shared_from_this()));
  }

  void OnResolve(const beast::error_code &ec,
                 tcp::resolver::results_type results) {
    if (ec) {
      Fail("resolve", ec);
      return;
    }
    beast::get_lowest_layer(ws_).expires_after(
        std::chrono::seconds(std::max(5, config_.request_timeout_seconds)));
    beast::get_lowest_layer(ws_).async_connect(
        results,
        beast::bind_front_handler(&Session::OnConnect, shared_from_this()));
  }

  void OnConnect(const beast::error_code &ec,
                 const tcp::resolver::results_type::endpoint_type &) {
    if (ec) {
      Fail("connect", ec);
      return;
    }
    if (config_.verify_tls) {
      if (!SSL_set_tlsext_host_name(ws_.next_layer().native_handle(),
                                    endpoint_.host.c_str())) {
        beast::error_code sni_error{static_cast<int>(::ERR_get_error()),
                                    net::error::get_ssl_category()};
        Fail("set_sni", sni_error);
        return;
      }
    }
    ws_.next_layer().async_handshake(
        ssl::stream_base::client,
        beast::bind_front_handler(&Session::OnTlsHandshake,
                                  shared_from_this()));
  }

  void OnTlsHandshake(const beast::error_code &ec) {
    if (ec) {
      Fail("tls_handshake", ec);
      return;
    }
    ws_.set_option(
        websocket::stream_base::timeout::suggested(beast::role_type::client));
    const std::string token = auth_token_;
    ws_.set_option(websocket::stream_base::decorator(
        [token](websocket::request_type &req) {
          req.set(http::field::user_agent, std::string("cert-ctrl-websocket/") +
                                               BOOST_BEAST_VERSION_STRING);
          if (!token.empty()) {
            req.set(http::field::authorization, std::string("Bearer ") + token);
          }
        }));
    std::string host_header = endpoint_.host;
    if (endpoint_.port != "443") {
      host_header.append(":");
      host_header.append(endpoint_.port);
    }
    ws_.async_handshake(
        host_header, endpoint_.target,
        beast::bind_front_handler(&Session::OnWsHandshake, shared_from_this()));
  }

  void OnWsHandshake(const beast::error_code &ec) {
    if (ec) {
      Fail("ws_handshake", ec);
      return;
    }
    client_.output_.logger().info()
        << "Websocket websocket established to " << endpoint_.host
        << endpoint_.target << std::endl;
    client_.HandleSessionConnected();
    StartRead();
    SchedulePing();
  }

  void StartRead() {
    ws_.async_read(read_buffer_, beast::bind_front_handler(&Session::OnRead,
                                                           shared_from_this()));
  }

  void OnRead(const beast::error_code &ec, std::size_t bytes_transferred) {
    if (ec) {
      if (ec == net::error::operation_aborted) {
        return;
      }
      if (ec == websocket::error::closed) {
        client_.output_.logger().warning()
            << "Websocket websocket closed by peer" << std::endl;
        NotifyClosed(true);
        return;
      }
      Fail("read", ec);
      return;
    }
    std::string payload{beast::buffers_to_string(read_buffer_.data())};
    read_buffer_.consume(bytes_transferred);
    try {
      auto message = json::parse(payload);
      HandleMessage(message);
    } catch (const std::exception &ex) {
      client_.output_.logger().error()
          << "Websocket received invalid JSON: " << ex.what() << std::endl;
    }
    StartRead();
  }

  void HandleMessage(const json::value &jv) {
    if (!jv.is_object()) {
      client_.output_.logger().warning()
          << "Websocket received non-object payload" << std::endl;
      return;
    }
    const auto &obj = jv.as_object();
    const auto *type_field = obj.if_contains("type");
    if (!type_field || !type_field->is_string()) {
      client_.output_.logger().warning()
          << "Websocket payload missing type field" << std::endl;
      return;
    }
    const std::string type = std::string(type_field->as_string().c_str());

    if (type == "event") {
      try {
        auto env = json::value_to<certctrl::WebsocketEventEnvelope>(jv);

        if (env.name == "updates.signal") {
          HandleUpdatesSignal(env);
          return;
        }

        auto legacy = certctrl::TryConvertEventEnvelopeToLegacyMessage(env);
        if (!legacy) {
          client_.output_.logger().debug()
              << "Websocket ignoring unknown event name: " << env.name
              << std::endl;
          return;
        }
        HandleMessage(*legacy);
        return;
      } catch (const std::exception &ex) {
        client_.output_.logger().warning()
            << "Websocket received invalid event envelope: " << ex.what()
            << std::endl;
        return;
      }
    }

    if (type == "hello") {
      HandleHello(jv);
    } else if (type == "request") {
      HandleRequest(jv);
    } else if (type == "ping") {
      HandlePing(jv);
    } else if (type == "pong") {
      HandlePong(jv);
    } else {
      client_.output_.logger().debug()
          << "Websocket ignoring message type: " << type << std::endl;
    }
  }

  void HandleUpdatesSignal(const certctrl::WebsocketEventEnvelope &env) {
    if (!client_.signal_dispatcher_) {
      client_.output_.logger().warning()
          << "Websocket received updates.signal but signal dispatcher is not initialized"
          << std::endl;
      return;
    }

    const auto ack_id = env.id;
    const auto resume_token = env.resume_token;

    if (!env.payload.is_object()) {
      client_.output_.logger().warning()
          << "Websocket updates.signal payload must be an object" << std::endl;
      return;
    }

    ::data::DeviceUpdateSignal signal;
    try {
      signal = json::value_to<::data::DeviceUpdateSignal>(env.payload);
    } catch (const std::exception &ex) {
      client_.output_.logger().warning()
          << "Websocket failed to parse updates.signal payload: " << ex.what()
          << std::endl;
      return;
    }

    auto self = shared_from_this();
    client_.signal_dispatcher_->dispatch(signal).run(
        [self, logger = &client_.output_.logger(), type = signal.type, ack_id,
         resume_token](auto r) {
          if (r.is_err()) {
            logger->warning()
                << "updates.signal dispatch failed for type=" << type
                << " error=" << r.error().what << std::endl;
            return;
          }

          net::post(self->ws_.get_executor(), [self, ack_id, resume_token]() {
            if (resume_token && !resume_token->empty()) {
              if (auto err =
                      self->client_.state_store_.save_websocket_resume_token(
                          resume_token)) {
                self->client_.output_.logger().warning()
                    << "Failed to persist websocket resume token: " << *err
                    << std::endl;
              }
            }
            if (ack_id && !ack_id->empty()) {
              self->SendUpdatesAck(*ack_id, resume_token);
            }
          });
        });
  }

  void SendUpdatesAck(const std::string &ack_id,
                      const std::optional<std::string> &resume_token) {
    certctrl::WebsocketEventEnvelope ack;
    ack.name = "updates.ack";
    ack.id = ack_id;
    ack.ts_ms = NowMillis();
    ack.resume_token = resume_token;
    ack.payload = json::object{};
    Enqueue(json::value_from(ack));
  }

  void HandleHello(const json::value &jv) {
    try {
      auto hello = json::value_to<WebsocketHello>(jv);
      hello_received_ = true;
      websocket_id_ = hello.connection_id;
      client_.output_.logger().info()
          << "Websocket handshake hello for websocket_id=" << websocket_id_
          << std::endl;

      SendHelloAck();
    } catch (const std::exception &ex) {
      client_.output_.logger().error()
          << "Failed to parse websocket hello: " << ex.what() << std::endl;
    }
  }

  void SendHelloAck() {
    certctrl::WebsocketEventEnvelope env;
    env.name = "lifecycle.hello_ack";
    env.ts_ms = NowMillis();
    env.resume_token = client_.state_store_.get_websocket_resume_token();
    env.payload = json::object{{"connection_id", websocket_id_}};
    Enqueue(json::value_from(env));
  }

  void HandleRequest(const json::value &jv) {
    WebsocketRequest req;
    try {
      req = json::value_to<WebsocketRequest>(jv);
    } catch (const std::exception &ex) {
      client_.output_.logger().error()
          << "Failed to parse websocket request: " << ex.what() << std::endl;
      return;
    }

    if (req.body.size() > max_payload_bytes_) {
      SendImmediateError(req.id, 413, "payload exceeds websocket limit");
      return;
    }

    if (config_.max_concurrent_requests > 0 &&
        in_flight_requests_ >= config_.max_concurrent_requests) {
      SendImmediateError(req.id, 429, "too many concurrent websocket requests");
      return;
    }

    if (local_calls_.find(req.id) != local_calls_.end()) {
      SendImmediateError(req.id, 409, "duplicate websocket request id");
      return;
    }

    auto resolved = ResolveLocalTarget(req.path);
    auto self = shared_from_this();
    auto call = std::make_shared<LocalCall>(self, std::move(req),
                                            std::move(resolved.endpoint),
                                            std::move(resolved.target));
    local_calls_.emplace(call->Id(), call);
    ++in_flight_requests_;
    call->Start();
  }

  void HandlePing(const json::value &jv) {
    try {
      auto ping = json::value_to<WebsocketPing>(jv);
      WebsocketPong pong;
      pong.ts = ping.ts ? ping.ts : NowMillis();
      Enqueue(json::value_from(pong));
    } catch (const std::exception &ex) {
      client_.output_.logger().warning()
          << "Failed to parse websocket ping: " << ex.what() << std::endl;
    }
  }

  void HandlePong(const json::value &jv) {
    try {
      auto pong = json::value_to<WebsocketPong>(jv);
      client_.output_.logger().debug()
          << "Websocket pong ts=" << pong.ts << std::endl;
    } catch (const std::exception &ex) {
      client_.output_.logger().warning()
          << "Failed to parse websocket pong: " << ex.what() << std::endl;
    }
  }

  void OnLocalCallSuccess(WebsocketResponse &&res) {
    DeliverResponse(std::move(res));
    CompleteLocalRequest(res.id);
  }

  void OnLocalCallFailure(const std::string &request_id, int status,
                          std::string message) {
    SendImmediateError(request_id, status, std::move(message));
    CompleteLocalRequest(request_id);
  }

  void SchedulePing() {
    auto interval = std::max(1, config_.ping_interval_seconds);
    ping_timer_.expires_after(std::chrono::seconds(interval));
    ping_timer_.async_wait(
        beast::bind_front_handler(&Session::OnPingTimer, shared_from_this()));
  }

  void OnPingTimer(const beast::error_code &ec) {
    if (ec) {
      if (ec != net::error::operation_aborted) {
        client_.output_.logger().warning()
            << "Websocket ping timer error: " << ec.message() << std::endl;
      }
      return;
    }
    SendPing();
    SchedulePing();
  }

  void SendPing() {
    WebsocketPing ping;
    ping.ts = NowMillis();
    Enqueue(json::value_from(ping));
  }

  void Enqueue(json::value &&jv) {
    auto payload = json::serialize(jv);
    write_queue_.push_back(std::move(payload));
    if (write_queue_.size() == 1) {
      DoWrite();
    }
  }

  void DoWrite() {
    ws_.async_write(
        net::buffer(write_queue_.front()),
        beast::bind_front_handler(&Session::OnWrite, shared_from_this()));
  }

  void OnWrite(const beast::error_code &ec, std::size_t) {
    if (ec) {
      if (ec == net::error::operation_aborted) {
        return;
      }
      Fail("write", ec);
      return;
    }
    write_queue_.pop_front();
    if (!write_queue_.empty()) {
      DoWrite();
    }
  }

  void SendImmediateError(const std::string &request_id, int status,
                          std::string message) {
    WebsocketResponse res;
    res.id = request_id;
    res.status = status;
    res.body = std::move(message);
    res.headers = {{"content-type", "text/plain"}};
    DeliverResponse(std::move(res));
  }

  void DeliverResponse(WebsocketResponse &&response) {
    Enqueue(json::value_from(response));
  }

  void CompleteLocalRequest(const std::string &request_id) {
    auto it = local_calls_.find(request_id);
    if (it != local_calls_.end()) {
      local_calls_.erase(it);
    }
    if (in_flight_requests_ > 0) {
      --in_flight_requests_;
    }
  }

  void CancelLocalCalls() {
    for (auto &kv : local_calls_) {
      kv.second->Cancel();
    }
    local_calls_.clear();
    in_flight_requests_ = 0;
  }

  bool HeaderAllowed(const std::string &name) const {
    if (!header_allowlist_) {
      return false;
    }
    return header_allowlist_->count(ToLowerCopy(name)) > 0;
  }

  void ApplyAllowlistedHeaders(http::fields &fields,
                               const HeaderMap &headers) const {
    if (!header_allowlist_) {
      return;
    }
    for (const auto &kv : headers) {
      if (HeaderAllowed(kv.first)) {
        fields.set(kv.first, kv.second);
      }
    }
  }

  void OnClose(const beast::error_code &ec) {
    if (ec && ec != net::error::operation_aborted) {
      client_.output_.logger().warning()
          << "Websocket websocket close error: " << ec.message() << std::endl;
    }
    NotifyClosed(false);
  }

  void Fail(const char *context, const beast::error_code &ec) {
    if (ec == net::error::operation_aborted && closing_) {
      NotifyClosed(false);
      return;
    }
    client_.output_.logger().error()
        << "Websocket " << context << " error: " << ec.message() << std::endl;

    if (std::string_view(context) == "ws_handshake") {
      const std::string msg = ec.message();
      const bool looks_like_rejection =
          (msg.find("declined") != std::string::npos) ||
          (msg.find("handshake") != std::string::npos) ||
          (msg.find("upgrade") != std::string::npos);

      if (looks_like_rejection) {
        client_.output_.logger().warning()
            << "Websocket handshake failed. This is often caused by authorization "
               "failure (token expired / device not registered) or a server/proxy "
               "rejecting the WebSocket upgrade. If this device should be online, "
               "re-run the device onboarding/registration flow to obtain a fresh token."
            << std::endl;
      }
    }

    NotifyClosed(true);
  }

  void NotifyClosed(bool should_retry) {
    if (notified_close_) {
      return;
    }
    notified_close_ = true;
    CancelLocalCalls();
    ping_timer_.cancel();
    resolver_.cancel();
    client_.HandleSessionClosed(should_retry && !closing_);
  }

  WebsocketClient &client_;
  WebsocketConfig config_;
  EndpointParts endpoint_;
  LocalEndpointParts local_endpoint_;
  std::vector<CompiledRoute> compiled_routes_;
  std::shared_ptr<std::unordered_set<std::string>> header_allowlist_;
  std::unordered_map<std::string, std::shared_ptr<LocalCall>> local_calls_;
  std::size_t max_payload_bytes_{0};
  int in_flight_requests_{0};
  tcp::resolver resolver_;
  ssl::context ssl_ctx_;
  websocket::stream<ssl::stream<beast::tcp_stream>> ws_;
  beast::flat_buffer read_buffer_;
  net::steady_timer ping_timer_;
  std::deque<std::string> write_queue_;
  bool closing_{false};
  bool notified_close_{false};
  bool hello_received_{false};
  std::string websocket_id_;
  std::string webhook_ingress_path_;
  std::string auth_token_;
};

WebsocketClient::WebsocketClient(cjj365::IoContextManager &io_context_manager,
                                 IWebsocketConfigProvider &config_provider,
                                 certctrl::ICertctrlConfigProvider &certctrl_config_provider,
                                 customio::ConsoleOutput &output,
                                 cjj365::ConfigSources &config_sources,
                                 certctrl::IDeviceStateStore &state_store,
                                 std::shared_ptr<certctrl::InstallConfigManager> install_config_manager,
                                 std::shared_ptr<certctrl::ISessionRefresher> session_refresher)
    : ioc_(io_context_manager.ioc()), config_provider_(config_provider),
      certctrl_config_provider_(certctrl_config_provider),
      output_(output), config_sources_(config_sources),
      state_store_(state_store),
      install_config_manager_(std::move(install_config_manager)),
      session_refresher_(std::move(session_refresher)),
      reconnect_timer_(ioc_), rng_(std::random_device{}()) {
  if (config_sources_.paths_.empty()) {
  output_.logger().warning()
    << "Signal dispatcher not initialized: no config source directories"
    << std::endl;
  return;
  }

  const auto config_dir = config_sources_.paths_.back();
  instance_lock_path_ = config_dir / "state" / "websocket_instance.lock";
  signal_dispatcher_ =
    std::make_unique<certctrl::SignalDispatcher>(config_dir, &state_store_);

  auto on_ws_config_updated = [this]() {
    net::dispatch(ioc_, [this]() {
      if (!running_ || stop_requested_) {
        return;
      }
      output_.logger().info()
          << "websocket config updated; restarting websocket session"
          << std::endl;
      reconnect_timer_.cancel();
      if (session_) {
        session_->Stop();
        session_.reset();
      }
      this->StartSession(config_provider_.get(), true);
    });
  };

  signal_dispatcher_->register_handler(
      std::make_shared<certctrl::signal_handlers::ConfigUpdatedHandler>(
          certctrl_config_provider_, output_, &config_provider_, on_ws_config_updated));

    auto acme_http01_mgr =
      std::make_shared<certctrl::acme::AcmeHttp01Manager>(output_);
    signal_dispatcher_->register_handler(
      std::make_shared<certctrl::signal_handlers::AcmeHttp01ChallengeHandler>(
        acme_http01_mgr));
    signal_dispatcher_->register_handler(
      std::make_shared<certctrl::signal_handlers::AcmeHttp01StopHandler>(
        acme_http01_mgr));

  if (!install_config_manager_) {
  output_.logger().warning()
    << "InstallConfigManager dependency missing; updates.signal will be ignored"
    << std::endl;
  } else {
  signal_dispatcher_->register_handler(
    std::make_shared<certctrl::signal_handlers::InstallUpdatedHandler>(
      install_config_manager_, output_));

  signal_dispatcher_->register_handler(
    std::make_shared<certctrl::signal_handlers::CertUpdatedHandler>(
      install_config_manager_, output_));

  signal_dispatcher_->register_handler(
    std::make_shared<certctrl::signal_handlers::CertUnassignedHandler>(
      install_config_manager_, output_));

  signal_dispatcher_->register_handler(
    std::make_shared<certctrl::signal_handlers::CaAssignedHandler>(
      install_config_manager_, output_));

  signal_dispatcher_->register_handler(
    std::make_shared<certctrl::signal_handlers::CaUnassignedHandler>(
      install_config_manager_, output_));
  }

  output_.logger().info() << "Websocket signal dispatcher ready (handlers="
              << signal_dispatcher_->handler_count() << ")"
              << std::endl;
}

WebsocketClient::~WebsocketClient() { Stop(); }

bool WebsocketClient::AcquireSingleInstanceLock() {
  if (instance_lock_) {
    return true;
  }

  if (instance_lock_path_.empty()) {
    output_.logger().warning()
        << "Websocket single-instance lock disabled: lock path missing"
        << std::endl;
    return true;
  }

  try {
    std::error_code ec;
    std::filesystem::create_directories(instance_lock_path_.parent_path(), ec);
    {
      std::ofstream touch(instance_lock_path_, std::ios::app);
    }

    auto lock = std::make_unique<boost::interprocess::file_lock>(
        instance_lock_path_.c_str());
    if (!lock->try_lock()) {
      return false;
    }
    instance_lock_ = std::move(lock);
    return true;
  } catch (const std::exception &ex) {
    output_.logger().warning()
        << "Websocket single-instance lock failed (continuing without lock): "
        << ex.what() << std::endl;
    return true;
  }
}

void WebsocketClient::Start() {
  const auto &config = config_provider_.get();
  BOOST_LOG_SEV(lg, trivial::trace)
      << "WebsocketClient::Start invoked (enabled=" << std::boolalpha
      << config.enabled << ", running=" << running_ << std::noboolalpha << ")";
  if (!config.enabled) {
    output_.logger().debug()
        << "Websocket client start skipped: feature disabled" << std::endl;
    return;
  }

  if (!AcquireSingleInstanceLock()) {
    output_.logger().info()
        << "Websocket client start skipped: another agent instance already holds the websocket lock"
        << std::endl;
    return;
  }
  if (running_) {
    output_.logger().debug() << "Websocket client already running" << std::endl;
    return;
  }
  running_ = true;
  stop_requested_ = false;
  LogConfiguration(config);
  BOOST_LOG_SEV(lg, trivial::debug)
      << "Starting websocket client toward " << config.remote_endpoint
      << " forwarding to " << config.tunnel.local_base_url;
    output_.logger().info()
      << "Websocket client (preview) enabling for " << config.remote_endpoint
      << " -> " << config.tunnel.local_base_url << std::endl;

  WebsocketConfig config_copy = config;
  net::dispatch(ioc_, [this, config_copy]() mutable {
    this->StartSession(std::move(config_copy), true);
  });
}

void WebsocketClient::Stop() {
  if (!running_) {
    return;
  }
  BOOST_LOG_SEV(lg, trivial::trace) << "WebsocketClient::Stop invoked";
  running_ = false;
  stop_requested_ = true;
  reconnect_timer_.cancel();
  net::dispatch(ioc_, [this]() {
    if (session_) {
      session_->Stop();
      session_.reset();
    }
  });
  output_.logger().info() << "Websocket client stopped" << std::endl;
  BOOST_LOG_SEV(lg, trivial::info) << "Websocket client stopped";
}

void WebsocketClient::LogConfiguration(const WebsocketConfig &config) {
  output_.logger().debug() << fmt::format("websocket cfg: ping={}s, timeout={}s, "
                                          "max_concurrent={}, max_payload={}B",
                                          config.ping_interval_seconds,
                                          config.request_timeout_seconds,
                                          config.max_concurrent_requests,
                                          config.max_payload_bytes)
                           << std::endl;
  BOOST_LOG_SEV(lg, trivial::trace) << fmt::format(
      "cfg ping={} timeout={} concurrent={} payload={}B verify_tls={}",
      config.ping_interval_seconds, config.request_timeout_seconds,
      config.max_concurrent_requests, config.max_payload_bytes,
      config.verify_tls);
}

void WebsocketClient::StartSession(WebsocketConfig config, bool allow_refresh) {
  if (!running_) {
    return;
  }
  BOOST_LOG_SEV(lg, trivial::debug)
      << "Starting websocket session with remote_endpoint="
      << config.remote_endpoint;
  reconnect_timer_.cancel();
  EndpointParts remote_endpoint;
  LocalEndpointParts local_endpoint;
  try {
    remote_endpoint = ParseEndpoint(config.remote_endpoint);
    local_endpoint = ParseLocalEndpoint(config.tunnel.local_base_url);
  } catch (const std::exception &ex) {
    output_.logger().error()
        << "Websocket configuration error: " << ex.what() << std::endl;
    BOOST_LOG_SEV(lg, trivial::error)
        << "Websocket configuration error: " << ex.what();
    ScheduleReconnect();
    return;
  }

  // Server contract (bbserver WebsocketHandler): device_id is required as a
  // query parameter, and authentication is via device JWT (Bearer header or
  // token query param). We prefer Authorization header; still add device_id to
  // the URL.
  std::string auth_token;
  std::string device_id;
  if (auto tok = state_store_.get_access_token(); tok && !tok->empty()) {
    auth_token = *tok;
    if (auto did = DecodeDeviceIdFromJwt(auth_token); did && !did->empty()) {
      device_id = *did;
    }
  }

  if (device_id.empty()) {
    output_.logger().warning()
        << "Websocket start skipped: cached access token missing device_id claim; "
           "run 'cert-ctrl login' to obtain a fresh device token."
        << std::endl;
    ScheduleReconnect();
    return;
  }
    // Server expects route param: /api/websocket/<device_id> (or /api/tunnel/<device_id>)
    remote_endpoint.target =
      EnsureDeviceIdPath(std::move(remote_endpoint.target), device_id);

  output_.logger().info() << "Websocket connecting to "
                          << fmt::format("wss://{}:{}{}", remote_endpoint.host,
                                         remote_endpoint.port,
                                         remote_endpoint.target)
                          << std::endl;
  // Ensure token is fresh enough; if not, refresh using the stored refresh
  // token and retry the connection.
  static constexpr std::chrono::seconds kSkew{60};
  if (allow_refresh && IsJwtExpiringSoon(auth_token, kSkew)) {
    if (!session_refresher_) {
      output_.logger().warning()
          << "Websocket access token is expired/expiring, but SessionRefresher is unavailable; "
             "run 'cert-ctrl login' or ensure refresh is configured."
          << std::endl;
      ScheduleReconnect();
      return;
    }

    output_.logger().info()
        << "Websocket access token expired/expiring; refreshing session tokens before connect."
        << std::endl;

    auto self = shared_from_this();
    session_refresher_->refresh("websocket connect")
        .run([self, cfg = std::move(config)](auto result) mutable {
          net::dispatch(self->ioc_, [self, cfg = std::move(cfg),
                                    result = std::move(result)]() mutable {
            if (!self->running_) {
              return;
            }
            if (result.is_err()) {
              self->output_.logger().warning()
                  << "Websocket token refresh failed: " << result.error().what
                  << std::endl;
              self->ScheduleReconnect();
              return;
            }
            self->StartSession(std::move(cfg), false);
          });
        });
    return;
  }

  session_ = std::make_shared<Session>(*this, std::move(config),
                                       std::move(remote_endpoint),
                                       std::move(local_endpoint),
                                       std::move(auth_token));
  session_->Start();
  BOOST_LOG_SEV(lg, trivial::trace) << "Websocket session dispatched";
}

void WebsocketClient::HandleSessionClosed(bool should_retry) {
  session_.reset();
  if (!running_) {
    return;
  }
  BOOST_LOG_SEV(lg, trivial::debug)
      << "Websocket session closed (retry=" << std::boolalpha << should_retry
      << ", stop_requested=" << stop_requested_ << std::noboolalpha << ")";
  if (!should_retry || stop_requested_) {
    output_.logger().info() << "Websocket session closed" << std::endl;
    return;
  }
  ScheduleReconnect();
}

void WebsocketClient::HandleSessionConnected() {
  BOOST_LOG_SEV(lg, trivial::info) << "Websocket session established";
  backoff_.Reset();
}

void WebsocketClient::ScheduleReconnect() {
  if (!running_) {
    return;
  }
  WebsocketConfig cfg = config_provider_.get();
  backoff_.UpdateOptions(BuildBackoffOptions(cfg));
  auto delay = backoff_.NextDelay(rng_);
  output_.logger().warning()
      << fmt::format("Websocket reconnect in {} ms", delay.count()) << std::endl;
  BOOST_LOG_SEV(lg, trivial::warning)
      << "Websocket reconnect scheduled in " << delay.count() << " ms";
  reconnect_timer_.expires_after(delay);
  auto weak = weak_from_this();
  reconnect_timer_.async_wait(
      [weak, cfg](const boost::system::error_code &ec) mutable {
        if (ec) {
          return;
        }
        auto self = weak.lock();
        if (!self || !self->running_) {
          return;
        }
        BOOST_LOG_SEV(self->lg, trivial::trace) << "Reconnect timer firing";
        self->StartSession(std::move(cfg), true);
      });
}

monad::ExponentialBackoffOptions
WebsocketClient::BuildBackoffOptions(const WebsocketConfig &config) const {
  monad::ExponentialBackoffOptions opts;
  const int initial = std::max(100, config.reconnect_initial_delay_ms);
  const int maximum = std::max(initial, config.reconnect_max_delay_ms);
  const int jitter = std::max(0, config.reconnect_jitter_ms);
  opts.initial_delay = std::chrono::milliseconds(initial);
  opts.max_delay = std::chrono::milliseconds(maximum);
  opts.jitter = std::chrono::milliseconds(jitter);
  return opts;
}

} // namespace certctrl
