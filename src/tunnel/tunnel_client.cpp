#include "tunnel/tunnel_client.hpp"

#include "tunnel/tunnel_messages.hpp"

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
#include <fmt/format.h>
#include <openssl/err.h>
#include <random>
#include <string_view>
#include <string>
#include <unordered_map>
#include <unordered_set>

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
    throw std::runtime_error(fmt::format("invalid tunnel endpoint '{}': {}",
                                         endpoint, parsed.error().message()));
  }
  const auto &url = parsed.value();
  if (!url.has_authority() || url.host().empty()) {
    throw std::runtime_error(
        fmt::format("tunnel endpoint missing host: '{}'", endpoint));
  }

  EndpointParts parts;
  const auto scheme = url.scheme();
  if (scheme != "wss") {
    throw std::runtime_error(fmt::format(
        "tunnel endpoint must use wss:// scheme (got '{}')", scheme));
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

class TunnelClient::Session
    : public std::enable_shared_from_this<TunnelClient::Session> {
public:
  Session(TunnelClient &client, TunnelConfig config, EndpointParts endpoint,
          LocalEndpointParts local_endpoint)
      : client_(client), config_(std::move(config)),
        endpoint_(std::move(endpoint)),
        local_endpoint_(std::move(local_endpoint)),
    webhook_ingress_path_(ParseIngressPath(config_.webhook_base_url)),
    compiled_routes_(CompileRoutes(config_, local_endpoint_)),
        header_allowlist_(BuildHeaderAllowlist(config_.header_allowlist)),
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
  CompileRoutes(const TunnelConfig &config,
                const LocalEndpointParts &default_endpoint) {
    std::vector<CompiledRoute> compiled;
    compiled.reserve(config.routes.size());
    for (const auto &rule : config.routes) {
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

    if (!tunnel_id_.empty() && !webhook_ingress_path_.empty()) {
      const std::string prefix =
          JoinLocalPath(webhook_ingress_path_, "/" + tunnel_id_);
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
    LocalCall(std::shared_ptr<Session> session, TunnelRequest request,
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
      stream_.socket().cancel(ec);
      stream_.socket().close(ec);
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
                        "cert-ctrl-tunnel/local-forwarder");
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
      TunnelResponse res;
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
      stream_.socket().cancel(ignore);
      Fail(504, "local request timeout");
    }

    void CompleteSuccess(TunnelResponse &&res) {
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
    TunnelRequest request_;
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
            << "Tunnel TLS verify setup failed, continuing: " << ex.what()
            << std::endl;
      }
    } else {
      ws_.next_layer().set_verify_mode(ssl::verify_none);
    }
  }

  void Resolve() {
    client_.output_.logger().info() << "Tunnel resolving " << endpoint_.host
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
    ws_.set_option(
        websocket::stream_base::decorator([](websocket::request_type &req) {
          req.set(http::field::user_agent, std::string("cert-ctrl-tunnel/") +
                                               BOOST_BEAST_VERSION_STRING);
        }));
    ws_.async_handshake(
        endpoint_.host, endpoint_.target,
        beast::bind_front_handler(&Session::OnWsHandshake, shared_from_this()));
  }

  void OnWsHandshake(const beast::error_code &ec) {
    if (ec) {
      Fail("ws_handshake", ec);
      return;
    }
    client_.output_.logger().info()
        << "Tunnel websocket established to " << endpoint_.host
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
            << "Tunnel websocket closed by peer" << std::endl;
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
          << "Tunnel received invalid JSON: " << ex.what() << std::endl;
    }
    StartRead();
  }

  void HandleMessage(const json::value &jv) {
    if (!jv.is_object()) {
      client_.output_.logger().warning()
          << "Tunnel received non-object payload" << std::endl;
      return;
    }
    const auto &obj = jv.as_object();
    const auto *type_field = obj.if_contains("type");
    if (!type_field || !type_field->is_string()) {
      client_.output_.logger().warning()
          << "Tunnel payload missing type field" << std::endl;
      return;
    }
    const std::string type = std::string(type_field->as_string().c_str());
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
          << "Tunnel ignoring message type: " << type << std::endl;
    }
  }

  void HandleHello(const json::value &jv) {
    try {
      auto hello = json::value_to<TunnelHello>(jv);
      hello_received_ = true;
      tunnel_id_ = hello.tunnel_id;
      client_.output_.logger().info()
          << "Tunnel handshake hello for tunnel_id=" << tunnel_id_
          << " local_base_url=" << hello.local_base_url << std::endl;
    } catch (const std::exception &ex) {
      client_.output_.logger().error()
          << "Failed to parse tunnel hello: " << ex.what() << std::endl;
    }
  }

  void HandleRequest(const json::value &jv) {
    TunnelRequest req;
    try {
      req = json::value_to<TunnelRequest>(jv);
    } catch (const std::exception &ex) {
      client_.output_.logger().error()
          << "Failed to parse tunnel request: " << ex.what() << std::endl;
      return;
    }

    if (req.body.size() > max_payload_bytes_) {
      SendImmediateError(req.id, 413, "payload exceeds tunnel limit");
      return;
    }

    if (config_.max_concurrent_requests > 0 &&
        in_flight_requests_ >= config_.max_concurrent_requests) {
      SendImmediateError(req.id, 429, "too many concurrent tunnel requests");
      return;
    }

    if (local_calls_.find(req.id) != local_calls_.end()) {
      SendImmediateError(req.id, 409, "duplicate tunnel request id");
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
      auto ping = json::value_to<TunnelPing>(jv);
      TunnelPong pong;
      pong.ts = ping.ts ? ping.ts : NowMillis();
      Enqueue(json::value_from(pong));
    } catch (const std::exception &ex) {
      client_.output_.logger().warning()
          << "Failed to parse tunnel ping: " << ex.what() << std::endl;
    }
  }

  void HandlePong(const json::value &jv) {
    try {
      auto pong = json::value_to<TunnelPong>(jv);
      client_.output_.logger().debug()
          << "Tunnel pong ts=" << pong.ts << std::endl;
    } catch (const std::exception &ex) {
      client_.output_.logger().warning()
          << "Failed to parse tunnel pong: " << ex.what() << std::endl;
    }
  }

  void OnLocalCallSuccess(TunnelResponse &&res) {
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
            << "Tunnel ping timer error: " << ec.message() << std::endl;
      }
      return;
    }
    SendPing();
    SchedulePing();
  }

  void SendPing() {
    TunnelPing ping;
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
    TunnelResponse res;
    res.id = request_id;
    res.status = status;
    res.body = std::move(message);
    res.headers = {{"content-type", "text/plain"}};
    DeliverResponse(std::move(res));
  }

  void DeliverResponse(TunnelResponse &&response) {
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
          << "Tunnel websocket close error: " << ec.message() << std::endl;
    }
    NotifyClosed(false);
  }

  void Fail(const char *context, const beast::error_code &ec) {
    if (ec == net::error::operation_aborted && closing_) {
      NotifyClosed(false);
      return;
    }
    client_.output_.logger().error()
        << "Tunnel " << context << " error: " << ec.message() << std::endl;
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

  TunnelClient &client_;
  TunnelConfig config_;
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
  std::string tunnel_id_;
  std::string webhook_ingress_path_;
};

TunnelClient::TunnelClient(cjj365::IoContextManager &io_context_manager,
                           ITunnelConfigProvider &config_provider,
                           customio::ConsoleOutput &output)
    : ioc_(io_context_manager.ioc()), config_provider_(config_provider),
      output_(output), reconnect_timer_(ioc_), rng_(std::random_device{}()) {}

TunnelClient::~TunnelClient() { Stop(); }

void TunnelClient::Start() {
  const auto &config = config_provider_.get();
  BOOST_LOG_SEV(lg, trivial::trace)
      << "TunnelClient::Start invoked (enabled=" << std::boolalpha
      << config.enabled << ", running=" << running_ << std::noboolalpha << ")";
  if (!config.enabled) {
    output_.logger().debug()
        << "Tunnel client start skipped: feature disabled" << std::endl;
    return;
  }
  if (running_) {
    output_.logger().debug() << "Tunnel client already running" << std::endl;
    return;
  }
  running_ = true;
  stop_requested_ = false;
  LogConfiguration(config);
  BOOST_LOG_SEV(lg, trivial::debug)
      << "Starting tunnel client toward " << config.remote_endpoint
      << " forwarding to " << config.local_base_url;
  output_.logger().info() << "Tunnel client (preview) enabling for "
                          << config.remote_endpoint << " → "
                          << config.local_base_url << std::endl;

  TunnelConfig config_copy = config;
  net::dispatch(ioc_, [this, config_copy]() mutable {
    StartSession(std::move(config_copy));
  });
}

void TunnelClient::Stop() {
  if (!running_) {
    return;
  }
  BOOST_LOG_SEV(lg, trivial::trace) << "TunnelClient::Stop invoked";
  running_ = false;
  stop_requested_ = true;
  reconnect_timer_.cancel();
  net::dispatch(ioc_, [this]() {
    if (session_) {
      session_->Stop();
      session_.reset();
    }
  });
  output_.logger().info() << "Tunnel client stopped" << std::endl;
  BOOST_LOG_SEV(lg, trivial::info) << "Tunnel client stopped";
}

void TunnelClient::LogConfiguration(const TunnelConfig &config) {
  output_.logger().debug() << fmt::format("tunnel cfg: ping={}s, timeout={}s, "
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

void TunnelClient::StartSession(TunnelConfig config) {
  if (!running_) {
    return;
  }
  BOOST_LOG_SEV(lg, trivial::debug)
      << "Starting tunnel session with remote_endpoint="
      << config.remote_endpoint;
  reconnect_timer_.cancel();
  EndpointParts remote_endpoint;
  LocalEndpointParts local_endpoint;
  try {
    remote_endpoint = ParseEndpoint(config.remote_endpoint);
    local_endpoint = ParseLocalEndpoint(config.local_base_url);
  } catch (const std::exception &ex) {
    output_.logger().error()
        << "Tunnel configuration error: " << ex.what() << std::endl;
    BOOST_LOG_SEV(lg, trivial::error)
        << "Tunnel configuration error: " << ex.what();
    ScheduleReconnect();
    return;
  }
  session_ = std::make_shared<Session>(*this, std::move(config),
                                       std::move(remote_endpoint),
                                       std::move(local_endpoint));
  session_->Start();
  BOOST_LOG_SEV(lg, trivial::trace) << "Tunnel session dispatched";
}

void TunnelClient::HandleSessionClosed(bool should_retry) {
  session_.reset();
  if (!running_) {
    return;
  }
  BOOST_LOG_SEV(lg, trivial::debug)
      << "Tunnel session closed (retry=" << std::boolalpha << should_retry
      << ", stop_requested=" << stop_requested_ << std::noboolalpha << ")";
  if (!should_retry || stop_requested_) {
    output_.logger().info() << "Tunnel session closed" << std::endl;
    return;
  }
  ScheduleReconnect();
}

void TunnelClient::HandleSessionConnected() {
  BOOST_LOG_SEV(lg, trivial::info) << "Tunnel session established";
  backoff_.Reset();
}

void TunnelClient::ScheduleReconnect() {
  if (!running_) {
    return;
  }
  TunnelConfig cfg = config_provider_.get();
  backoff_.UpdateOptions(BuildBackoffOptions(cfg));
  auto delay = backoff_.NextDelay(rng_);
  output_.logger().warning()
      << fmt::format("Tunnel reconnect in {} ms", delay.count()) << std::endl;
  BOOST_LOG_SEV(lg, trivial::warning)
      << "Tunnel reconnect scheduled in " << delay.count() << " ms";
  reconnect_timer_.expires_after(delay);
  reconnect_timer_.async_wait(
      [this, cfg](const boost::system::error_code &ec) mutable {
        if (ec || !running_) {
          if (ec) {
            BOOST_LOG_SEV(lg, trivial::debug)
                << "Reconnect timer cancelled: " << ec.message();
          }
          return;
        }
        BOOST_LOG_SEV(lg, trivial::trace) << "Reconnect timer firing";
        StartSession(std::move(cfg));
      });
}

monad::ExponentialBackoffOptions
TunnelClient::BuildBackoffOptions(const TunnelConfig &config) const {
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
