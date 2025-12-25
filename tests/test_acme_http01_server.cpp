#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include "acme/acme_http01_server.hpp"

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;
using tcp = boost::asio::ip::tcp;

static http::response<http::string_body> http_get(const std::string &host,
                                                 std::uint16_t port,
                                                 const std::string &target) {
  net::io_context ioc;
  tcp::resolver resolver(ioc);
  auto results = resolver.resolve(host, std::to_string(port));

  beast::tcp_stream stream(ioc);
  stream.connect(results);

  http::request<http::empty_body> req{http::verb::get, target, 11};
  req.set(http::field::host, host);
  req.set(http::field::user_agent, "test");

  http::write(stream, req);

  beast::flat_buffer buffer;
  http::response<http::string_body> res;
  http::read(stream, buffer, res);

  boost::system::error_code ec;
  try {
    stream.socket().shutdown(tcp::socket::shutdown_both);
  } catch (...) {
  }

  return res;
}

TEST(AcmeHttp01Server, ServesExactChallengePath) {
  auto started = certctrl::acme::AcmeHttp01Server::start(
      {"127.0.0.1", 0},
      {"tok-123", "tok-123.thumb", std::chrono::seconds(30)});
  ASSERT_TRUE(started.is_ok()) << started.error().what;

  auto server = started.value();
  const auto port = server->port();
  ASSERT_NE(port, 0);

  auto ok_res = http_get("127.0.0.1", port,
                        "/.well-known/acme-challenge/tok-123");
  EXPECT_EQ(ok_res.result(), http::status::ok);
  EXPECT_EQ(ok_res.body(), "tok-123.thumb");

  auto not_found_res = http_get("127.0.0.1", port, "/nope");
  EXPECT_EQ(not_found_res.result(), http::status::not_found);

  server->stop();
}

TEST(AcmeHttp01Server, TtlStopsServer) {
  auto started = certctrl::acme::AcmeHttp01Server::start(
      {"127.0.0.1", 0},
      {"tok-ttl", "tok-ttl.thumb", std::chrono::seconds(1)});
  ASSERT_TRUE(started.is_ok()) << started.error().what;

  auto server = started.value();
  const auto port = server->port();
  ASSERT_NE(port, 0);

  std::this_thread::sleep_for(std::chrono::seconds(2));

  // Best-effort: connection should fail after TTL.
  net::io_context ioc;
  tcp::resolver resolver(ioc);
  auto results = resolver.resolve("127.0.0.1", std::to_string(port));
  beast::tcp_stream stream(ioc);

  boost::system::error_code ec;
  stream.connect(results, ec);
  EXPECT_TRUE(static_cast<bool>(ec));

  server->stop();
}
