#include <gtest/gtest.h>

#include <boost/json.hpp>

#include "tunnel/tunnel_messages.hpp"

namespace certctrl {
namespace json = boost::json;

TEST(TunnelMessagesTest, HelloRoundTrip) {
  TunnelHello hello;
  hello.tunnel_id = "abc123";
  hello.local_base_url = "http://127.0.0.1:8080";

  auto serialized = json::value_from(hello);
  ASSERT_TRUE(serialized.is_object());
  const auto &obj = serialized.as_object();
  EXPECT_EQ(obj.at("type"), "hello");
  EXPECT_EQ(obj.at("tunnel_id"), "abc123");
  EXPECT_EQ(obj.at("local_base_url"), "http://127.0.0.1:8080");

  auto parsed = json::value_to<TunnelHello>(serialized);
  EXPECT_EQ(parsed.tunnel_id, hello.tunnel_id);
  EXPECT_EQ(parsed.local_base_url, hello.local_base_url);
}

TEST(TunnelMessagesTest, RequestRoundTrip) {
  TunnelRequest req;
  req.id = "req-42";
  req.method = "POST";
  req.path = "/edge";
  req.body = "payload";
  req.headers = {{"x-auth", "token"}, {"accept", "application/json"}};

  auto serialized = json::value_from(req);
  ASSERT_TRUE(serialized.is_object());
  const auto &obj = serialized.as_object();
  ASSERT_TRUE(obj.if_contains("headers"));
  ASSERT_TRUE(obj.at("headers").is_object());
  EXPECT_EQ(obj.at("headers").as_object().size(), 2);

  auto parsed = json::value_to<TunnelRequest>(serialized);
  EXPECT_EQ(parsed.id, req.id);
  EXPECT_EQ(parsed.method, req.method);
  EXPECT_EQ(parsed.path, req.path);
  EXPECT_EQ(parsed.body, req.body);
  ASSERT_EQ(parsed.headers.size(), req.headers.size());
  EXPECT_EQ(parsed.headers.at("x-auth"), "token");
  EXPECT_EQ(parsed.headers.at("accept"), "application/json");
}

TEST(TunnelMessagesTest, ResponseRoundTrip) {
  TunnelResponse res;
  res.id = "req-7";
  res.status = 404;
  res.body = "missing";
  res.headers = {{"content-type", "text/plain"}};

  auto serialized = json::value_from(res);
  ASSERT_TRUE(serialized.is_object());
  const auto &obj = serialized.as_object();
  EXPECT_EQ(obj.at("status"), 404);

  auto parsed = json::value_to<TunnelResponse>(serialized);
  EXPECT_EQ(parsed.id, res.id);
  EXPECT_EQ(parsed.status, res.status);
  EXPECT_EQ(parsed.body, res.body);
  ASSERT_EQ(parsed.headers.size(), res.headers.size());
  EXPECT_EQ(parsed.headers.at("content-type"), "text/plain");
}

TEST(TunnelMessagesTest, RequestMissingIdThrows) {
  json::object obj{{"type", "request"},
                   {"method", "GET"},
                   {"path", "/"},
                   {"headers", json::object{}}};

  json::value jv = obj;
  EXPECT_THROW({ auto parsed = json::value_to<TunnelRequest>(jv); (void)parsed; },
               std::runtime_error);
}

TEST(TunnelMessagesTest, ResponseMissingStatusThrows) {
  json::object obj{{"type", "response"},
                   {"id", "abc"},
                   {"headers", json::object{}}};

  json::value jv = obj;
  EXPECT_THROW({ auto parsed = json::value_to<TunnelResponse>(jv); (void)parsed; },
               std::runtime_error);
}

TEST(TunnelMessagesTest, PingPongDefaults) {
  json::object ping_obj{{"type", "ping"}};
  json::value ping_value = ping_obj;
  auto ping = json::value_to<TunnelPing>(ping_value);
  EXPECT_EQ(ping.ts, 0u);

  TunnelPong pong;
  pong.ts = 123;
  auto serialized = json::value_from(pong);
  ASSERT_TRUE(serialized.is_object());
  EXPECT_EQ(serialized.as_object().at("ts").to_number<std::uint64_t>(), 123u);

  auto parsed = json::value_to<TunnelPong>(serialized);
  EXPECT_EQ(parsed.ts, pong.ts);
}

} // namespace certctrl
