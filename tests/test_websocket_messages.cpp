#include <gtest/gtest.h>

#include <boost/json.hpp>

#include "websocket/websocket_messages.hpp"

namespace certctrl {
namespace json = boost::json;

TEST(WebsocketMessagesTest, HelloRoundTrip) {
  WebsocketHello hello;
  hello.connection_id = "abc123";

  auto serialized = json::value_from(hello);
  ASSERT_TRUE(serialized.is_object());
  const auto &obj = serialized.as_object();
  EXPECT_EQ(obj.at("type"), "hello");
  EXPECT_EQ(obj.at("connection_id"), "abc123");

  auto parsed = json::value_to<WebsocketHello>(serialized);
  EXPECT_EQ(parsed.connection_id, hello.connection_id);
}

TEST(WebsocketMessagesTest, HelloIgnoresLegacyLocalBaseUrlField) {
  json::object obj{{"type", "hello"},
                   {"connection_id", "abc123"},
                   {"local_base_url", "http://127.0.0.1:8080"}};
  auto parsed = json::value_to<WebsocketHello>(json::value(obj));
  EXPECT_EQ(parsed.connection_id, "abc123");
}

TEST(WebsocketMessagesTest, RequestRoundTrip) {
  WebsocketRequest req;
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

  auto parsed = json::value_to<WebsocketRequest>(serialized);
  EXPECT_EQ(parsed.id, req.id);
  EXPECT_EQ(parsed.method, req.method);
  EXPECT_EQ(parsed.path, req.path);
  EXPECT_EQ(parsed.body, req.body);
  ASSERT_EQ(parsed.headers.size(), req.headers.size());
  EXPECT_EQ(parsed.headers.at("x-auth"), "token");
  EXPECT_EQ(parsed.headers.at("accept"), "application/json");
}

TEST(WebsocketMessagesTest, ResponseRoundTrip) {
  WebsocketResponse res;
  res.id = "req-7";
  res.status = 404;
  res.body = "missing";
  res.headers = {{"content-type", "text/plain"}};

  auto serialized = json::value_from(res);
  ASSERT_TRUE(serialized.is_object());
  const auto &obj = serialized.as_object();
  EXPECT_EQ(obj.at("status"), 404);

  auto parsed = json::value_to<WebsocketResponse>(serialized);
  EXPECT_EQ(parsed.id, res.id);
  EXPECT_EQ(parsed.status, res.status);
  EXPECT_EQ(parsed.body, res.body);
  ASSERT_EQ(parsed.headers.size(), res.headers.size());
  EXPECT_EQ(parsed.headers.at("content-type"), "text/plain");
}

TEST(WebsocketMessagesTest, RequestMissingIdThrows) {
  json::object obj{{"type", "request"},
                   {"method", "GET"},
                   {"path", "/"},
                   {"headers", json::object{}}};

  json::value jv = obj;
  EXPECT_THROW({ auto parsed = json::value_to<WebsocketRequest>(jv); (void)parsed; },
               std::runtime_error);
}

TEST(WebsocketMessagesTest, ResponseMissingStatusThrows) {
  json::object obj{{"type", "response"},
                   {"id", "abc"},
                   {"headers", json::object{}}};

  json::value jv = obj;
  EXPECT_THROW({ auto parsed = json::value_to<WebsocketResponse>(jv); (void)parsed; },
               std::runtime_error);
}

TEST(WebsocketMessagesTest, PingPongDefaults) {
  json::object ping_obj{{"type", "ping"}};
  json::value ping_value = ping_obj;
  auto ping = json::value_to<WebsocketPing>(ping_value);
  EXPECT_EQ(ping.ts, 0u);

  WebsocketPong pong;
  pong.ts = 123;
  auto serialized = json::value_from(pong);
  ASSERT_TRUE(serialized.is_object());
  EXPECT_EQ(serialized.as_object().at("ts").to_number<std::uint64_t>(), 123u);

  auto parsed = json::value_to<WebsocketPong>(serialized);
  EXPECT_EQ(parsed.ts, pong.ts);
}

} // namespace certctrl
