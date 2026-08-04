#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <memory>
#include <sstream>
#include <string>

#include "handlers/handler_dispatcher.hpp"
#include "include/awaitable_test_helper.hpp"

namespace {

class TestOutput final : public customio::IOutput {
public:
  customio::LogStream trace() override { return disabled(); }
  customio::LogStream debug() override { return disabled(); }
  customio::LogStream info() override { return disabled(); }
  customio::LogStream warning() override { return disabled(); }
  customio::LogStream error() override { return disabled(); }
  std::ostream &stream() override { return stream_; }
  std::ostream &err_stream() override { return stream_; }
  std::size_t verbosity() const override { return 0; }

private:
  static customio::LogStream disabled() {
    return customio::LogStream::make_disabled();
  }

  std::ostringstream stream_;
};

class AwaitableHandler final : public certctrl::IHandler {
public:
  std::string command() const override { return "test"; }
  boost::asio::awaitable<monad::MyResult<void>> start_awaitable() override {
    started = true;
    co_return monad::MyResult<void>::Ok();
  }

  bool started{false};
};

TEST(HandlerDispatcherTest, EmptySubcommandDoesNotInvokeFactory) {
  TestOutput output;
  std::size_t factory_calls = 0;
  certctrl::HandlerFactoryImpl factory(
      [&factory_calls](
          const std::string &) -> std::shared_ptr<certctrl::IHandler> {
        ++factory_calls;
        return nullptr;
      });
  certctrl::HandlerDispatcher dispatcher(output, factory);

  EXPECT_FALSE(dispatcher.dispatch_awaitable("").has_value());
  EXPECT_EQ(factory_calls, 0U);
}

TEST(HandlerDispatcherTest, RetainsHandlerUntilAwaitableCompletes) {
  TestOutput output;

  auto handler = std::make_shared<AwaitableHandler>();
  certctrl::HandlerFactoryImpl factory(
      [handler](
          const std::string &command) -> std::shared_ptr<certctrl::IHandler> {
        if (command != "test") {
          return nullptr;
        }
        return handler;
      });
  certctrl::HandlerDispatcher dispatcher(output, factory);

  EXPECT_FALSE(dispatcher.dispatch_awaitable("missing").has_value());

  auto operation = dispatcher.dispatch_awaitable("test");
  ASSERT_TRUE(operation.has_value());
  auto result = testinfra::run_result_awaitable(std::move(*operation));

  EXPECT_TRUE(result.is_ok());
  EXPECT_TRUE(handler->started);
}

} // namespace
