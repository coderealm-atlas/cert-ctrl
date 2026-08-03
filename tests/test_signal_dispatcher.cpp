#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <string>

#include "handlers/signal_dispatcher.hpp"
#include "handlers/signal_handlers/signal_handler_base.hpp"
#include "include/awaitable_test_helper.hpp"
#include "my_error_codes.hpp"

namespace asio = boost::asio;
using namespace std::chrono_literals;

namespace {

class TempDirectory {
public:
  TempDirectory() {
    path_ = std::filesystem::temp_directory_path() /
            ("certctrl-signal-dispatcher-" +
             std::to_string(
                 std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(path_);
  }

  ~TempDirectory() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }

  const std::filesystem::path &path() const { return path_; }

private:
  std::filesystem::path path_;
};

class ControlledSignalHandler final
    : public certctrl::signal_handlers::ISignalHandler {
public:
  explicit ControlledSignalHandler(bool fail_first = false,
                                   std::chrono::milliseconds delay = 0ms)
      : fail_first_(fail_first), delay_(delay) {}

  std::string signal_type() const override { return "test.signal"; }

  asio::awaitable<monad::MyResult<void>>
  handle_awaitable(const ::data::DeviceUpdateSignal &) override {
    const int call = ++calls_;
    if (delay_ > 0ms) {
      asio::steady_timer timer(co_await asio::this_coro::executor);
      timer.expires_after(delay_);
      co_await timer.async_wait(asio::use_awaitable);
    }
    if (fail_first_ && call == 1) {
      co_return monad::MyResult<void>::Err(monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT, "first attempt failed"));
    }
    co_return monad::MyResult<void>::Ok();
  }

  int calls() const { return calls_.load(); }

private:
  bool fail_first_;
  std::chrono::milliseconds delay_;
  std::atomic<int> calls_{0};
};

::data::DeviceUpdateSignal make_signal() {
  ::data::DeviceUpdateSignal signal;
  signal.type = "test.signal";
  signal.ts_ms = 123456;
  signal.ref = boost::json::object{};
  return signal;
}

} // namespace

TEST(SignalDispatcherTest, ConcurrentDuplicateExecutesHandlerOnce) {
  TempDirectory temp;
  certctrl::SignalDispatcher dispatcher(temp.path());
  auto handler = std::make_shared<ControlledSignalHandler>(false, 50ms);
  dispatcher.register_handler(handler);
  const auto signal = make_signal();

  asio::io_context ioc;
  std::promise<monad::MyResult<void>> first_promise;
  std::promise<monad::MyResult<void>> second_promise;
  auto first_future = first_promise.get_future();
  auto second_future = second_promise.get_future();

  auto run = [&dispatcher, signal](std::promise<monad::MyResult<void>> &promise)
      -> asio::awaitable<void> {
    promise.set_value(co_await dispatcher.dispatch_awaitable(signal));
  };
  asio::co_spawn(ioc, run(first_promise), asio::detached);
  asio::co_spawn(ioc, run(second_promise), asio::detached);
  ioc.run();

  EXPECT_TRUE(first_future.get().is_ok());
  EXPECT_TRUE(second_future.get().is_ok());
  EXPECT_EQ(handler->calls(), 1);
  EXPECT_EQ(dispatcher.processed_count(), 1U);
}

TEST(SignalDispatcherTest, FailedSignalCanBeRetried) {
  TempDirectory temp;
  certctrl::SignalDispatcher dispatcher(temp.path());
  auto handler = std::make_shared<ControlledSignalHandler>(true);
  dispatcher.register_handler(handler);
  const auto signal = make_signal();

  auto first = testinfra::run_result_awaitable<void>(
      dispatcher.dispatch_awaitable(signal));
  auto second = testinfra::run_result_awaitable<void>(
      dispatcher.dispatch_awaitable(signal));

  EXPECT_TRUE(first.is_err());
  EXPECT_TRUE(second.is_ok());
  EXPECT_EQ(handler->calls(), 2);
  EXPECT_EQ(dispatcher.processed_count(), 1U);
}

TEST(SignalDispatcherTest, ConcurrentFailureIsSharedAndRemainsRetryable) {
  TempDirectory temp;
  certctrl::SignalDispatcher dispatcher(temp.path());
  auto handler = std::make_shared<ControlledSignalHandler>(true, 50ms);
  dispatcher.register_handler(handler);
  const auto signal = make_signal();

  asio::io_context ioc;
  std::promise<monad::MyResult<void>> first_promise;
  std::promise<monad::MyResult<void>> second_promise;
  auto first_future = first_promise.get_future();
  auto second_future = second_promise.get_future();

  auto run = [&dispatcher, signal](std::promise<monad::MyResult<void>> &promise)
      -> asio::awaitable<void> {
    promise.set_value(co_await dispatcher.dispatch_awaitable(signal));
  };
  asio::co_spawn(ioc, run(first_promise), asio::detached);
  asio::co_spawn(ioc, run(second_promise), asio::detached);
  ioc.run();

  EXPECT_TRUE(first_future.get().is_err());
  EXPECT_TRUE(second_future.get().is_err());
  EXPECT_EQ(handler->calls(), 1);
  EXPECT_EQ(dispatcher.processed_count(), 0U);

  auto retry = testinfra::run_result_awaitable<void>(
      dispatcher.dispatch_awaitable(signal));
  EXPECT_TRUE(retry.is_ok());
  EXPECT_EQ(handler->calls(), 2);
  EXPECT_EQ(dispatcher.processed_count(), 1U);
}
