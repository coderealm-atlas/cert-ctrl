#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>

#include "result_monad.hpp"

namespace testinfra {

namespace detail {

template <typename T>
boost::asio::awaitable<void>
fulfill_result(std::shared_ptr<std::promise<monad::MyResult<T>>> promise,
               boost::asio::awaitable<monad::MyResult<T>> operation) {
  try {
    promise->set_value(co_await std::move(operation));
  } catch (const std::exception &ex) {
    promise->set_value(monad::MyResult<T>::Err(monad::Error{1, ex.what()}));
  } catch (...) {
    promise->set_value(
        monad::MyResult<T>::Err(monad::Error{1, "Unknown coroutine failure"}));
  }
}

} // namespace detail

template <typename T>
monad::MyResult<T> run_result_awaitable(
    boost::asio::io_context &ioc,
    boost::asio::awaitable<monad::MyResult<T>> operation,
    std::chrono::milliseconds timeout = std::chrono::seconds(30)) {
  auto promise = std::make_shared<std::promise<monad::MyResult<T>>>();
  auto future = promise->get_future();
  boost::asio::co_spawn(ioc,
                        detail::fulfill_result(promise, std::move(operation)),
                        boost::asio::detached);

  if (future.wait_for(timeout) != std::future_status::ready) {
    throw std::runtime_error("Timed out waiting for coroutine result");
  }
  return future.get();
}

template <typename T>
monad::MyResult<T>
run_result_awaitable(boost::asio::awaitable<monad::MyResult<T>> operation) {
  boost::asio::io_context ioc;
  auto promise = std::make_shared<std::promise<monad::MyResult<T>>>();
  auto future = promise->get_future();
  boost::asio::co_spawn(ioc,
                        detail::fulfill_result(promise, std::move(operation)),
                        boost::asio::detached);
  ioc.run();

  if (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
    throw std::runtime_error("Coroutine completed without producing a result");
  }
  return future.get();
}

} // namespace testinfra
