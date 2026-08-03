#pragma once

#include <algorithm>
#include <boost/asio/awaitable.hpp>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "handlers/i_handler.hpp"
#include "log_stream.hpp"

namespace certctrl {

// The dispatcher and factory are owned by App::start. Each dispatched handler
// is retained by the returned coroutine frame until execution finishes.
class HandlerDispatcher {
  customio::IOutput &output_;
  IHandlerFactory &handler_factory_;

  static boost::asio::awaitable<monad::MyResult<void>>
  run_handler(std::shared_ptr<IHandler> handler) {
    co_return co_await handler->start_awaitable();
  }

public:
  HandlerDispatcher(customio::IOutput &out, IHandlerFactory &handler_factory)
      : output_(out), handler_factory_(handler_factory) {}

  std::optional<boost::asio::awaitable<monad::MyResult<void>>>
  dispatch_awaitable(const std::string &subcmd) {
    try {
      auto handler = handler_factory_.create(subcmd);
      if (!handler) {
        return std::nullopt;
      }
      return run_handler(std::move(handler));
    } catch (const std::exception &ex) {
      output_.error() << "Failed to dispatch handler '" << subcmd
                      << "': " << ex.what() << std::endl;
      return std::nullopt;
    }
  }
};

} // namespace certctrl
