#pragma once

#include <memory>
#include <string>

#include "io_monad.hpp"

namespace certctrl {

// IHandlerFactory
struct IHandlerFactory {
  virtual ~IHandlerFactory() = default;
  // Create a new instance of the handler
  virtual std::shared_ptr<class IHandler> create() = 0;
};

// Minimal common contract for subcommand handlers
struct IHandler {
  virtual ~IHandler() = default;
  // The subcommand name this handler responds to (e.g., "conf", "login")
  virtual std::string command() const = 0;
  // Execute the handler's main work
  virtual monad::IO<void> start() = 0;
};

} // namespace certctrl
