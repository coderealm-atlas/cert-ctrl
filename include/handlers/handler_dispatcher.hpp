#pragma once

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "certctrl_common.hpp"
#include "handlers/i_handler.hpp"
#include "io_monad.hpp"
#include "log_stream.hpp"

namespace certctrl {

// Lifetime: instantiated via DI inside App::start and kept on the stack for
// the duration of the CLI session. Owns a vector of shared_ptr<IHandler>
// provided by DI; those handler instances live as long as the dispatcher.
class HandlerDispatcher {
  customio::IOutput &output_;
  certctrl::CliCtx &cli_ctx_;
  // std::vector<std::shared_ptr<IHandler>> handlers_;
  IHandlerFactory &handler_factory_;

public:
  HandlerDispatcher(customio::IOutput &out, //
                    certctrl::CliCtx &ctx,  //
                    IHandlerFactory &handler_factory)
      : output_(out), cli_ctx_(ctx), handler_factory_(handler_factory) {}

  // std::vector<std::string> commands() const {
  //   std::vector<std::string> cmds;
  //   cmds.reserve(handlers_.size());
  //   for (auto &h : handlers_) {
  //     if (h) cmds.emplace_back(h->command());
  //   }
  //   std::sort(cmds.begin(), cmds.end());
  //   cmds.erase(std::unique(cmds.begin(), cmds.end()), cmds.end());
  //   return cmds;
  // }

  bool dispatch_run(const std::string &subcmd,
                    std::function<void(monad::MyResult<void> &&)> cont) {
    // auto it = std::find_if(handlers_.begin(), handlers_.end(), [&](auto &h) {
    //   return h && h->command() == subcmd;
    // });
    // if (it == handlers_.end()) {
    //   return false;
    // }
    // (*it)->start().run(std::move(cont));
    // return true;
    try {
      handler_factory_.create(subcmd)->start().run(std::move(cont));
      return true;
    } catch (const std::exception &ex) {
      return false;
    }
  }
};

} // namespace certctrl
