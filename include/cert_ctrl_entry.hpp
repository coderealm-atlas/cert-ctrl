#pragma once

#include <algorithm>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>
#include <vector>

#include "boost/di.hpp"
#include "certctrl_common.hpp"
#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/agent_update_checker.hpp"
#include "handlers/conf_handler.hpp"
#include "handlers/handler_dispatcher.hpp"
#include "handlers/i_handler.hpp"
#include "handlers/install_config_apply_handler.hpp"
#include "handlers/install_config_handler.hpp"
#include "handlers/login_handler.hpp"
#include "handlers/update_handler.hpp"
#include "handlers/updates_polling_handler.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "ioc_manager_config_provider.hpp"
#include "misc_util.hpp"
#include "my_error_codes.hpp"
#include "version.h"

namespace di = boost::di;
namespace certctrl {

namespace type_tags {

// -- AppTypeTraits --
template <typename Tag> struct AppTypeTraits;

struct OneTag {}; // Example tag
struct TwoTag {}; // Example tag

template <> struct AppTypeTraits<OneTag> {
  // using Store = acme::AcmeStoreMysql;
  // using UserService = service::UserServiceMysql;
};
template <> struct AppTypeTraits<TwoTag> {};
} // namespace type_tags

namespace detail {
inline std::mutex &shutdown_mutex() {
  static std::mutex mutex;
  return mutex;
}

inline std::function<void()> &shutdown_handler() {
  static std::function<void()> handler;
  return handler;
}

inline void register_shutdown_handler(std::function<void()> handler) {
  std::lock_guard<std::mutex> lock(shutdown_mutex());
  shutdown_handler() = std::move(handler);
}

inline void clear_shutdown_handler() {
  std::lock_guard<std::mutex> lock(shutdown_mutex());
  shutdown_handler() = nullptr;
}

inline void invoke_shutdown_handler() {
  std::function<void()> handler;
  {
    std::lock_guard<std::mutex> lock(shutdown_mutex());
    handler = shutdown_handler();
  }
  if (handler) {
    handler();
  }
}
} // namespace detail

template <typename AppTag>
class App : public std::enable_shared_from_this<App<AppTag>> {
  misc::Blocker blocker_;
  certctrl::CliCtx &cli_ctx_;
  client_async::HttpClientManager *http_client_;
  customio::ConsoleOutput *output_hub_;
  std::once_flag shutdown_once_flag_;
  std::unique_ptr<boost::asio::signal_set> signals_;
  cjj365::ConfigSources &config_sources_;
  cjj365::IoContextManager *io_context_manager_;
  const certctrl::CertctrlConfig *certctrl_config_;

public:
  App(cjj365::ConfigSources &config_sources, certctrl::CliCtx &cli_ctx)
      : config_sources_(config_sources), cli_ctx_(cli_ctx) {}

  void print_error(const monad::Error &err) {
    if (err.code == my_errors::GENERAL::SHOW_OPT_DESC) {
      std::cerr << err.what << std::endl;
    } else {
      output_hub_->logger().error() << err << std::endl;
    }
  }

  void info(const std::string &message) {
    output_hub_->logger().info() << message << std::endl;
  }

  void start() {
    static customio::ConsoleOutputWithColor output_hub(
        cli_ctx_.verbosity_level());

    auto injector = di::make_injector(
        di::bind<cjj365::ConfigSources>().to(config_sources_),

        di::bind<cjj365::IIocConfigProvider>()
            .to<cjj365::IocConfigProviderFile>(),
        di::bind<certctrl::ICertctrlConfigProvider>()
            .to<certctrl::CertctrlConfigProviderFile>(),
        di::bind<cjj365::IHttpclientConfigProvider>()
            .to<cjj365::HttpclientConfigProviderFile>(),
        di::bind<customio::IOutput>().to(output_hub),
        di::bind<certctrl::CliCtx>().to(cli_ctx_),
        // Register all handlers for aggregate injection; DI will convert to
        // vector<unique_ptr<IHandler>>
  di::bind<certctrl::IHandler *[]>.to<certctrl::ConfHandler, certctrl::InstallConfigApplyHandler, certctrl::InstallConfigHandler, certctrl::LoginHandler, certctrl::UpdateHandler, certctrl::UpdatesPollingHandler>());

    certctrl_config_ =
        &injector.template create<certctrl::ICertctrlConfigProvider &>().get();

    io_context_manager_ =
        &injector.template create<cjj365::IoContextManager &>();
    http_client_ =
        &injector.template create<client_async::HttpClientManager &>();
    output_hub_ = &injector.template create<customio::ConsoleOutput &>();
    auto self = this->shared_from_this();

    detail::register_shutdown_handler([weak_self = std::weak_ptr<App>(self)] {
      if (auto shared = weak_self.lock()) {
        shared->blocker_.stop();
      }
    });

    // output the sources
    output_hub_->logger().info() << "Config source directories:" << std::endl;
    for (const auto &source : config_sources_.paths_) {
      output_hub_->logger().info() << " - " << source << std::endl;
    }

    // Use dispatcher injected with all handlers (as
    // vector<unique_ptr<IHandler>>)
    auto &dispatcher =
        injector.template create<certctrl::HandlerDispatcher &>();

    bool dispatched =
        dispatcher.dispatch_run(cli_ctx_.params.subcmd, [self](auto r) {
          if (r.is_err()) {
            self->print_error(r.error());
          } else {
            self->info("Handler completed successfully.");
          }
          return self->blocker_.stop();
        });

    if (!dispatched) {
      if (cli_ctx_.params.subcmd.empty()) {
        output_hub_->logger().info()
            << "No subcommand provided; running default update workflow."
            << std::endl;

        auto update_checker = injector.template create<
            std::shared_ptr<certctrl::AgentUpdateChecker>>();
        auto updates_handler = injector.template create<
            std::shared_ptr<certctrl::UpdatesPollingHandler>>();

        auto workflow =
            update_checker->run_once(MYAPP_VERSION)
                .catch_then([self, update_checker](monad::Error err) {
                  self->output_hub_->logger().warning()
                      << "Agent update check failed: " << err.what << std::endl;
                  return monad::IO<void>::pure();
                })
                .then([updates_handler]() { return updates_handler->start(); });

        workflow.run([self, update_checker, updates_handler](auto r) {
          if (r.is_err()) {
            self->print_error(r.error());
          } else {
            if (self->cli_ctx_.params.keep_running) {
              self->info("Default updates polling loop active.");
            } else {
              self->info("Default update workflow completed.");
            }
          }
          return self->blocker_.stop();
        });
      } else if (cli_ctx_.params.keep_running) {
        output_hub_->logger().info()
            << "Running in keep running mode." << std::endl;
      } else {
        // Build available commands string
        std::string cmds;
        auto v = dispatcher.commands();
        for (size_t i = 0; i < v.size(); ++i) {
          if (i)
            cmds += ", ";
          cmds += v[i];
        }
        output_hub_->logger().error()
            << "No valid subcommand provided. Available: " << cmds
            << ". Also 'account' (TBD)." << std::endl;
        return shutdown();
      }
    }
    signals_ = std::make_unique<boost::asio::signal_set>(
        io_context_manager_->ioc(), SIGINT, SIGTERM);
    signals_->async_wait(
        [&, self](const boost::system::error_code &error, int signal) {
          if (!error) {
            const char *signal_name = (signal == SIGINT) ? "SIGINT" : "SIGTERM";
            std::cerr << signal_name << " received. Stopping io_context..."
                      << std::endl;
            self->blocker_.stop();
          }
        });
    blocker_.wait();
    output_hub_->logger().debug()
        << "blocker_.wait() returned, start() exiting." << std::endl;
    // shutdown now
    shutdown();
  }

  void shutdown() {
    auto self = this->shared_from_this();
    std::call_once(shutdown_once_flag_, [self] {
      self->info("Shutting down App...");
      // 1. Disable further signal handling early
      if (self->signals_) {
        self->output_hub_->logger().debug()
            << "Shutdown: cancel signals" << std::endl;
        boost::system::error_code ec;
        auto n = self->signals_->cancel(ec);
        self->output_hub_->logger().debug()
            << "Shutdown: signal handlers canceled=" << n
            << (ec ? ", ec=" + ec.message() : ", ok") << std::endl;
        self->signals_.reset();
      }
      // 3. Stop outbound http client pool
      if (self->http_client_) {
        self->output_hub_->logger().debug()
            << "Shutdown: stop http_client_" << std::endl;
        self->http_client_->stop();
        self->http_client_ = nullptr;
      }
      // 4. Stop io_context (joins threads)
      // if (io_context_manager_) {
      self->output_hub_->logger().debug()
          << "Shutdown: stop io_context_manager_" << std::endl;
      self->io_context_manager_->stop();
      self->info("App shutdown completed.");
      detail::clear_shutdown_handler();
    });
  }
};

template <typename AppTag>
void launch(cjj365::ConfigSources &config, certctrl::CliCtx &ctx) {
  auto app = std::make_shared<certctrl::App<AppTag>>(config, ctx);
  app->start();
}

inline void request_shutdown() { detail::invoke_shutdown_handler(); }

} // namespace certctrl