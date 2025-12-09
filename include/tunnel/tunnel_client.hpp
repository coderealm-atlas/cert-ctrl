#pragma once

#include "conf/tunnel_config.hpp"
#include "customio/console_output.hpp"
#include "io_context_manager.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include "util/my_logging.hpp"

#include <memory>
#include <random>

namespace certctrl {

class TunnelClient {
public:
  TunnelClient(cjj365::IoContextManager &io_context_manager,
               ITunnelConfigProvider &config_provider,
               customio::ConsoleOutput &output);
  ~TunnelClient();

  void Start();
  void Stop();

private:
  void LogConfiguration(const TunnelConfig &config);
  void StartSession(TunnelConfig config);
  void HandleSessionClosed(bool should_retry);
  void HandleSessionConnected();
  void ScheduleReconnect();
  int NextBackoffDelayMs(const TunnelConfig &config);

  class Session;

  boost::asio::io_context &ioc_;
  ITunnelConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  bool running_{false};
  bool stop_requested_{false};
  std::shared_ptr<Session> session_;
  boost::asio::steady_timer reconnect_timer_;
  int current_backoff_ms_{0};
  std::mt19937 rng_;
  src::severity_logger<trivial::severity_level> lg;
};

} // namespace certctrl
