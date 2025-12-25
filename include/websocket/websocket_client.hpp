#pragma once

#include "backoff_utils.hpp"
#include "conf/certctrl_config.hpp"
#include "conf/websocket_config.hpp"
#include "customio/console_output.hpp"
#include "io_context_manager.hpp"
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/trivial.hpp>

#include <filesystem>
#include <memory>
#include <random>

namespace certctrl {

class IDeviceStateStore;
class InstallConfigManager;
class SignalDispatcher;
class ISessionRefresher;

} // namespace certctrl

namespace cjj365 {
struct ConfigSources;
} // namespace cjj365

namespace certctrl {

class WebsocketClient : public std::enable_shared_from_this<WebsocketClient> {
public:
  WebsocketClient(cjj365::IoContextManager &io_context_manager,
                 IWebsocketConfigProvider &config_provider,
                 certctrl::ICertctrlConfigProvider &certctrl_config_provider,
                 customio::ConsoleOutput &output,
                 cjj365::ConfigSources &config_sources,
                 certctrl::IDeviceStateStore &state_store,
                 std::shared_ptr<certctrl::InstallConfigManager> install_config_manager,
                 std::shared_ptr<certctrl::ISessionRefresher> session_refresher);
  ~WebsocketClient();

  void Start();
  void Stop();

private:
  bool AcquireSingleInstanceLock();
  void LogConfiguration(const WebsocketConfig &config);
  void StartSession(WebsocketConfig config, bool allow_refresh);
  void HandleSessionClosed(bool should_retry);
  void HandleSessionConnected();
  void ScheduleReconnect();
  monad::ExponentialBackoffOptions
  BuildBackoffOptions(const WebsocketConfig &config) const;

  class Session;

  boost::asio::io_context &ioc_;
  IWebsocketConfigProvider &config_provider_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  customio::ConsoleOutput &output_;
  cjj365::ConfigSources &config_sources_;
  certctrl::IDeviceStateStore &state_store_;
  std::shared_ptr<certctrl::InstallConfigManager> install_config_manager_;
  std::shared_ptr<certctrl::ISessionRefresher> session_refresher_;
  std::unique_ptr<certctrl::SignalDispatcher> signal_dispatcher_;
  bool running_{false};
  bool stop_requested_{false};
  std::shared_ptr<Session> session_;
  boost::asio::steady_timer reconnect_timer_;
  monad::JitteredExponentialBackoff backoff_;
  std::mt19937 rng_;
  boost::log::sources::severity_logger<boost::log::trivial::severity_level> lg;

  std::filesystem::path instance_lock_path_;
  std::unique_ptr<boost::interprocess::file_lock> instance_lock_;
};

} // namespace certctrl
