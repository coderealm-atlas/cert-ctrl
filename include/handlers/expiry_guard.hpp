#pragma once

#include <boost/asio.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/install_config_manager.hpp"

namespace certctrl {

// Periodically checks cached certificate materials (local files) and triggers
// a full install-config pull+apply when certificates are near expiry.
//
// Design constraints:
// - Cross-platform (no systemd dependency)
// - Expiry decision uses cached on-disk artifacts only (best-effort)
// - Force update is rate-limited via a persisted cooldown
class ExpiryGuard : public std::enable_shared_from_this<ExpiryGuard> {
public:
  ExpiryGuard(boost::asio::io_context &ioc,
              certctrl::ICertctrlConfigProvider &config_provider,
              customio::ConsoleOutput &output,
              std::shared_ptr<certctrl::InstallConfigManager> install_manager);

  void Start();
  void Stop();

private:
  struct CachedCertInfo {
    std::int64_t cert_id{0};
    bool has_material{false};
    std::optional<std::chrono::system_clock::time_point> not_before;
    std::optional<std::chrono::system_clock::time_point> not_after;
    std::string error;
  };

  struct ScanResult {
    bool any_needs_refresh{false};
    std::vector<std::string> reasons;
    // Minimum remaining time across certs where remaining was available.
    std::optional<std::chrono::seconds> min_remaining;
  };

  void ScheduleNext(std::chrono::seconds delay);
  void OnTimer(const boost::system::error_code &ec);

  ScanResult ScanCachedCertificates();
  std::vector<std::int64_t> GetCachedCertIds() const;
  CachedCertInfo LoadCachedCertInfo(std::int64_t cert_id) const;

  bool CooldownAllowsAction(std::chrono::system_clock::time_point now,
                            std::string &reason);
  void PersistCooldown(std::chrono::system_clock::time_point now);

  void TriggerForceUpdate(const ScanResult &scan);

  std::filesystem::path state_file_path() const;

private:
  boost::asio::io_context &ioc_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  boost::asio::steady_timer timer_;

  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  std::shared_ptr<certctrl::InstallConfigManager> install_manager_;

  bool stop_requested_{false};
  bool tick_inflight_{false};
};

} // namespace certctrl
