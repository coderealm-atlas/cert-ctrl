#include "handlers/expiry_guard.hpp"

#include <boost/json.hpp>
#include <chrono>
#include <fstream>
#include <set>
#include <sstream>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "openssl/x509_time.hpp"

namespace certctrl {

namespace {
namespace fs = std::filesystem;

std::optional<std::string> read_text_file(const fs::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    return std::nullopt;
  }
  std::ostringstream oss;
  oss << ifs.rdbuf();
  return oss.str();
}

struct ParsedTimes {
  std::optional<std::chrono::system_clock::time_point> not_before;
  std::optional<std::chrono::system_clock::time_point> not_after;
};

std::optional<ParsedTimes> parse_cert_times_pem(const std::string &pem,
                                               std::string &error) {
  BIO *raw = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!raw) {
    error = "Failed to allocate BIO";
    return std::nullopt;
  }
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw, &BIO_free);

  X509 *x509_raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (!x509_raw) {
    error = "Failed to parse certificate PEM";
    return std::nullopt;
  }
  std::unique_ptr<X509, decltype(&X509_free)> cert(x509_raw, &X509_free);

  ParsedTimes out;
  out.not_before = cjj365::opensslutil::asn1_time_to_time_point(
      X509_get0_notBefore(cert.get()));
  out.not_after = cjj365::opensslutil::asn1_time_to_time_point(
      X509_get0_notAfter(cert.get()));
  return out;
}

std::int64_t now_epoch_seconds() {
  const auto now = std::chrono::system_clock::now();
  return std::chrono::duration_cast<std::chrono::seconds>(
             now.time_since_epoch())
      .count();
}

} // namespace

ExpiryGuard::ExpiryGuard(boost::asio::io_context &ioc,
                         certctrl::ICertctrlConfigProvider &config_provider,
                         customio::ConsoleOutput &output,
                         std::shared_ptr<certctrl::InstallConfigManager>
                             install_manager)
    : ioc_(ioc), strand_(boost::asio::make_strand(ioc_)), timer_(ioc_),
      config_provider_(config_provider), output_(output),
      install_manager_(std::move(install_manager)) {}

void ExpiryGuard::Start() {
  boost::asio::dispatch(strand_, [self = shared_from_this()]() {
    const auto &cfg = self->config_provider_.get().expiry_guard;
    if (!cfg.enabled) {
      self->output_.logger().debug()
          << "ExpiryGuard disabled by configuration" << std::endl;
      return;
    }

    if (!self->install_manager_) {
      self->output_.logger().warning()
          << "ExpiryGuard cannot start: InstallConfigManager unavailable"
          << std::endl;
      return;
    }

    self->stop_requested_ = false;
    self->tick_inflight_ = false;

    const int interval =
        (cfg.interval_seconds > 0) ? cfg.interval_seconds : 3600;
    self->output_.logger().info()
        << "ExpiryGuard enabled (interval_seconds=" << interval
        << ", cooldown_seconds=" << cfg.cooldown_seconds << ")" << std::endl;

    self->ScheduleNext(std::chrono::seconds(1));
  });
}

void ExpiryGuard::Stop() {
  boost::asio::dispatch(strand_, [self = shared_from_this()]() {
    self->stop_requested_ = true;
    self->timer_.cancel();
  });
}

void ExpiryGuard::ScheduleNext(std::chrono::seconds delay) {
  if (stop_requested_) {
    return;
  }

  timer_.expires_after(delay);
  timer_.async_wait(
      boost::asio::bind_executor(strand_,
                                 [self = shared_from_this()](auto ec) {
                                   self->OnTimer(ec);
                                 }));
}

void ExpiryGuard::OnTimer(const boost::system::error_code &ec) {
  if (ec == boost::asio::error::operation_aborted || stop_requested_) {
    return;
  }

  const auto &cfg = config_provider_.get().expiry_guard;
  const int interval = (cfg.interval_seconds > 0) ? cfg.interval_seconds : 3600;

  if (tick_inflight_) {
    output_.logger().debug() << "ExpiryGuard tick skipped (in-flight)"
                             << std::endl;
    ScheduleNext(std::chrono::seconds(interval));
    return;
  }
  tick_inflight_ = true;

  // Scan cached cert materials synchronously (local filesystem only).
  ScanResult scan = ScanCachedCertificates();

  if (!scan.any_needs_refresh) {
    tick_inflight_ = false;
    ScheduleNext(std::chrono::seconds(interval));
    return;
  }

  TriggerForceUpdate(scan);
}

std::filesystem::path ExpiryGuard::state_file_path() const {
  const auto &runtime_dir = config_provider_.get().runtime_dir;
  if (runtime_dir.empty()) {
    return {};
  }
  return runtime_dir / "state" / "expiry_guard_state.json";
}

bool ExpiryGuard::CooldownAllowsAction(
    std::chrono::system_clock::time_point now, std::string &reason) {
  const auto &cfg = config_provider_.get().expiry_guard;
  const int cooldown = (cfg.cooldown_seconds > 0) ? cfg.cooldown_seconds : 21600;

  const fs::path p = state_file_path();
  if (p.empty()) {
    reason = "runtime_dir not configured";
    return false;
  }

  std::error_code ec;
  fs::create_directories(p.parent_path(), ec);
  (void)ec;

  std::int64_t last_epoch = 0;
  {
    std::ifstream ifs(p);
    if (ifs.good()) {
      try {
        std::string content((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());
        if (!content.empty()) {
          auto jv = boost::json::parse(content);
          if (auto *jo = jv.if_object()) {
            if (auto *v = jo->if_contains("last_force_update_epoch_seconds")) {
              if (v->is_int64()) {
                last_epoch = v->as_int64();
              } else if (v->is_uint64()) {
                last_epoch = static_cast<std::int64_t>(v->as_uint64());
              }
            }
          }
        }
      } catch (const std::exception &ex) {
        output_.logger().warning()
            << "ExpiryGuard: failed to parse state file '" << p.string()
            << "': " << ex.what() << std::endl;
      }
    }
  }

  const auto now_epoch =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
          .count();
  if (last_epoch > 0) {
    const auto delta = now_epoch - last_epoch;
    if (delta >= 0 && delta < cooldown) {
      reason = "cooldown active";
      return false;
    }
  }

  reason.clear();
  return true;
}

void ExpiryGuard::PersistCooldown(std::chrono::system_clock::time_point now) {
  const fs::path p = state_file_path();
  if (p.empty()) {
    return;
  }

  std::error_code ec;
  fs::create_directories(p.parent_path(), ec);
  if (ec) {
    output_.logger().warning() << "ExpiryGuard: failed creating state dir '"
                               << p.parent_path().string() << "': "
                               << ec.message() << std::endl;
    return;
  }

  boost::json::object jo;
  jo["last_force_update_epoch_seconds"] =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
          .count();

  auto tmp = p;
  tmp += ".tmp-" + std::to_string(now_epoch_seconds());

  {
    std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
    ofs << boost::json::serialize(jo);
  }
  fs::rename(tmp, p, ec);
  if (ec) {
    output_.logger().warning() << "ExpiryGuard: failed writing state file '"
                               << p.string() << "': " << ec.message()
                               << std::endl;
    // best effort cleanup
    std::error_code rm_ec;
    fs::remove(tmp, rm_ec);
  }
}

std::vector<std::int64_t> ExpiryGuard::GetCachedCertIds() const {
  std::set<std::int64_t> ids;
  if (!install_manager_) {
    return {};
  }
  auto cfg = install_manager_->cached_config_snapshot();
  if (!cfg) {
    return {};
  }
  for (const auto &item : cfg->installs) {
    if (!item.ob_type || *item.ob_type != "cert" || !item.ob_id) {
      continue;
    }
    ids.insert(*item.ob_id);
  }
  return std::vector<std::int64_t>(ids.begin(), ids.end());
}

ExpiryGuard::CachedCertInfo ExpiryGuard::LoadCachedCertInfo(
    std::int64_t cert_id) const {
  CachedCertInfo info;
  info.cert_id = cert_id;

  if (!install_manager_) {
    info.error = "InstallConfigManager unavailable";
    return info;
  }
  const fs::path runtime_dir = install_manager_->runtime_dir();
  if (runtime_dir.empty()) {
    info.error = "Runtime directory not configured";
    return info;
  }

  fs::path pem_path = runtime_dir / "resources" / "certs" /
                      std::to_string(cert_id) / "current" /
                      "certificate.pem";

  auto pem = read_text_file(pem_path);
  if (!pem) {
    info.error = "certificate.pem not found";
    return info;
  }
  info.has_material = true;
  std::string parse_error;
  if (auto times = parse_cert_times_pem(*pem, parse_error)) {
    info.not_before = times->not_before;
    info.not_after = times->not_after;
  } else {
    info.error = std::move(parse_error);
  }

  return info;
}

ExpiryGuard::ScanResult ExpiryGuard::ScanCachedCertificates() {
  ScanResult result;

  const auto &cfg = config_provider_.get().expiry_guard;
  const int min_window =
      (cfg.min_window_seconds > 0) ? cfg.min_window_seconds : 86400;
  const double ratio = (cfg.ratio > 0.0) ? cfg.ratio : 0.15;

  const auto now = std::chrono::system_clock::now();
  const auto cert_ids = GetCachedCertIds();
  if (cert_ids.empty()) {
    output_.logger().debug()
        << "ExpiryGuard: no cached cert ids (install_config.json missing or empty)"
        << std::endl;
    return result;
  }

  for (const auto cert_id : cert_ids) {
    const auto info = LoadCachedCertInfo(cert_id);
    if (!info.has_material) {
      // Missing local materials: treat as actionable, but still cooldowned.
      result.any_needs_refresh = true;
      result.reasons.push_back("cert " + std::to_string(cert_id) +
                               ": materials missing");
      continue;
    }
    if (!info.error.empty()) {
      // Parse error: treat as actionable.
      result.any_needs_refresh = true;
      result.reasons.push_back("cert " + std::to_string(cert_id) +
                               ": parse error: " + info.error);
      continue;
    }
    if (!info.not_after) {
      continue;
    }

    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(*info.not_after - now);
    if (!result.min_remaining || remaining < *result.min_remaining) {
      result.min_remaining = remaining;
    }

    if (remaining.count() <= 0) {
      result.any_needs_refresh = true;
      result.reasons.push_back("cert " + std::to_string(cert_id) +
                               ": expired or expiring now");
      continue;
    }

    std::chrono::seconds lifetime_window{std::chrono::seconds(min_window)};
    if (info.not_before) {
      const auto lifetime =
          std::chrono::duration_cast<std::chrono::seconds>(*info.not_after - *info.not_before);
      if (lifetime.count() > 0) {
        const auto ratio_window = std::chrono::seconds(
            static_cast<std::int64_t>(ratio * static_cast<double>(lifetime.count())));
        if (ratio_window > lifetime_window) {
          lifetime_window = ratio_window;
        }
      }
    }

    if (remaining <= lifetime_window) {
      result.any_needs_refresh = true;
      result.reasons.push_back("cert " + std::to_string(cert_id) +
                               ": remaining " + std::to_string(remaining.count()) +
                               "s <= window " +
                               std::to_string(lifetime_window.count()) + "s");
    }
  }

  return result;
}

void ExpiryGuard::TriggerForceUpdate(const ScanResult &scan) {
  const auto &cfg = config_provider_.get().expiry_guard;
  const int interval = (cfg.interval_seconds > 0) ? cfg.interval_seconds : 3600;

  const auto now = std::chrono::system_clock::now();
  std::string cooldown_reason;
  if (!CooldownAllowsAction(now, cooldown_reason)) {
    output_.logger().info() << "ExpiryGuard: force update skipped (" << cooldown_reason
                            << ")" << std::endl;
    tick_inflight_ = false;
    ScheduleNext(std::chrono::seconds(interval));
    return;
  }

  PersistCooldown(now);

  output_.logger().warning()
      << "ExpiryGuard: triggering full install-config pull+apply (reasons="
      << scan.reasons.size() << ")" << std::endl;
  for (const auto &r : scan.reasons) {
    output_.logger().info() << "ExpiryGuard: reason: " << r << std::endl;
  }

  auto self = shared_from_this();

  // Full pull+apply using InstallConfigManager pipeline (no shell invocation).
  install_manager_->pull_and_apply_full()
      .catch_then([self](monad::Error err) -> monad::IO<void> {
        self->output_.logger().error()
            << "ExpiryGuard: force update failed: code=" << err.code
            << " status=" << err.response_status << " what=" << err.what
            << std::endl;
        return monad::IO<void>::pure();
      })
      .run([self, interval](auto) {
        boost::asio::dispatch(self->strand_, [self, interval]() {
          self->tick_inflight_ = false;
          self->ScheduleNext(std::chrono::seconds(interval));
        });
      });
}

} // namespace certctrl
