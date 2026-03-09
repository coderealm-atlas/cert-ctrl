#pragma once
#include "log_stream.hpp"
#include <boost/asio/thread_pool.hpp>
#include <boost/json/fwd.hpp>
#include <boost/log/trivial.hpp>
#include <fstream>
#include <cstdlib>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>
#include <stdexcept>
#include <string>
#include <utility>

#include "json_util.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "simple_data.hpp"
#include <filesystem>
#include <iostream>

namespace certctrl {
namespace fs = std::filesystem;

class ConfigFromOs; // forward declaration

inline const std::string an_empty_str = "";

struct ShortPollConfig {
  bool enabled{true};
  std::string poll_url{};
  int idle_interval_seconds{30};
  int interval_seconds{5};
  int jitter_seconds{1};
  int backoff_seconds{30};
  int fast_mode_ttl_seconds{120};
};

struct ExpiryGuardConfig {
  // When enabled, the agent periodically checks cached certificate materials
  // (local files under runtime_dir/resources/...) and can trigger a refresh.
  bool enabled{false};

  // How often to scan cached cert artifacts.
  int interval_seconds{3600};

  // Renewal window = max(min_window_seconds, ratio * lifetime_seconds).
  // This adapts to both short-lived and long-lived certificates.
  int min_window_seconds{86400};
  double ratio{0.15};

  // Cooldown between force-update actions.
  int cooldown_seconds{21600};
};

struct CertctrlConfig {
  bool auto_apply_config{true};
  bool auto_allow_after_update_script_hash{true};
  int install_update_grace_period_seconds{21600};
  std::int64_t install_update_grace_expires_at_epoch_seconds{0};
  std::vector<std::string> trusted_after_update_script_hashes;
  std::string verbose{};
  // Allowlist of signal types that should trigger after_update_script.
  // Missing/empty means disabled.
  std::vector<std::string> events_trigger_script;
  std::string base_url{"https://api.cjj365.cc"};
  std::string update_check_url{
      "https://install.lets-script.com/api/version/check"};
  fs::path runtime_dir{};
  int interval_seconds{30};
  std::string poll_url{};
  int jitter_seconds{1};
  int backoff_seconds{30};
  ShortPollConfig short_poll{};
  ExpiryGuardConfig expiry_guard{};

  friend CertctrlConfig tag_invoke(const json::value_to_tag<CertctrlConfig> &,
                                   const json::value &jv) {
    try {
      if (auto *jo_p = jv.if_object()) {
        CertctrlConfig cc{};

        // Backward-compat: older configs omitted this key but still expected
        // the after-update hook to run for common update signals.
        static const std::vector<std::string> kDefaultEventsTriggerScript{
            "install.updated",
            "cert.updated",
            "cert.wrap_ready",
            "cert.unassigned",
        };

        if (auto *p = jo_p->if_contains("auto_apply_config")) {
          cc.auto_apply_config = p->as_bool();
        }
        if (auto *p = jo_p->if_contains("auto_allow_after_update_script_hash")) {
          cc.auto_allow_after_update_script_hash = p->as_bool();
        }
        if (auto *p = jo_p->if_contains("install_update_grace_period_seconds")) {
          cc.install_update_grace_period_seconds = p->to_number<int>();
        }
        if (auto *p = jo_p->if_contains("install_update_grace_expires_at_epoch_seconds")) {
          if (p->is_int64()) {
            cc.install_update_grace_expires_at_epoch_seconds = p->as_int64();
          } else if (p->is_uint64()) {
            cc.install_update_grace_expires_at_epoch_seconds =
                static_cast<std::int64_t>(p->as_uint64());
          }
        }
        if (auto *p = jo_p->if_contains("verbose"))
          cc.verbose = p->as_string().c_str();
        if (auto *p = jo_p->if_contains("trusted_after_update_script_hashes")) {
          if (p->is_array()) {
            for (const auto &v : p->as_array()) {
              if (v.is_string()) {
                cc.trusted_after_update_script_hashes.emplace_back(
                    v.as_string().c_str());
              }
            }
          }
        }
        if (auto *p = jo_p->if_contains("url_base"))
          cc.base_url = p->as_string().c_str();
        if (auto *p = jo_p->if_contains("update_check_url"))
          cc.update_check_url = p->as_string().c_str();
        if (auto *p = jo_p->if_contains("runtime_dir"))
          cc.runtime_dir = fs::path(p->as_string().c_str());

        if (auto *p = jo_p->if_contains("events_trigger_script")) {
          if (p->is_array()) {
            for (const auto &v : p->as_array()) {
              if (v.is_string()) {
                cc.events_trigger_script.emplace_back(v.as_string().c_str());
              }
            }
          } else if (p->is_null()) {
            // Explicit null disables the hook.
            cc.events_trigger_script.clear();
          }
        } else {
          // Missing key: use backward-compatible defaults.
          cc.events_trigger_script = kDefaultEventsTriggerScript;
        }

        if (auto *p = jo_p->if_contains("interval_seconds"))
          cc.interval_seconds = p->to_number<int>();

        if (auto *eg_val = jo_p->if_contains("expiry_guard");
            eg_val && eg_val->is_object()) {
          const auto &eg_obj = eg_val->as_object();
          ExpiryGuardConfig eg{};
          if (auto *p = eg_obj.if_contains("enabled")) {
            eg.enabled = p->as_bool();
          }
          if (auto *p = eg_obj.if_contains("interval_seconds")) {
            eg.interval_seconds = p->to_number<int>();
          }
          if (auto *p = eg_obj.if_contains("min_window_seconds")) {
            eg.min_window_seconds = p->to_number<int>();
          }
          if (auto *p = eg_obj.if_contains("ratio")) {
            if (p->is_double()) {
              eg.ratio = p->as_double();
            } else if (p->is_int64()) {
              eg.ratio = static_cast<double>(p->as_int64());
            } else if (p->is_uint64()) {
              eg.ratio = static_cast<double>(p->as_uint64());
            }
          }
          if (auto *p = eg_obj.if_contains("cooldown_seconds")) {
            eg.cooldown_seconds = p->to_number<int>();
          }
          cc.expiry_guard = std::move(eg);
        }

        if (auto *sp_val = jo_p->if_contains("short_poll");
            sp_val && sp_val->is_object()) {
          const auto &sp_obj = sp_val->as_object();
          ShortPollConfig spcfg{};
          // defaults remain local to short-poll
          spcfg.poll_url = cc.poll_url;
          spcfg.idle_interval_seconds = 30;
          spcfg.interval_seconds = 5;
          spcfg.jitter_seconds = 1;
          spcfg.backoff_seconds = 30;
          spcfg.fast_mode_ttl_seconds = 120;

          if (auto *p = sp_obj.if_contains("enabled"))
            spcfg.enabled = p->as_bool();
          if (auto *p = sp_obj.if_contains("poll_url"); p && p->is_string())
            spcfg.poll_url = p->as_string().c_str();
          if (auto *p = sp_obj.if_contains("idle_interval_seconds"))
            spcfg.idle_interval_seconds = p->to_number<int>();
          if (auto *p = sp_obj.if_contains("interval_seconds"))
            spcfg.interval_seconds = p->to_number<int>();
          if (auto *p = sp_obj.if_contains("jitter_seconds"))
            spcfg.jitter_seconds = p->to_number<int>();
          if (auto *p = sp_obj.if_contains("backoff_seconds"))
            spcfg.backoff_seconds = p->to_number<int>();
          if (auto *p = sp_obj.if_contains("fast_mode_ttl_seconds"))
            spcfg.fast_mode_ttl_seconds = p->to_number<int>();

          cc.short_poll = std::move(spcfg);
        }
        return cc;
      } else {
        throw std::runtime_error("CertctrlConfig is not an object");
      }
    } catch (...) {
      throw std::runtime_error("error in parsing CertctrlConfig");
    }
  }
};

class ICertctrlConfigProvider {
public:
  virtual ~ICertctrlConfigProvider() = default;

  virtual const CertctrlConfig &get() const = 0;
  virtual CertctrlConfig &get() = 0;

  virtual monad::MyVoidResult refresh_install_update_grace_window(
      bool enable_flags) = 0;
  virtual void expire_install_update_grace_window_if_needed() = 0;

  virtual monad::MyVoidResult save(const json::object &content) = 0;

  // Persist a complete override snapshot (replace semantics).
  // Callers should prefer save() for partial patches.
  virtual monad::MyVoidResult save_replace(const json::object &content) = 0;
};

class CertctrlConfigProviderFile : public ICertctrlConfigProvider {
private:
  CertctrlConfig config_;
  customio::IOutput &output_;
  cjj365::ConfigSources &config_sources_;

  static constexpr const char *kApplicationOverrideFile =
      "application.override.json";
  static constexpr const char *kApplicationLocalFile =
      "application.local.json";

  static bool is_local_only_key(const std::string &key) {
    return key == "auto_apply_config" ||
           key == "auto_allow_after_update_script_hash" ||
           key == "install_update_grace_period_seconds" ||
           key == "install_update_grace_expires_at_epoch_seconds" ||
           key == "trusted_after_update_script_hashes";
  }

  static std::int64_t now_epoch_seconds() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch())
        .count();
  }

  fs::path application_local_path() const {
    return config_sources_.paths_.back() / kApplicationLocalFile;
  }

  static monad::MyResult<json::object> read_json_object(const fs::path &path) {
    if (!fs::exists(path)) {
      return monad::MyResult<json::object>::Ok(json::object{});
    }

    std::ifstream ifs(path);
    if (!ifs) {
      monad::Error err{};
      err.code = my_errors::GENERAL::FILE_READ_WRITE;
      err.what = "Unable to open configuration file: " + path.string();
      return monad::MyResult<json::object>::Err(std::move(err));
    }

    std::string existing_content((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());
    ifs.close();

    auto parsed = json::parse(existing_content);
    if (!parsed.is_object()) {
      monad::Error err{};
      err.code = my_errors::GENERAL::INVALID_ARGUMENT;
      err.what = "Configuration file is not a JSON object: " + path.string();
      return monad::MyResult<json::object>::Err(std::move(err));
    }

    return monad::MyResult<json::object>::Ok(parsed.as_object());
  }

  static monad::MyVoidResult write_json_object(const fs::path &path,
                                               const json::object &content) {
    std::ofstream ofs(path);
    if (!ofs) {
      monad::Error err{};
      err.code = my_errors::GENERAL::FILE_READ_WRITE;
      err.what = "Unable to open configuration file for writing: " +
                 path.string();
      return monad::MyVoidResult::Err(std::move(err));
    }
    ofs << boost::json::serialize(content);
    ofs.close();
    return monad::MyVoidResult::Ok();
  }

  monad::MyVoidResult merge_and_write_patch(const fs::path &path,
                                            const json::object &patch) {
    if (patch.empty()) {
      return monad::MyVoidResult::Ok();
    }

    auto existing_r = read_json_object(path);
    if (existing_r.is_err()) {
      return monad::MyVoidResult::Err(existing_r.error());
    }

    auto merged = existing_r.value();
    for (const auto &[key, value] : patch) {
      merged[key] = value;
    }
    return write_json_object(path, merged);
  }

  void apply_local_only_overrides() {
    const auto local_path = application_local_path();
    auto local_r = read_json_object(local_path);
    if (local_r.is_err()) {
      output_.error() << local_r.error().what << std::endl;
      throw std::runtime_error(local_r.error().what);
    }

    const auto local = local_r.value();
    if (auto *p = local.if_contains("auto_apply_config")) {
      config_.auto_apply_config = p->as_bool();
    }
    if (auto *p = local.if_contains("auto_allow_after_update_script_hash")) {
      config_.auto_allow_after_update_script_hash = p->as_bool();
    }
    if (auto *p = local.if_contains("install_update_grace_period_seconds")) {
      config_.install_update_grace_period_seconds = p->to_number<int>();
    }
    if (auto *p = local.if_contains("install_update_grace_expires_at_epoch_seconds")) {
      if (p->is_int64()) {
        config_.install_update_grace_expires_at_epoch_seconds = p->as_int64();
      } else if (p->is_uint64()) {
        config_.install_update_grace_expires_at_epoch_seconds =
            static_cast<std::int64_t>(p->as_uint64());
      }
    }
    if (auto *p = local.if_contains("trusted_after_update_script_hashes")) {
      config_.trusted_after_update_script_hashes.clear();
      if (p->is_array()) {
        for (const auto &v : p->as_array()) {
          if (v.is_string()) {
            config_.trusted_after_update_script_hashes.emplace_back(
                v.as_string().c_str());
          }
        }
      }
    }
  }

  monad::MyVoidResult write_local_patch(const json::object &patch) {
    return merge_and_write_patch(application_local_path(), patch);
  }

  monad::MyVoidResult ensure_install_update_grace_window_initialized() {
    if (!(config_.auto_apply_config ||
          config_.auto_allow_after_update_script_hash)) {
      return monad::MyVoidResult::Ok();
    }
    if (config_.install_update_grace_expires_at_epoch_seconds > 0) {
      return monad::MyVoidResult::Ok();
    }
    return refresh_install_update_grace_window(false);
  }

public:
  CertctrlConfigProviderFile(cjj365::AppProperties &app_properties,
                             cjj365::ConfigSources &config_sources,
                             customio::IOutput &output)
      : output_(output), config_sources_(config_sources) {
    if (!config_sources.application_json) {
      output_.error() << "Failed to load App config." << std::endl;
      throw std::runtime_error("Failed to load App config.");
    }
    json::value jv = config_sources.application_json.value();
    jsonutil::substitue_envs(jv, config_sources.cli_overrides(),
                             app_properties.properties);
    config_ = json::value_to<CertctrlConfig>(std::move(jv));
    if (config_.install_update_grace_period_seconds <= 0) {
      config_.install_update_grace_period_seconds = 21600;
    }
    apply_local_only_overrides();
    if (config_.install_update_grace_period_seconds <= 0) {
      config_.install_update_grace_period_seconds = 21600;
    }
    if (auto init_r = ensure_install_update_grace_window_initialized();
        init_r.is_err()) {
      output_.error() << init_r.error().what << std::endl;
      throw std::runtime_error(init_r.error().what);
    }
    expire_install_update_grace_window_if_needed();

    if (auto it = config_sources.cli_overrides().find("url_base");
        it != config_sources.cli_overrides().end() && !it->second.empty()) {
      config_.base_url = it->second;
    }
  }

  const CertctrlConfig &get() const override {
    const_cast<CertctrlConfigProviderFile *>(this)
        ->expire_install_update_grace_window_if_needed();
    return config_;
  }
  CertctrlConfig &get() override {
    expire_install_update_grace_window_if_needed();
    return config_;
  }

  monad::MyVoidResult refresh_install_update_grace_window(
      bool enable_flags) override {
    if (config_.install_update_grace_period_seconds <= 0) {
      config_.install_update_grace_period_seconds = 21600;
    }

    json::object patch{{"install_update_grace_expires_at_epoch_seconds",
                        now_epoch_seconds() +
                            config_.install_update_grace_period_seconds}};
    if (enable_flags) {
      patch["auto_apply_config"] = true;
      patch["auto_allow_after_update_script_hash"] = true;
    }

    auto write_r = write_local_patch(patch);
    if (write_r.is_err()) {
      return write_r;
    }

    config_.install_update_grace_expires_at_epoch_seconds =
        json::value_to<std::int64_t>(
            patch.at("install_update_grace_expires_at_epoch_seconds"));
    if (enable_flags) {
      config_.auto_apply_config = true;
      config_.auto_allow_after_update_script_hash = true;
    }
    return monad::MyVoidResult::Ok();
  }

  void expire_install_update_grace_window_if_needed() override {
    if (config_.install_update_grace_expires_at_epoch_seconds <= 0) {
      return;
    }
    if (now_epoch_seconds() < config_.install_update_grace_expires_at_epoch_seconds) {
      return;
    }

    if (!(config_.auto_apply_config || config_.auto_allow_after_update_script_hash)) {
      config_.install_update_grace_expires_at_epoch_seconds = 0;
      (void)write_local_patch(
          {{"install_update_grace_expires_at_epoch_seconds", 0}});
      return;
    }

    auto write_r = write_local_patch({
        {"auto_apply_config", false},
        {"auto_allow_after_update_script_hash", false},
        {"install_update_grace_expires_at_epoch_seconds", 0},
    });
    if (write_r.is_err()) {
      output_.error() << write_r.error().what << std::endl;
      return;
    }

    config_.auto_apply_config = false;
    config_.auto_allow_after_update_script_hash = false;
    config_.install_update_grace_expires_at_epoch_seconds = 0;
  }

  monad::MyVoidResult save(const json::object &content) override {
    json::object remote_patch;
    json::object local_patch;
    for (const auto &[key, value] : content) {
      if (is_local_only_key(std::string(key))) {
        local_patch[key] = value;
      } else {
        remote_patch[key] = value;
      }
    }

    auto remote_r = merge_and_write_patch(
        config_sources_.paths_.back() / kApplicationOverrideFile, remote_patch);
    if (remote_r.is_err()) {
      return remote_r;
    }

    return merge_and_write_patch(config_sources_.paths_.back() /
                                     kApplicationLocalFile,
                                 local_patch);
  }

  monad::MyVoidResult save_replace(const json::object &content) override {
    json::object remote_content;
    json::object local_content;
    for (const auto &[key, value] : content) {
      if (is_local_only_key(std::string(key))) {
        local_content[key] = value;
      } else {
        remote_content[key] = value;
      }
    }

    if (!remote_content.empty()) {
      auto remote_r = write_json_object(
          config_sources_.paths_.back() / kApplicationOverrideFile,
          remote_content);
      if (remote_r.is_err()) {
        return remote_r;
      }
    }

    if (!local_content.empty()) {
      return write_json_object(config_sources_.paths_.back() /
                                   kApplicationLocalFile,
                               local_content);
    }

    return monad::MyVoidResult::Ok();
  }
};
} // namespace certctrl
