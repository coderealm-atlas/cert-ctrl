#pragma once
#include "log_stream.hpp"
#include <boost/asio/thread_pool.hpp>
#include <boost/json/fwd.hpp>
#include <boost/log/trivial.hpp>
#include <cstdlib>
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

struct CertctrlConfig {
  bool auto_apply_config{true};
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
        if (auto *p = jo_p->if_contains("verbose"))
          cc.verbose = p->as_string().c_str();
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

    if (auto it = config_sources.cli_overrides().find("url_base");
        it != config_sources.cli_overrides().end() && !it->second.empty()) {
      config_.base_url = it->second;
    }
  }

  const CertctrlConfig &get() const override { return config_; }
  CertctrlConfig &get() override { return config_; }

  monad::MyVoidResult save(const json::object &content) override {
    auto f = config_sources_.paths_.back() / "application.override.json";
    json::value jv;
    if (fs::exists(f)) {
      std::ifstream ifs(f);
      if (!ifs) {
        monad::Error err{};
        err.code = my_errors::GENERAL::FILE_READ_WRITE;
        err.what = "Unable to open configuration file: " + f.string();
        return monad::MyVoidResult::Err(std::move(err));
      }
      std::string existing_content((std::istreambuf_iterator<char>(ifs)),
                                   std::istreambuf_iterator<char>());
      ifs.close();
      jv = json::parse(existing_content);
      if (!jv.is_object()) {
        monad::Error err{};
        err.code = my_errors::GENERAL::INVALID_ARGUMENT;
        err.what = "Configuration file is not a JSON object: " + f.string();
        return monad::MyVoidResult::Err(std::move(err));
      }
      json::object &jo = jv.as_object();
      for (const auto &[key, value] : content) {
        jo[key] = value;
      }
    } else {
      jv = content;
    }
    std::ofstream ofs(f);
    if (!ofs) {
      monad::Error err{};
      err.code = my_errors::GENERAL::FILE_READ_WRITE;
      err.what = "Unable to open configuration file for writing: " + f.string();
      return monad::MyVoidResult::Err(std::move(err));
    }
    ofs << content;
    ofs.close();
    return monad::MyVoidResult::Ok();
  }

  monad::MyVoidResult save_replace(const json::object &content) override {
    auto f = config_sources_.paths_.back() / "application.override.json";
    std::ofstream ofs(f);
    if (!ofs) {
      monad::Error err{};
      err.code = my_errors::GENERAL::FILE_READ_WRITE;
      err.what = "Unable to open configuration file for writing: " + f.string();
      return monad::MyVoidResult::Err(std::move(err));
    }
    ofs << content;
    ofs.close();
    return monad::MyVoidResult::Ok();
  }
};
} // namespace certctrl
