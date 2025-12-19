#pragma once

#include "log_stream.hpp"

#include <boost/json.hpp>
#include <boost/log/trivial.hpp>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "json_util.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "simple_data.hpp"

namespace certctrl {
namespace fs = std::filesystem;

struct TunnelConfig {
  struct RouteRule {
    std::string match_prefix;
    std::optional<std::string> local_base_url;
    std::optional<std::string> rewrite_prefix;

    friend RouteRule tag_invoke(
        const boost::json::value_to_tag<RouteRule> &,
        const boost::json::value &jv) {
      if (!jv.is_object()) {
        throw std::runtime_error("TunnelConfig.RouteRule is not an object");
      }
      const auto &obj = jv.as_object();
      RouteRule rule{};
      if (auto *p = obj.if_contains("match_prefix"); p && p->is_string()) {
        rule.match_prefix = std::string(p->as_string().c_str());
      } else {
        throw std::runtime_error("RouteRule missing string field 'match_prefix'");
      }
      if (auto *p = obj.if_contains("local_base_url"); p && p->is_string()) {
        rule.local_base_url = std::string(p->as_string().c_str());
      }
      if (auto *p = obj.if_contains("rewrite_prefix"); p && p->is_string()) {
        rule.rewrite_prefix = std::string(p->as_string().c_str());
      }
      return rule;
    }

    friend void tag_invoke(const boost::json::value_from_tag &,
                           boost::json::value &jv, const RouteRule &rule) {
      boost::json::object obj;
      obj["match_prefix"] = rule.match_prefix;
      if (rule.local_base_url.has_value()) {
        obj["local_base_url"] = *rule.local_base_url;
      }
      if (rule.rewrite_prefix.has_value()) {
        obj["rewrite_prefix"] = *rule.rewrite_prefix;
      }
      jv = std::move(obj);
    }
  };

  bool enabled{false};
  std::string remote_endpoint{"wss://api.cjj365.cc/api/tunnel"};
  std::string webhook_base_url{"https://hook.cjj365.cc/hooks"};
  std::string local_base_url{"http://127.0.0.1:9000"};
  bool verify_tls{true};
  int request_timeout_seconds{45};
  int ping_interval_seconds{20};
  int max_concurrent_requests{12};
  int max_payload_bytes{5 * 1024 * 1024};
  int reconnect_initial_delay_ms{1000};
  int reconnect_max_delay_ms{30000};
  int reconnect_jitter_ms{250};
  std::vector<std::string> header_allowlist{
      "content-type", "user-agent", "stripe-signature"};
  std::vector<RouteRule> routes{};

  friend TunnelConfig tag_invoke(const boost::json::value_to_tag<TunnelConfig> &,
                                 const boost::json::value &jv) {
    TunnelConfig cfg{};
    if (auto *obj = jv.if_object()) {
      if (auto *p = obj->if_contains("enabled")) {
        cfg.enabled = p->as_bool();
      }
      if (auto *p = obj->if_contains("remote_endpoint"); p && p->is_string()) {
        cfg.remote_endpoint = std::string(p->as_string().c_str());
      }
      if (auto *p = obj->if_contains("webhook_base_url"); p && p->is_string()) {
        cfg.webhook_base_url = std::string(p->as_string().c_str());
      }
      if (auto *p = obj->if_contains("local_base_url"); p && p->is_string()) {
        cfg.local_base_url = std::string(p->as_string().c_str());
      }
      if (auto *p = obj->if_contains("verify_tls")) {
        cfg.verify_tls = p->as_bool();
      }
      if (auto *p = obj->if_contains("request_timeout_seconds")) {
        cfg.request_timeout_seconds = p->to_number<int>();
      }
      if (auto *p = obj->if_contains("ping_interval_seconds")) {
        cfg.ping_interval_seconds = p->to_number<int>();
      }
      if (auto *p = obj->if_contains("max_concurrent_requests")) {
        cfg.max_concurrent_requests = p->to_number<int>();
      }
      if (auto *p = obj->if_contains("max_payload_bytes")) {
        cfg.max_payload_bytes = p->to_number<int>();
      }
      if (auto *p = obj->if_contains("reconnect_initial_delay_ms")) {
        cfg.reconnect_initial_delay_ms = p->to_number<int>();
      }
      if (auto *p = obj->if_contains("reconnect_max_delay_ms")) {
        cfg.reconnect_max_delay_ms = p->to_number<int>();
      }
      if (auto *p = obj->if_contains("reconnect_jitter_ms")) {
        cfg.reconnect_jitter_ms = p->to_number<int>();
      }
      if (auto *p = obj->if_contains("header_allowlist"); p && p->is_array()) {
        cfg.header_allowlist = boost::json::value_to<std::vector<std::string>>(*p);
      }
      if (auto *p = obj->if_contains("routes"); p && p->is_array()) {
        cfg.routes = boost::json::value_to<std::vector<RouteRule>>(*p);
      }
      return cfg;
    }
    throw std::runtime_error("TunnelConfig is not an object");
  }

  friend void tag_invoke(const boost::json::value_from_tag &, boost::json::value &jv,
                         const TunnelConfig &cfg) {
    jv = boost::json::object{{"enabled", cfg.enabled},
                             {"remote_endpoint", cfg.remote_endpoint},
                             {"webhook_base_url", cfg.webhook_base_url},
                             {"local_base_url", cfg.local_base_url},
                             {"verify_tls", cfg.verify_tls},
                             {"request_timeout_seconds", cfg.request_timeout_seconds},
                             {"ping_interval_seconds", cfg.ping_interval_seconds},
                             {"max_concurrent_requests", cfg.max_concurrent_requests},
                             {"max_payload_bytes", cfg.max_payload_bytes},
                             {"reconnect_initial_delay_ms", cfg.reconnect_initial_delay_ms},
                             {"reconnect_max_delay_ms", cfg.reconnect_max_delay_ms},
                             {"reconnect_jitter_ms", cfg.reconnect_jitter_ms},
                             {"header_allowlist", boost::json::value_from(cfg.header_allowlist)},
                             {"routes", boost::json::value_from(cfg.routes)}};
  }
};

class ITunnelConfigProvider {
 public:
  virtual ~ITunnelConfigProvider() = default;
  virtual const TunnelConfig &get() const = 0;
  virtual TunnelConfig &get() = 0;
  virtual monad::MyVoidResult save(const boost::json::object &content) = 0;
};

class TunnelConfigProviderFile : public ITunnelConfigProvider {
 public:
  TunnelConfigProviderFile(cjj365::AppProperties &app_properties,
                           cjj365::ConfigSources &config_sources,
                           customio::IOutput &output)
      : config_sources_(config_sources), output_(output) {
    auto result = config_sources_.json_content("tunnel_config");
    if (result.is_err()) {
      output_.info() << "tunnel_config.json not found; using defaults"
                     << std::endl;
      config_ = TunnelConfig{};
      return;
    }
    auto jv = result.value();
    jsonutil::substitue_envs(jv, config_sources_.cli_overrides(),
                             app_properties.properties);
    config_ = boost::json::value_to<TunnelConfig>(jv);
  }

  const TunnelConfig &get() const override { return config_; }
  TunnelConfig &get() override { return config_; }

  monad::MyVoidResult save(const boost::json::object &content) override {
    auto file_path = config_sources_.paths_.back() / "tunnel_config.override.json";
    boost::json::value merged = content;
    if (fs::exists(file_path)) {
      std::ifstream ifs(file_path);
      if (!ifs) {
        return make_io_error(file_path, "open for reading");
      }
      std::string existing((std::istreambuf_iterator<char>(ifs)),
                           std::istreambuf_iterator<char>());
      try {
        boost::json::value current = boost::json::parse(existing);
        if (!current.is_object()) {
          return make_invalid_error(file_path, "not a JSON object");
        }
        boost::json::object &obj = current.as_object();
        for (const auto &[key, value] : content) {
          obj[key] = value;
        }
        merged = current;
      } catch (const std::exception &ex) {
        return make_invalid_error(file_path, ex.what());
      }
    }

    std::ofstream ofs(file_path);
    if (!ofs) {
      return make_io_error(file_path, "open for writing");
    }
    ofs << boost::json::serialize(merged);
    ofs.close();
    return monad::MyVoidResult::Ok();
  }

 private:
  static monad::MyVoidResult make_io_error(const fs::path &file, const char *action) {
    monad::Error err{};
    err.code = my_errors::GENERAL::FILE_READ_WRITE;
    err.what = "Unable to " + std::string(action) + ": " + file.string();
    return monad::MyVoidResult::Err(std::move(err));
  }

  static monad::MyVoidResult make_invalid_error(const fs::path &file,
                                                const char *reason) {
    monad::Error err{};
    err.code = my_errors::GENERAL::INVALID_ARGUMENT;
    err.what = "Invalid JSON content in " + file.string() + ": " + reason;
    return monad::MyVoidResult::Err(std::move(err));
  }

  TunnelConfig config_{};
  cjj365::ConfigSources &config_sources_;
  customio::IOutput &output_;
};

} // namespace certctrl
