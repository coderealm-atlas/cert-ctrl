#pragma once

#include <boost/json.hpp>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "simple_data.hpp"

namespace testinfra {

namespace fs = std::filesystem;
namespace json = boost::json;

struct ConfigFileOptions {
  std::string base_url{"https://api.example.test"};
  fs::path runtime_dir;
  bool auto_apply{false};
  std::string verbose{"info"};
  int interval_seconds{300};
  int http_threads{1};
  std::string ioc_name{"install-config-test-ioc"};
  int ioc_threads{1};
};

inline void write_basic_config_files(const fs::path &config_dir,
                                     const ConfigFileOptions &options) {
  std::error_code ec;
  fs::create_directories(config_dir, ec);
  if (ec) {
    throw std::runtime_error("Failed to create config dir: " + ec.message());
  }

  auto write_json = [](const fs::path &path, const json::object &obj) {
    std::error_code write_ec;
    fs::create_directories(path.parent_path(), write_ec);
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    ofs << json::serialize(obj);
  };

  json::object application{
      {"auto_apply_config", options.auto_apply},
      {"verbose", options.verbose},
      {"url_base", options.base_url},
      {"runtime_dir", options.runtime_dir.string()},
      {"interval_seconds", options.interval_seconds},
      {"update_check_url",
       "https://install.lets-script.com/api/version/check"}};
  write_json(config_dir / "application.json", application);

  json::object httpclient{
      {"threads_num", options.http_threads},
      {"ssl_method", "tlsv12_client"},
      {"insecure_skip_verify", true},
      {"verify_paths", json::array{}},
      {"certificates", json::array{}},
      {"certificate_files", json::array{}},
      {"proxy_pool", json::array{}}};
  write_json(config_dir / "httpclient_config.json", httpclient);

  json::object ioc{
      {"threads_num", options.ioc_threads},
      {"name", options.ioc_name}};
  write_json(config_dir / "ioc_config.json", ioc);
}

inline std::unique_ptr<cjj365::ConfigSources>
make_config_sources(std::vector<fs::path> paths,
                    std::vector<std::string> profiles = {}) {
  cjj365::ConfigSources::instance_count.store(0);
  return std::make_unique<cjj365::ConfigSources>(std::move(paths),
                                                 std::move(profiles));
}

inline fs::path make_temp_dir(const std::string &prefix) {
  auto base = fs::temp_directory_path();
  std::mt19937_64 gen{std::random_device{}()};
  std::uniform_int_distribution<std::uint64_t> dist;
  auto dir = base / (prefix + "-" + std::to_string(dist(gen)));
  fs::create_directories(dir);
  return dir;
}

} // namespace testinfra
