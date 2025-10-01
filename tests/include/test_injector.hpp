#pragma once

#include "boost/di.hpp"
#include "http_client_config_provider.hpp"
#include "io_context_manager.hpp"
#include "ioc_manager_config_provider.hpp"
#include "log_stream.hpp"
#include "simple_data.hpp"

namespace testinfra {

namespace di = boost::di;
namespace fs = std::filesystem;

constexpr const char *test_email = "jianglibo@hotmail.com";
constexpr const char *test_password = "StrongPass1!";

inline cjj365::ConfigSources &config_sources() {
  static const fs::path config_dir = [] {
    if (const char *env = std::getenv("GTEST_CONFIG_DIR"); env && *env) {
      return fs::path(env);
    }
    // Header lives at gtest/common/test_util.hpp; config_dir is at
    // gtest/config_dir
    fs::path p = fs::path(__FILE__).parent_path().parent_path().parent_path() /
                 "apps" / "bbserver" / "config_dir";
    if (fs::exists(p))
      return p;
#ifdef PROJECT_SOURCE_DIR
    fs::path p2 =
        fs::path(PROJECT_SOURCE_DIR) / "apps" / "bbserver" / "config_dir";
    if (fs::exists(p2))
      return p2;
#endif
    return fs::path("gtest/config_dir");
  }();

  static cjj365::ConfigSources instance({config_dir}, {"develop"});
  return instance;
}

// Reuse canonical test config source resolution used across legacy tests to
// avoid divergence.
inline cjj365::ConfigSources &shared_config_sources() {
  return config_sources();
}

inline int compute_log_level() {
  if (const char *lvl = std::getenv("TEST_LOG_LEVEL")) {
    try {
      int v = std::stoi(lvl);
      if (v < 0)
        v = 0;
      if (v > 6)
        v = 6;
      return v;
    } catch (...) {
    }
  }
  return 5; // default debug/info mix
}

inline customio::ConsoleOutputWithColor &shared_output() {
  static customio::ConsoleOutputWithColor out(compute_log_level());
  return out;
}

// Base injector for handler/service integration tests
inline auto build_base_injector() {
  return di::make_injector(
      di::bind<cjj365::ConfigSources>().to(shared_config_sources()),
      di::bind<customio::IOutput>().to(shared_output()),
      di::bind<cjj365::IIocConfigProvider>()
          .to<cjj365::IocConfigProviderFile>(),
      di::bind<cjj365::IIoContextManager>().to<cjj365::IoContextManager>().in(
          di::singleton),
      di::bind<cjj365::IHttpclientConfigProvider>()
          .to<cjj365::HttpclientConfigProviderFile>());
}

inline auto build_base_injector(cjj365::ConfigSources &config_sources) {
  return di::make_injector(
      di::bind<cjj365::ConfigSources>().to(config_sources),
      di::bind<customio::IOutput>().to(shared_output()),
      di::bind<cjj365::IIocConfigProvider>()
          .to<cjj365::IocConfigProviderFile>(),
      di::bind<cjj365::IIoContextManager>().to<cjj365::IoContextManager>().in(
          di::singleton),
      di::bind<cjj365::IHttpclientConfigProvider>()
          .to<cjj365::HttpclientConfigProviderFile>());
}

// Mock session alias for convenience
// using MockSession = httphandler::MockHttpSession;

} // namespace testinfra
