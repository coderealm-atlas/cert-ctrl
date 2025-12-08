#pragma once

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "certctrl_common.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/i_handler.hpp"
#include "handlers/install_config_manager.hpp"

namespace certctrl {

class CaHandler : public IHandler,
                  public std::enable_shared_from_this<CaHandler> {
public:
  CaHandler(cjj365::ConfigSources &config_sources, CliCtx &cli_ctx,
            customio::ConsoleOutput &output,
            std::unique_ptr<InstallConfigManager> install_config_manager);

  std::string command() const override { return "ca"; }
  monad::IO<void> start() override;

private:
  struct ListOptions {
    bool json{false};
  };

  struct ShowOptions {
    bool json{false};
    bool refresh{false};
    std::optional<std::int64_t> id;
  };

  struct CaArtifacts {
    bool has_material{false};
    std::string subject;
    std::string issuer;
    std::optional<std::chrono::system_clock::time_point> not_before;
    std::optional<std::chrono::system_clock::time_point> not_after;
    std::string fingerprint_sha256;
    std::string serial_hex;
    std::filesystem::path ca_pem_path;
    std::filesystem::path bundle_path;
    std::string error;
  };

  struct CaSummary {
    std::int64_t id{0};
    std::string name;
    CaArtifacts artifacts;
  };

  ListOptions parse_list_options(const std::string &action);
  ShowOptions parse_show_options(const std::string &action);

  monad::IO<void> handle_list();
  monad::IO<void> handle_show();
  monad::IO<void> render_show(const dto::DeviceInstallConfigDto &config,
                              std::int64_t ca_id,
                              const ShowOptions &options);

  std::vector<CaSummary>
  gather_cas(const dto::DeviceInstallConfigDto &config) const;
  CaArtifacts load_ca_artifacts(std::int64_t ca_id) const;

  static std::string format_time(
      const std::optional<std::chrono::system_clock::time_point> &tp);

  cjj365::ConfigSources &config_sources_;
  CliCtx &cli_ctx_;
  customio::ConsoleOutput &output_;
  std::unique_ptr<InstallConfigManager> install_config_manager_;
};

} // namespace certctrl
