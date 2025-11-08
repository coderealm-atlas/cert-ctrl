#pragma once

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/program_options.hpp>

#include "certctrl_common.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/i_handler.hpp"
#include "handlers/install_config_manager.hpp"

namespace certctrl {

class CertificatesHandler : public IHandler,
                            public std::enable_shared_from_this<CertificatesHandler> {
public:
  CertificatesHandler(cjj365::ConfigSources &config_sources,
                      CliCtx &cli_ctx,
                      customio::ConsoleOutput &output,
                      std::unique_ptr<InstallConfigManager> install_config_manager);

  std::string command() const override { return "certificates"; }
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

  struct CertificateArtifacts {
    bool has_material{false};
    std::string subject;
    std::string issuer;
    std::vector<std::string> sans;
    std::optional<std::chrono::system_clock::time_point> not_before;
    std::optional<std::chrono::system_clock::time_point> not_after;
    std::string fingerprint_sha256;
    std::string serial_hex;
    std::filesystem::path certificate_path;
    std::filesystem::path detail_path;
    std::filesystem::path bundle_path;
    std::filesystem::path private_key_path;
    std::string error;
  };

  struct CertificateSummary {
    std::int64_t id{0};
    std::string name;
    CertificateArtifacts artifacts;
  };

  ListOptions parse_list_options(const std::string &action);
  ShowOptions parse_show_options(const std::string &action);

  monad::IO<void> handle_list();
  monad::IO<void> handle_show();

  monad::IO<void> render_show(const dto::DeviceInstallConfigDto &config,
                              std::int64_t cert_id,
                              const ShowOptions &options);

  std::vector<CertificateSummary>
  gather_certificates(const dto::DeviceInstallConfigDto &config) const;

  CertificateArtifacts
  load_certificate_artifacts(std::int64_t cert_id) const;

  static std::string
  format_time(const std::optional<std::chrono::system_clock::time_point> &tp);

  static std::string join_sans(const std::vector<std::string> &sans);

  cjj365::ConfigSources &config_sources_;
  CliCtx &cli_ctx_;
  customio::ConsoleOutput &output_;
  std::unique_ptr<InstallConfigManager> install_config_manager_;
};

} // namespace certctrl
