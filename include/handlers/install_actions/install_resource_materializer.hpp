#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/trivial.hpp>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/materialize_password_manager.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "resource_fetcher.hpp"

namespace certctrl::install_actions {

class InstallResourceMaterializer
    : public IResourceMaterializer,
      public std::enable_shared_from_this<InstallResourceMaterializer> {
public:
  InstallResourceMaterializer(
      cjj365::IoContextManager &io_context_manager,       //
      certctrl::ICertctrlConfigProvider &config_provider, //
      customio::ConsoleOutput &output,                    //
      IResourceFetcher &resource_fetcher,                 //
      client_async::HttpClientManager &http_client,       //
      install_actions::IAccessTokenLoader &access_token_loader, //
      IMaterializePasswordManager &password_manager);

  ~InstallResourceMaterializer();

  monad::IO<void> ensure_materialized(const dto::InstallItem &item) override;

private:
  std::filesystem::path state_dir() const;
  std::filesystem::path resource_current_dir(const std::string &ob_type,
                                             std::int64_t ob_id) const;

  monad::IO<void>
  ensure_resource_materialized_impl(const dto::InstallItem &item);

  monad::IO<void>
  fetch_with_refresh(std::shared_ptr<MaterializationData> state,
                     bool attempted_refresh = false);

  std::optional<std::string> load_refresh_token() const;

  monad::IO<void> refresh_access_token(const std::string &refresh_token);

  static std::optional<std::string>
  write_text_0600(const std::filesystem::path &p, const std::string &text);

  std::filesystem::path runtime_state_dir() const;

  boost::asio::io_context &ensure_io_context();
  monad::IO<std::string> fetch_http_body(const std::string &url,
                                         const std::string &token,
                                         const char *context_label);

private:
  std::filesystem::path runtime_dir_;
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  IResourceFetcher &resource_fetcher_;
  client_async::HttpClientManager &http_client_;
  boost::log::sources::severity_logger<boost::log::trivial::severity_level> lg;
  boost::asio::io_context &io_context_;
  install_actions::IAccessTokenLoader &access_token_loader_;
  IMaterializePasswordManager &password_manager_;
};

} // namespace certctrl::install_actions
