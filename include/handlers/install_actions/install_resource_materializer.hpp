#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "http_client_manager.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "resource_fetcher.hpp"
#include "util/my_logging.hpp"

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
      install_actions::IAccessTokenLoader &access_token_loader);

  ~InstallResourceMaterializer();

  monad::IO<void> ensure_materialized(const dto::InstallItem &item) override;

private:
  std::filesystem::path state_dir() const;
  std::filesystem::path resource_current_dir(const std::string &ob_type,
                                             std::int64_t ob_id) const;

  std::optional<std::string> lookup_bundle_password(const std::string &ob_type,
                                                    std::int64_t ob_id) const;
  void remember_bundle_password(const std::string &ob_type, std::int64_t ob_id,
                                const std::string &password);
  void forget_bundle_password(const std::string &ob_type, std::int64_t ob_id);

  monad::IO<void>
  ensure_resource_materialized_impl(const dto::InstallItem &item);

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
  IResourceFetcher::BundlePasswordLookup bundle_lookup_;
  IResourceFetcher::BundlePasswordRemember bundle_remember_;
  IResourceFetcher::BundlePasswordForget bundle_forget_;
  logsrc::severity_logger<trivial::severity_level> lg;
  boost::asio::io_context &io_context_;
  install_actions::IAccessTokenLoader &access_token_loader_;
};

} // namespace certctrl::install_actions
