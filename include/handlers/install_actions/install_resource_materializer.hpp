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
#include "io_monad.hpp"
#include "util/my_logging.hpp"

namespace certctrl::install_actions {

class InstallResourceMaterializer
    : public IResourceMaterializer,
      public std::enable_shared_from_this<InstallResourceMaterializer> {
public:
  using ResourceFetchOverrideFn =
      std::function<std::optional<std::string>(const dto::InstallItem &)>;
  using AccessTokenLoader = std::function<std::optional<std::string>()>;
  using BundlePasswordLookup = std::function<std::optional<std::string>(
      const std::string &, std::int64_t)>;
  using BundlePasswordRemember = std::function<void(
      const std::string &, std::int64_t, const std::string &)>;
  using BundlePasswordForget =
      std::function<void(const std::string &, std::int64_t)>;

  struct RuntimeConfig {
    std::filesystem::path runtime_dir;
    AccessTokenLoader access_token_loader;
    ResourceFetchOverrideFn resource_fetch_override;
    BundlePasswordLookup bundle_lookup;
    BundlePasswordRemember bundle_remember;
    BundlePasswordForget bundle_forget;
  };

  InstallResourceMaterializer(certctrl::ICertctrlConfigProvider &config_provider,
                              customio::ConsoleOutput &output,
                              client_async::HttpClientManager *http_client,
                              boost::asio::io_context *io_context = nullptr);

  ~InstallResourceMaterializer();

  void customize(RuntimeConfig config);
  void update_runtime_dir(std::filesystem::path runtime_dir);
  void update_resource_fetch_override(ResourceFetchOverrideFn fn);
  void update_access_token_loader(AccessTokenLoader loader);
  void update_bundle_hooks(BundlePasswordLookup lookup,
                           BundlePasswordRemember remember,
                           BundlePasswordForget forget);

  monad::IO<void> ensure_materialized(const dto::InstallItem &item) override;

private:
  std::filesystem::path state_dir() const;
  std::filesystem::path resource_current_dir(const std::string &ob_type,
                                             std::int64_t ob_id) const;

  std::optional<std::string> load_access_token() const;
  std::optional<std::string> lookup_bundle_password(const std::string &ob_type,
                                                    std::int64_t ob_id) const;
  void remember_bundle_password(const std::string &ob_type, std::int64_t ob_id,
                                const std::string &password);
  void forget_bundle_password(const std::string &ob_type, std::int64_t ob_id);

  monad::IO<void>
  ensure_resource_materialized_impl(const dto::InstallItem &item);

  boost::asio::io_context &ensure_io_context();
  monad::IO<std::string>
  fetch_http_body(const std::string &url, const std::string &token,
                  const char *context_label);

private:
  std::filesystem::path runtime_dir_;
  certctrl::ICertctrlConfigProvider *config_provider_{nullptr};
  customio::ConsoleOutput *output_{nullptr};
  client_async::HttpClientManager *http_client_{nullptr};
  AccessTokenLoader access_token_loader_;
  ResourceFetchOverrideFn resource_fetch_override_;
  BundlePasswordLookup bundle_lookup_;
  BundlePasswordRemember bundle_remember_;
  BundlePasswordForget bundle_forget_;
  logsrc::severity_logger<trivial::severity_level> lg;
  boost::asio::io_context *io_context_{nullptr};
  std::unique_ptr<boost::asio::io_context> owned_io_context_;
  std::unique_ptr<
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>
      owned_io_work_guard_;
  std::thread owned_io_thread_;
};

} // namespace certctrl::install_actions
