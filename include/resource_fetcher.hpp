#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <fmt/format.h>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "data/install_config_dto.hpp"
#include "http_client_manager.hpp"
#include "http_client_monad.hpp"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "my_error_codes.hpp"

namespace asio = boost::asio;

namespace certctrl::install_actions {

struct MaterializationData {
  std::shared_ptr<dto::InstallItem> item;
  std::string ob_type;
  std::int64_t ob_id{0};
  bool is_cert{false};
  bool is_ca{false};
  std::filesystem::path current_dir;
  std::string deploy_raw_json;
  std::string detail_raw_json;
  std::string ca_body;
  boost::json::object deploy_obj;
  boost::json::object detail_obj;
  boost::json::object ca_obj;
  bool detail_parsed{false};
  bool deploy_available{false};
  bool ca_parsed{false};
};

class IResourceFetcher {
public:
  virtual ~IResourceFetcher() = default;
  virtual monad::IO<void> fetch(
      std::optional<std::string> /*access_token*/,
      std::shared_ptr<certctrl::install_actions::MaterializationData>) = 0;
};

// default implementation that fetches from remote server
class ResourceFetcher : public IResourceFetcher {
public:
  ResourceFetcher(cjj365::IoContextManager &io_context_manager,
                  certctrl::ICertctrlConfigProvider &config_provider,
                  customio::ConsoleOutput &output,
                  client_async::HttpClientManager &http_client)
      : config_provider_(config_provider), output_(output),
        http_client_(http_client), io_context_(io_context_manager.ioc()) {}

  monad::IO<void>
  fetch(std::optional<std::string> token_opt,
        std::shared_ptr<certctrl::install_actions::MaterializationData>
            current_materialization) override {
    return monad::IO<void>::pure();
  }

private:
  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;
  asio::io_context &io_context_;
};
} // namespace certctrl::install_actions