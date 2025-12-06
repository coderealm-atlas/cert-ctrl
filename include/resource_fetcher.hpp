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
#include "state/device_state_store.hpp"

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

class IAccessTokenLoader {
public:
  virtual ~IAccessTokenLoader() = default;
  virtual std::optional<std::string> load_token() const = 0;
};

class AccessTokenLoaderFile : public IAccessTokenLoader {
  certctrl::IDeviceStateStore &state_store_;

public:
  AccessTokenLoaderFile(certctrl::IDeviceStateStore &state_store)
      : state_store_(state_store) {}

  std::optional<std::string> load_token() const override {
    return state_store_.get_access_token();
  }
};

class IResourceFetcher {
public:
  using AccessTokenLoader = std::function<std::optional<std::string>()>;
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
        std::shared_ptr<certctrl::install_actions::MaterializationData> state)
      override {
    output_.logger().debug() << "ResourceFetcher::fetch ob_type="
                             << state->ob_type << " ob_id=" << state->ob_id
                             << " has_token="
                             << (token_opt && !token_opt->empty() ? "true"
                                                               : "false")
                             << std::endl;
    if (!token_opt || token_opt->empty()) {
      auto err = monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                                   "Device access token unavailable");
      BOOST_LOG_SEV(lg, trivial::error)
          << "ensure_resource_materialized_impl cert fetch missing token "
             "ob_id="
          << state->ob_id;
      return monad::IO<void>::fail(std::move(err));
    }
    if (state->is_cert) {
      return fetch_cert(*token_opt, state);
    } else if (state->is_ca) {
      output_.logger().debug() << "Dispatching CA fetch ob_id="
                               << state->ob_id << std::endl;
      return fetch_ca(*token_opt, state);
    }
    BOOST_LOG_SEV(lg, trivial::error)
        << "ResourceFetcher::fetch called for unknown resource type ob_type="
        << state->ob_type << " ob_id=" << state->ob_id;
    return monad::IO<void>::pure();
  }

private:
  std::optional<boost::json::object>
  parse_bundle_data(const std::string &body) {
    boost::system::error_code ec;
    auto parsed = boost::json::parse(body, ec);
    if (ec || !parsed.is_object()) {
      return std::nullopt;
    }
    auto &obj = parsed.as_object();
    if (auto *data = obj.if_contains("data"); data && data->is_object()) {
      return data->as_object();
    }
    return std::nullopt;
  }
  monad::IO<void> fetch_ca(
      const std::string &token,
      std::shared_ptr<certctrl::install_actions::MaterializationData> state) {

    const auto &cfg = config_provider_.get();
    std::string url =
        fmt::format("{}/apiv1/devices/self/cas/{}/bundle?pack=download",
                    cfg.base_url, state->ob_id);

    monad::IO<void> pipeline = monad::IO<void>::pure();
    pipeline = pipeline.then([this, state, url, token]() {
      this->output_.logger().debug()
          << "Fetching CA bundle ob_id=" << state->ob_id
          << " url=" << url << std::endl;
      return this->fetch_http_body(url, token, "ca bundle")
          .map([state, this](std::string body) {
            this->output_.logger().debug()
                << "Fetched CA bundle bytes=" << body.size()
                << " ob_id=" << state->ob_id << std::endl;
            state->ca_body = std::move(body);
          })
          .then([state, this]() {
            auto bundle_data = this->parse_bundle_data(state->ca_body);
            if (!bundle_data) {
              auto err =
                  monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                                    "CA bundle response missing expected data");
              return monad::IO<void>::fail(std::move(err));
            }
            state->ca_obj = std::move(*bundle_data);
            state->ca_parsed = true;
            this->output_.logger().debug()
                << "Parsed CA bundle ob_id=" << state->ob_id << std::endl;
            return monad::IO<void>::pure();
          });
    });
    return pipeline;
  }

  monad::IO<void> fetch_cert(
      const std::string &token,
      std::shared_ptr<certctrl::install_actions::MaterializationData> state) {

    const auto &cfg = config_provider_.get();
    std::string detail_url = fmt::format(
        "{}/apiv1/devices/self/certificates/{}", cfg.base_url, state->ob_id);
    std::string deploy_url =
        fmt::format("{}/apiv1/devices/self/certificates/{}/deploy-materials",
                    cfg.base_url, state->ob_id);
    monad::IO<void> pipeline = monad::IO<void>::pure();
    pipeline = pipeline.then([this, state, detail_url, deploy_url, token]() {
      return this->fetch_http_body(detail_url, token, "certificate detail")
          .map([state](std::string body) {
            state->detail_raw_json = std::move(body);
          })
          .then([this, state, deploy_url, token]() {
            return this->fetch_http_body(deploy_url, token, "deploy materials")
                .map([state](std::string body) {
                  state->deploy_raw_json = std::move(body);
                  state->deploy_available = true;
                })
                .catch_then([state, this](monad::Error err) {
                  if (err.response_status == 404 ||
                      err.response_status == 204) {
                    state->deploy_available = false;
                    boost::json::object placeholder;
                    placeholder["note"] = "no deploy materials provided; "
                                          "generated locally by agent";
                    state->deploy_raw_json = boost::json::serialize(
                        boost::json::object{{"data", placeholder}});
                    this->output_.logger().info()
                        << "Deploy materials endpoint unavailable for cert "
                        << state->ob_id << " (status=" << err.response_status
                        << "); falling back to certificate detail payload"
                        << std::endl;
                    return monad::IO<void>::pure();
                  }
                  return monad::IO<void>::fail(std::move(err));
                })
                .then([state, this]() {
                  auto detail_err = this->parse_enveloped_object(
                      state->detail_raw_json, "certificate detail",
                      state->detail_obj);
                  if (detail_err) {
                    return monad::IO<void>::fail(std::move(*detail_err));
                  }
                  state->detail_parsed = true;

                  if (!state->deploy_raw_json.empty()) {
                    boost::json::object deploy_obj;
                    auto deploy_err = this->parse_enveloped_object(
                        state->deploy_raw_json, "deploy materials", deploy_obj);
                    if (deploy_err) {
                      return monad::IO<void>::fail(std::move(*deploy_err));
                    }
                    state->deploy_obj = std::move(deploy_obj);
                  }
                  return monad::IO<void>::pure();
                });
          });
    });
    return pipeline;
  }

  monad::IO<std::string> fetch_http_body(const std::string &url,
                                         const std::string &token,
                                         const char *context_label) {
    using monad::GetStringTag;
    using monad::http_io;
    using monad::http_request_io;
    using ExchangePtr = monad::ExchangePtrFor<GetStringTag>;

    namespace http = boost::beast::http;

    constexpr int kMaxAttempts = 12;
    constexpr std::chrono::seconds kRetryBaseDelay{3};

    auto attempt_counter = std::make_shared<int>(0);

    auto fetch_once =
        http_io<GetStringTag>(url)
            .map([this, attempt_counter, token, url, context_label, kMaxAttempts](auto ex) {
              const int current_attempt = ++(*attempt_counter);
              BOOST_LOG_SEV(lg, trivial::trace)
                  << "fetch_http_body attempt " << current_attempt << '/'
                  << kMaxAttempts << " for url=" << url
                  << " context=" << context_label;
              ex->request.set(http::field::authorization,
                              std::string("Bearer ") + token);
              return ex;
            })
            .then(http_request_io<GetStringTag>(http_client_))
            .then([this, url, context_label,
                   attempt_counter](ExchangePtr ex) -> monad::IO<std::string> {
              if (!ex->response.has_value()) {
                BOOST_LOG_SEV(lg, trivial::warning)
                    << "fetch_http_body received empty response for url=" << url
                    << " context=" << context_label;
                return monad::IO<std::string>::fail(
                    monad::make_error(my_errors::NETWORK::READ_ERROR,
                                      "No response while fetching resource"));
              }

              int status = ex->response->result_int();
              std::string body = ex->response->body();

              if (status == 200) {
                BOOST_LOG_SEV(lg, trivial::trace)
                    << "fetch_http_body succeeded for url=" << url
                    << " context=" << context_label
                    << " (status=200, bytes=" << body.size() << ')';
                return monad::IO<std::string>::pure(std::move(body));
              }

              auto err = monad::make_error(
                  my_errors::NETWORK::READ_ERROR,
                  fmt::format("Resource fetch HTTP {}", status));
              err.response_status = status;
              err.params["response_body_preview"] = body.substr(0, 512);

              if (status == 503) {
                BOOST_LOG_SEV(lg, trivial::warning)
                    << "fetch_http_body retry for url=" << url
                    << " context=" << context_label
                    << " attempt=" << *attempt_counter;
              } else {
                BOOST_LOG_SEV(lg, trivial::warning)
                    << "fetch_http_body aborting status=" << status
                    << " url=" << url << " context=" << context_label;
              }

              return monad::IO<std::string>::fail(std::move(err));
            });

    auto should_retry = [attempt_counter, kMaxAttempts](const monad::Error &err) {
      return err.response_status == 503 && *attempt_counter < kMaxAttempts;
    };

    return std::move(fetch_once)
        .retry_exponential_if(kMaxAttempts, kRetryBaseDelay, io_context_,
                              should_retry);
  }

  std::optional<monad::Error> parse_enveloped_object(const std::string &raw,
                                                     const char *context,
                                                     boost::json::object &out) {
    boost::system::error_code ec;
    auto parsed = boost::json::parse(raw, ec);
    if (ec || !parsed.is_object()) {
      return monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                               fmt::format("{} response not a JSON object: {}",
                                           context, ec ? ec.message() : ""));
    }
    auto &obj = parsed.as_object();
    if (auto *data = obj.if_contains("data")) {
      if (data->is_object()) {
        out = data->as_object();
        return std::nullopt;
      }
    }
    return monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        fmt::format("{} response missing data object", context));
  }

  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  client_async::HttpClientManager &http_client_;
  asio::io_context &io_context_;
  logsrc::severity_logger<trivial::severity_level> lg;
};
} // namespace certctrl::install_actions