#include "handlers/login_handler.hpp"
#include "base64.h"
#include "customio/spinner.hpp"
#include "data/device_auth_types.hpp"
#include "http_client_awaitable.hpp"
#include "http_client_monad.hpp"
#include "util/device_fingerprint.hpp"
#include "util/user_key_crypto.hpp"
#include "version.h"
#include <algorithm>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/http.hpp>
#include <boost/log/trivial.hpp>
#include <boost/system/error_code.hpp>
#include <boost/url.hpp>
#include <cctype>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fmt/format.h>
#include <fstream>
#include <jwt-cpp/jwt.h>
#include <string>
#include <string_view>
#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace json = boost::json;
namespace asio = boost::asio;
namespace http = boost::beast::http;

namespace certctrl {

namespace {

std::string determine_device_ip(asio::io_context &ioc,
                                const std::string &base_url) {
  static constexpr std::string_view kFallback = "";

  auto parsed = boost::urls::parse_uri(base_url);
  if (!parsed) {
    return std::string{kFallback};
  }

  auto host_view = parsed->host();
  if (host_view.empty()) {
    return std::string{kFallback};
  }

  auto port_view = parsed->port();
  std::string service =
      port_view.empty() ? std::string("443") : std::string(port_view);

  auto host_str = std::string(host_view);

  asio::ip::udp::resolver resolver(ioc);
  boost::system::error_code ec;
  auto results = resolver.resolve(asio::ip::udp::v4(), host_str, service, ec);
  if (ec || results.empty()) {
    ec = {};
    results = resolver.resolve(asio::ip::udp::v6(), host_str, service, ec);
    if (ec || results.empty()) {
      return std::string{kFallback};
    }
  }

  auto endpoint = results.begin()->endpoint();
  boost::asio::ip::udp::socket socket(ioc);
  try {
    if (endpoint.address().is_v6()) {
      socket.open(boost::asio::ip::udp::v6());
    } else {
      socket.open(boost::asio::ip::udp::v4());
    }

    socket.connect(endpoint);
    auto local_endpoint = socket.local_endpoint();
    socket.close();
    return local_endpoint.address().to_string();
  } catch (const std::exception &) {
    if (socket.is_open()) {
      socket.close();
    }
    return std::string{kFallback};
  }
}

bool is_valid_device_public_id(std::string_view candidate) {
  if (candidate.size() != 36) {
    return false;
  }
  for (size_t i = 0; i < candidate.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (candidate[i] != '-') {
        return false;
      }
      continue;
    }
    if (!std::isxdigit(static_cast<unsigned char>(candidate[i]))) {
      return false;
    }
  }
  return true;
}

} // namespace

std::optional<std::filesystem::path> LoginHandler::resolve_runtime_dir() const {
  if (runtime_dir_) {
    return runtime_dir_;
  }
  return std::nullopt;
}

bool LoginHandler::is_access_token_valid(const std::string &token,
                                         std::chrono::seconds skew) {
  try {
    auto decoded = jwt::decode(token);
    if (decoded.has_payload_claim("exp")) {
      auto exp_time = decoded.get_payload_claim("exp").as_date();
      auto now = std::chrono::system_clock::now();
      if (exp_time <= now + skew) {
        return false;
      }
    }
    return true;
  } catch (...) {
    return false;
  }
}

void LoginHandler::clear_cached_session() {
  auto runtime_dir = resolve_runtime_dir();
  if (!runtime_dir) {
    output_hub_.logger().info() << "Force login requested but runtime "
                                   "directory unavailable; nothing to clear."
                                << std::endl;
    return;
  }

  const bool had_access = state_store_.get_access_token().has_value();
  const bool had_refresh = state_store_.get_refresh_token().has_value();
  if (auto err = state_store_.clear_tokens()) {
    output_hub_.logger().warning()
        << "Failed to clear cached device session tokens: " << *err
        << std::endl;
  } else if (had_access || had_refresh) {
    output_hub_.printer().yellow()
        << "Cleared cached device session tokens." << std::endl;
  } else {
    output_hub_.logger().trace()
        << "No cached device session tokens present" << std::endl;
  }

  registration_completed_ = false;
  poll_resp_.reset();
  start_resp_.reset();
}

asio::awaitable<monad::MyResult<bool>>
LoginHandler::reuse_existing_session_if_possible_awaitable() {
  auto runtime_dir = resolve_runtime_dir();
  if (!runtime_dir) {
    co_return monad::MyResult<bool>::Ok(false);
  }

  auto cached_access = state_store_.get_access_token();
  auto cached_refresh = state_store_.get_refresh_token();

  const std::chrono::seconds skew(60);
  if (cached_access && is_access_token_valid(*cached_access, skew)) {
    registration_completed_ = true;
    co_return monad::MyResult<bool>::Ok(true);
  }

  if (cached_refresh && !cached_refresh->empty()) {
    auto refreshed =
        co_await refresh_session_with_token_awaitable(*cached_refresh);
    if (refreshed.is_ok()) {
      co_return refreshed;
    }

    const auto &error = refreshed.error();
    output_hub_.logger().warning()
        << "Refresh token attempt failed: " << error.what << std::endl;
    const std::string_view message = error.what;
    if (message.find("rotated") != std::string_view::npos ||
        message.find("family revoked") != std::string_view::npos) {
      output_hub_.printer().yellow()
          << "Cached session tokens are no longer valid; please rerun "
          << "`cert-ctrl login --force` to re-authorize this device."
          << std::endl;
    }
    co_return monad::MyResult<bool>::Ok(false);
  }

  co_return monad::MyResult<bool>::Ok(false);
}

asio::awaitable<monad::MyResult<bool>>
LoginHandler::refresh_session_with_token_awaitable(std::string refresh_token) {
  const auto &base_url = certctrl_config_provider_.get().base_url;
  const auto refresh_url = fmt::format("{}/auth/refresh", base_url);
  auto exchange_result =
      async_support::make_http_exchange<monad::PostJsonTag>(refresh_url);
  if (exchange_result.is_err()) {
    co_return monad::MyResult<bool>::Err(std::move(exchange_result).error());
  }

  auto exchange = std::move(exchange_result).value();
  exchange->setRequestJsonBody(
      boost::json::object{{"refresh_token", refresh_token}});
  auto request_result =
      co_await async_support::http_exchange_awaitable<monad::PostJsonTag>(
          http_client_, std::move(exchange));
  if (request_result.is_err()) {
    co_return monad::MyResult<bool>::Err(std::move(request_result).error());
  }
  exchange = std::move(request_result).value();

  if (!exchange->is_2xx()) {
    std::string error_msg =
        std::string("Refresh token request failed via ") + refresh_url;
    if (exchange->response) {
      error_msg +=
          " (HTTP " + std::to_string(exchange->response->result_int()) + ")";
      if (!exchange->response->body().empty()) {
        error_msg += ": " + std::string(exchange->response->body());
      }
    }
    const int status = static_cast<int>(
        exchange->response ? exchange->response->result_int() : 500);
    co_return monad::MyResult<bool>::Err(
        monad::make_error(status, std::move(error_msg)));
  }

  auto payload_result =
      exchange->template parseJsonDataResponse<boost::json::object>();
  if (payload_result.is_err()) {
    auto error = std::move(payload_result).error();
    error.what = std::string("Refresh token response parse failed via ") +
                 refresh_url + ": " + error.what;
    co_return monad::MyResult<bool>::Err(std::move(error));
  }
  auto response_obj = std::move(payload_result).value();
  const boost::json::object *data_ptr = &response_obj;
  if (auto *data = response_obj.if_contains("data");
      data && data->is_object()) {
    data_ptr = &data->as_object();
  }

  auto get_string = [](const boost::json::object &obj,
                       std::string_view key) -> std::optional<std::string> {
    if (auto *value = obj.if_contains(key); value && value->is_string()) {
      return boost::json::value_to<std::string>(*value);
    }
    return std::nullopt;
  };

  std::optional<std::string> new_access_token;
  std::optional<std::string> new_refresh_token;
  std::optional<int> new_expires_in;
  if (auto *session = data_ptr->if_contains("session");
      session && session->is_object()) {
    const auto &session_obj = session->as_object();
    new_access_token = get_string(session_obj, "access_token");
    new_refresh_token = get_string(session_obj, "refresh_token");
    if (auto *expires = session_obj.if_contains("expires_in");
        expires && expires->is_number()) {
      new_expires_in = boost::json::value_to<int>(*expires);
    }
  }

  if (!new_access_token || new_access_token->empty() || !new_refresh_token ||
      new_refresh_token->empty()) {
    co_return monad::MyResult<bool>::Err(monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        "Refresh token response missing required session tokens"));
  }

  if (auto error = state_store_.save_tokens(new_access_token, new_refresh_token,
                                            new_expires_in)) {
    output_hub_.logger().warning()
        << "Failed to persist refreshed tokens: " << *error << std::endl;
  }
  if (new_expires_in) {
    output_hub_.printer().yellow() << "Refreshed tokens; expires in "
                                   << *new_expires_in << "s" << std::endl;
  } else {
    output_hub_.printer().yellow() << "Refreshed device tokens" << std::endl;
  }
  registration_completed_ = true;
  co_return monad::MyResult<bool>::Ok(true);
}

asio::awaitable<monad::MyResult<void>> LoginHandler::start_awaitable() {
  auto begin_authorization =
      [this]() -> asio::awaitable<monad::MyResult<void>> {
    auto started = co_await start_device_authorization_awaitable();
    if (started.is_err()) {
      co_return monad::MyResult<void>::Err(std::move(started).error());
    }
    auto start_response = std::move(started).value();
    output_hub_.printer().yellow()
        << "Device Authorization started.\n"
        << "User Code: " << start_response.user_code << "\n"
        << "Verification URI: " << start_response.verification_uri << "\n"
        << "Verification URI complete: "
        << start_response.verification_uri_complete << "\n"
        << "Complete the authorization in your browser." << std::endl;
    co_return co_await poll_awaitable();
  };
  const bool use_api_key = options_.api_key && !options_.api_key->empty();

  if (options_.force) {
    output_hub_.printer().yellow()
        << "--force flag detected; starting fresh device authorization."
        << std::endl;
    clear_cached_session();
    if (use_api_key) {
      output_hub_.printer().yellow()
          << "API key supplied; skipping device authorization flow."
          << std::endl;
      co_return co_await register_device_with_api_key_awaitable(
          *options_.api_key);
    }
    co_return co_await begin_authorization();
  }

  auto reuse_result = co_await reuse_existing_session_if_possible_awaitable();
  if (reuse_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(reuse_result).error());
  }
  if (reuse_result.value()) {
    output_hub_.printer().green()
        << "Existing device session is still valid; skipping device "
           "authorization, add --force to override."
        << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  if (use_api_key) {
    output_hub_.printer().yellow()
        << "API key supplied; skipping device authorization flow." << std::endl;
    co_return co_await register_device_with_api_key_awaitable(
        *options_.api_key);
  }
  co_return co_await begin_authorization();
}

asio::awaitable<monad::MyResult<::data::deviceauth::StartResp>>
LoginHandler::start_device_authorization_awaitable() {
  using ::data::deviceauth::StartResp;
  auto exchange_result =
      async_support::make_http_exchange<monad::PostJsonTag>(device_auth_url_);
  if (exchange_result.is_err()) {
    co_return monad::MyResult<StartResp>::Err(
        std::move(exchange_result).error());
  }

  json::value body{{"action", "device_start"},
                   {"scopes", json::array{"openid", "profile", "email"}},
                   {"interval", 5},
                   {"expires_in", 900}};
  output_hub_.logger().trace()
      << "Starting device authorization with body: " << body << std::endl;
  auto exchange = std::move(exchange_result).value();
  exchange->setRequestJsonBody(std::move(body));
  auto request_result =
      co_await async_support::http_exchange_awaitable<monad::PostJsonTag>(
          http_client_, std::move(exchange));
  if (request_result.is_err()) {
    co_return monad::MyResult<StartResp>::Err(
        std::move(request_result).error());
  }

  auto parsed = std::move(request_result)
                    .value()
                    ->template parseJsonDataResponse<StartResp>();
  if (parsed.is_err()) {
    co_return monad::MyResult<StartResp>::Err(std::move(parsed).error());
  }
  start_resp_ = std::move(parsed).value();
  co_return monad::MyResult<StartResp>::Ok(*start_resp_);
}

asio::awaitable<monad::MyResult<::data::deviceauth::PollResp>>
LoginHandler::poll_device_once_awaitable() {
  using ::data::deviceauth::PollResp;
  if (!start_resp_) {
    co_return monad::MyResult<PollResp>::Err(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Device authorization has not been started"));
  }

  auto exchange_result =
      async_support::make_http_exchange<monad::PostJsonTag>(device_auth_url_);
  if (exchange_result.is_err()) {
    co_return monad::MyResult<PollResp>::Err(
        std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  exchange->setRequestJsonBody(json::value{
      {"action", "device_poll"}, {"device_code", start_resp_->device_code}});
  auto request_result =
      co_await async_support::http_exchange_awaitable<monad::PostJsonTag>(
          http_client_, std::move(exchange));
  if (request_result.is_err()) {
    co_return monad::MyResult<PollResp>::Err(std::move(request_result).error());
  }
  auto parsed = std::move(request_result)
                    .value()
                    ->template parseJsonDataResponse<PollResp>();
  if (parsed.is_err()) {
    co_return monad::MyResult<PollResp>::Err(std::move(parsed).error());
  }
  auto response = std::move(parsed).value();
  poll_resp_ = response;
  co_return monad::MyResult<PollResp>::Ok(std::move(response));
}

asio::awaitable<monad::MyResult<void>> LoginHandler::poll_awaitable() {
  using ::data::deviceauth::PollResp;
  if (!start_resp_) {
    co_return monad::MyResult<void>::Err(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Device authorization has not been started"));
  }

  const int interval_seconds = std::max(1, start_resp_->interval);
  const auto interval = std::chrono::seconds(interval_seconds);
  const int base_attempts = start_resp_->expires_in > 0
                                ? start_resp_->expires_in / interval_seconds
                                : 0;
  const int max_retries = std::max(2, base_attempts + 1);

  auto spinner = std::make_shared<customio::Spinner>(
      exec_, output_hub_.printer().stream(), std::string{"Polling... "},
      std::chrono::milliseconds(120),
      /*enabled=*/true);
  spinner->start();

  auto is_terminal = [](const PollResp &response) {
    return response.status == "ready" || response.status == "approved" ||
           response.status == "denied" || response.status == "access_denied" ||
           response.status == "expired";
  };

  for (int attempt = 1; attempt <= max_retries; ++attempt) {
    auto poll_result = co_await poll_device_once_awaitable();
    if (poll_result.is_err()) {
      if (attempt >= max_retries) {
        spinner->stop();
        co_return monad::MyResult<void>::Err(std::move(poll_result).error());
      }
      boost::asio::steady_timer retry_timer(exec_);
      retry_timer.expires_after(interval);
      boost::system::error_code timer_error;
      co_await retry_timer.async_wait(
          boost::asio::redirect_error(boost::asio::use_awaitable, timer_error));
      if (timer_error) {
        spinner->stop();
        co_return monad::MyResult<void>::Err(
            monad::Error{timer_error.value(),
                         "Polling timer failed: " + timer_error.message()});
      }
      continue;
    }

    auto response = std::move(poll_result).value();
    output_hub_.logger().trace()
        << "Device authorization poll attempt " << attempt
        << " status=" << response.status << std::endl;
    if (is_terminal(response)) {
      spinner->stop("Polling done.");
      output_hub_.printer().yellow()
          << "Device Authorization polling finished.\n"
          << "Final Status: " << response.status << "\n"
          << "Expires In: " << response.expires_in.value_or(0) << std::endl;
      poll_resp_ = std::move(response);
      if (poll_resp_->status == "ready" || poll_resp_->status == "approved") {
        co_return co_await register_device_awaitable();
      }
      co_return monad::MyResult<void>::Ok();
    }

    boost::asio::steady_timer timer(exec_);
    timer.expires_after(interval);
    boost::system::error_code timer_error;
    co_await timer.async_wait(
        boost::asio::redirect_error(boost::asio::use_awaitable, timer_error));
    if (timer_error) {
      spinner->stop();
      co_return monad::MyResult<void>::Err(
          monad::Error{timer_error.value(),
                       "Polling timer failed: " + timer_error.message()});
    }
  }

  spinner->stop();
  co_return monad::MyResult<void>::Err(
      monad::Error{3, "Polling attempts exhausted"});
}

asio::awaitable<monad::MyResult<void>>
LoginHandler::register_device_awaitable() {
  if (registration_completed_) {
    output_hub_.printer().yellow()
        << "Device already registered; skipping." << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  if (!poll_resp_) {
    co_return monad::MyResult<void>::Err(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Device authorization state unavailable"));
  }

  const std::string status = poll_resp_->status;
  if (status != "ready" && status != "approved") {
    output_hub_.printer().yellow()
        << "Skipping device registration; status=" << status << std::endl;
    co_return monad::MyResult<void>::Ok();
  }

  const std::string access_token =
      poll_resp_->access_token.value_or(std::string{});
  const std::string refresh_token =
      poll_resp_->refresh_token.value_or(std::string{});
  const std::string registration_code =
      poll_resp_->registration_code.value_or(std::string{});
  const bool have_access_token = !access_token.empty();
  const bool have_registration_code = !registration_code.empty();

  if (!have_access_token && !have_registration_code) {
    co_return monad::MyResult<void>::Err(monad::make_error(
        my_errors::GENERAL::INVALID_ARGUMENT,
        "Device registration requires access_token or registration_code"));
  }

  if (!poll_resp_->user_id || poll_resp_->user_id->empty()) {
    co_return monad::MyResult<void>::Err(monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        "Device authorization poll response missing user_id"));
  }
  const std::string user_id = *poll_resp_->user_id;
  DeviceRegistrationRequestConfig config;
  config.user_id = user_id;
  if (have_registration_code) {
    config.registration_code = registration_code;
    config.include_cached_refresh_token = false;
  } else {
    if (!refresh_token.empty()) {
      config.refresh_token = refresh_token;
    }
    config.include_cached_refresh_token = true;
  }
  config.endpoint_path = "/apiv1/device/registration";

  co_return co_await perform_device_registration_awaitable(
      std::move(config), poll_resp_ ? &*poll_resp_ : nullptr);
}

asio::awaitable<monad::MyResult<void>>
LoginHandler::register_device_with_api_key_awaitable(std::string api_key) {
  if (api_key.empty()) {
    co_return monad::MyResult<void>::Err(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "--apikey value must not be empty"));
  }

  DeviceRegistrationRequestConfig config;
  config.api_key = api_key;
  config.include_cached_refresh_token = false;
  config.endpoint_path = "/apiv1/me/devices";

  co_return co_await perform_device_registration_awaitable(std::move(config),
                                                           nullptr);
}

asio::awaitable<monad::MyResult<void>>
LoginHandler::perform_device_registration_awaitable(
    DeviceRegistrationRequestConfig config,
    ::data::deviceauth::PollResp *poll_state) {
  auto self = shared_from_this();
  const auto &base_url = self->certctrl_config_provider_.get().base_url;

  std::string endpoint_path = config.endpoint_path;
  if (endpoint_path.empty()) {
    endpoint_path = "/apiv1/device/registration";
  }
  if (endpoint_path.front() != '/') {
    endpoint_path.insert(endpoint_path.begin(), '/');
  }
  const auto devices_url = fmt::format("{}{}", base_url, endpoint_path);

  std::filesystem::path out_dir =
      self->runtime_dir_.value_or(std::filesystem::path{});

  std::string user_agent = fmt::format("cert-ctrl/{}", MYAPP_VERSION);
  auto info = cjj365::device::gather_device_info(user_agent);
  const std::string entropy = self->options_.entropy.value_or(std::string{});
  auto derived_fp_hex =
      cjj365::device::generate_device_fingerprint_hex(info, entropy);
  auto derived_device_public_id =
      cjj365::device::device_public_id_from_fingerprint(derived_fp_hex);

  bool persist_device_identity = false;
  std::string device_public_id = derived_device_public_id;
  if (!out_dir.empty()) {
    auto persisted_id = self->state_store_.get_device_public_id();
    if (persisted_id && is_valid_device_public_id(*persisted_id)) {
      device_public_id = *persisted_id;
      if (*persisted_id != derived_device_public_id) {
        self->output_hub_.logger().warning()
            << "Derived device_public_id " << derived_device_public_id
            << " differs from stored value " << *persisted_id
            << "; continuing with persisted identifier." << std::endl;
      }
    } else {
      if (persisted_id && !persisted_id->empty()) {
        self->output_hub_.logger().warning()
            << "Ignoring malformed device_public_id stored in state store;"
            << " regenerating a new identifier." << std::endl;
      }
      persist_device_identity = true;
      device_public_id = derived_device_public_id;
    }
  } else {
    self->output_hub_.logger().warning()
        << "Runtime directory unavailable; device identity will not be"
        << " persisted and may drift." << std::endl;
  }

  auto device_ip = determine_device_ip(self->ioc_, base_url);

  try {
    cjj365::cryptutil::sodium_init_or_throw();
  } catch (const std::exception &e) {
    co_return monad::MyResult<void>::Err(
        monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                          std::string{"libsodium init failed: "} + e.what()));
  }

  auto write_file_0600 = [](const std::filesystem::path &p,
                            const unsigned char *data,
                            size_t len) -> std::optional<std::string> {
    try {
      std::error_code ec;
      if (auto parent = p.parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec)
          return std::string{"create_directories failed: "} + ec.message();
      }
      {
        std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open())
          return std::string{"open failed for "} + p.string();
        ofs.write(reinterpret_cast<const char *>(data),
                  static_cast<std::streamsize>(len));
        if (!ofs)
          return std::string{"write failed for "} + p.string();
      }
#ifndef _WIN32
      ::chmod(p.c_str(), 0600);
#endif
      return std::nullopt;
    } catch (const std::exception &e) {
      return std::string{"write_file_0600 exception: "} + e.what();
    }
  };

  if (!out_dir.empty() && persist_device_identity) {
    if (auto err = self->state_store_.save_device_identity(device_public_id,
                                                           derived_fp_hex)) {
      self->output_hub_.logger().warning()
          << "Failed to persist device identity in SQLite store: " << *err
          << std::endl;
    }
  }

  cjj365::cryptutil::BoxKeyPair box_kp{};
  bool generated_new_keys = false;
  std::filesystem::path pk_path, sk_path;
  std::filesystem::path key_dir;
  if (!out_dir.empty()) {
    key_dir = out_dir / "keys";
    pk_path = key_dir / "dev_pk.bin";
    sk_path = key_dir / "dev_sk.bin";
    std::error_code ec;
    bool have_pk =
        std::filesystem::exists(pk_path, ec) &&
        std::filesystem::file_size(pk_path, ec) == crypto_box_PUBLICKEYBYTES;
    bool have_sk =
        std::filesystem::exists(sk_path, ec) &&
        std::filesystem::file_size(sk_path, ec) == crypto_box_SECRETKEYBYTES;
    if (have_pk && have_sk) {
      std::ifstream ifp(pk_path, std::ios::binary);
      std::ifstream ifs(sk_path, std::ios::binary);
      if (ifp && ifs) {
        ifp.read(reinterpret_cast<char *>(box_kp.public_key.data()),
                 crypto_box_PUBLICKEYBYTES);
        ifs.read(reinterpret_cast<char *>(box_kp.secret_key.data()),
                 crypto_box_SECRETKEYBYTES);
      }
    } else {
      try {
        box_kp = cjj365::cryptutil::generate_box_keypair();
        generated_new_keys = true;
      } catch (const std::exception &e) {
        co_return monad::MyResult<void>::Err(monad::make_error(
            my_errors::GENERAL::UNEXPECTED_RESULT,
            std::string{"keypair generation failed: "} + e.what()));
      }
    }
  } else {
    try {
      box_kp = cjj365::cryptutil::generate_box_keypair();
      generated_new_keys = true;
    } catch (const std::exception &e) {
      co_return monad::MyResult<void>::Err(monad::make_error(
          my_errors::GENERAL::UNEXPECTED_RESULT,
          std::string{"keypair generation failed: "} + e.what()));
    }
  }

  if (!out_dir.empty() && generated_new_keys) {
    if (auto err = write_file_0600(pk_path, box_kp.public_key.data(),
                                   box_kp.public_key.size())) {
      self->output_hub_.logger().warning() << *err << std::endl;
    }
    if (auto err = write_file_0600(sk_path, box_kp.secret_key.data(),
                                   box_kp.secret_key.size())) {
      self->output_hub_.logger().warning() << *err << std::endl;
    }
  }

  std::string dev_pk_b64 = base64_encode(
      box_kp.public_key.data(), box_kp.public_key.size(), /*url=*/false);
  std::string ip_for_payload =
      device_ip.empty() ? std::string{"unknown"} : std::move(device_ip);

  boost::json::object payload{
      {"device_public_id", device_public_id},
      {"platform", info.platform},
      {"model", info.model},
      {"app_version", MYAPP_VERSION},
      {"name", std::string("CLI Device ") + info.hostname},
      {"ip", ip_for_payload},
      {"user_agent", info.user_agent},
      {"dev_pk", dev_pk_b64}};

  if (config.user_id && !config.user_id->empty()) {
    try {
      auto numeric_user_id = std::stoll(*config.user_id);
      payload["user_id"] = numeric_user_id;
    } catch (...) {
      payload["user_id"] = *config.user_id;
    }
  }

  if (config.registration_code && !config.registration_code->empty()) {
    payload["registration_code"] = *config.registration_code;
  }

  std::optional<std::string> refresh_for_payload;
  if (config.refresh_token && !config.refresh_token->empty()) {
    refresh_for_payload = config.refresh_token;
  } else if (config.include_cached_refresh_token) {
    auto cached_refresh = self->state_store_.get_refresh_token();
    if (cached_refresh && !cached_refresh->empty()) {
      refresh_for_payload = cached_refresh;
    }
  }
  if (refresh_for_payload) {
    payload["refresh_token"] = *refresh_for_payload;
  }

  auto exchange_result =
      async_support::make_http_exchange<monad::PostJsonTag>(devices_url);
  if (exchange_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(exchange_result).error());
  }
  auto exchange = std::move(exchange_result).value();
  exchange->setRequestJsonBody(std::move(payload));
  if (config.api_key && !config.api_key->empty()) {
    exchange->request.set(http::field::authorization,
                          std::string("Bearer ") + *config.api_key);
  }
  auto request_result =
      co_await async_support::http_exchange_awaitable<monad::PostJsonTag>(
          self->http_client_, std::move(exchange));
  if (request_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(request_result).error());
  }
  exchange = std::move(request_result).value();

  if (!exchange->is_2xx()) {
    std::string error_msg = "Device registration failed";
    if (exchange->response) {
      error_msg +=
          " (HTTP " + std::to_string(exchange->response->result_int()) + ")";
      if (!exchange->response->body().empty()) {
        error_msg += ": " + std::string(exchange->response->body());
      }
    }
    co_return monad::MyResult<void>::Err(monad::make_error(
        static_cast<int>(exchange->response ? exchange->response->result_int()
                                            : 500),
        std::move(error_msg)));
  }

  auto payload_result =
      exchange->template parseJsonDataResponse<json::object>();
  if (payload_result.is_err()) {
    co_return monad::MyResult<void>::Err(std::move(payload_result).error());
  }
  auto payload_obj = std::move(payload_result).value();
  const json::object *data_ptr = &payload_obj;
  if (auto *data = payload_obj.if_contains("data"); data && data->is_object()) {
    data_ptr = &data->as_object();
  }

  auto get_string = [](const json::object &obj,
                       std::string_view key) -> std::optional<std::string> {
    if (auto *p = obj.if_contains(key); p && p->is_string()) {
      return json::value_to<std::string>(*p);
    }
    return std::nullopt;
  };

  auto get_int = [](const json::object &obj,
                    std::string_view key) -> std::optional<int> {
    if (auto *p = obj.if_contains(key); p && p->is_number()) {
      return json::value_to<int>(*p);
    }
    return std::nullopt;
  };

  std::optional<std::string> new_access_token;
  std::optional<std::string> new_refresh_token;
  std::optional<int> new_expires_in;
  std::optional<std::string> device_id_str;

  if (auto *session_ptr = data_ptr->if_contains("session");
      session_ptr && session_ptr->is_object()) {
    const auto &session_obj = session_ptr->as_object();
    new_access_token = get_string(session_obj, "access_token");
    new_refresh_token = get_string(session_obj, "refresh_token");
    new_expires_in = get_int(session_obj, "expires_in");
  }

  if (auto *device_ptr = data_ptr->if_contains("device");
      device_ptr && device_ptr->is_object()) {
    const auto &device_obj = device_ptr->as_object();
    if (auto *p = device_obj.if_contains("id")) {
      if (p->is_number()) {
        device_id_str = std::to_string(json::value_to<int64_t>(*p));
      } else if (p->is_string()) {
        device_id_str = json::value_to<std::string>(*p);
      }
    }
    if (!device_id_str) {
      device_id_str = get_string(device_obj, "device_public_id");
    }
  }

  if (new_access_token && poll_state) {
    poll_state->access_token = *new_access_token;
  }
  if (new_refresh_token && poll_state) {
    poll_state->refresh_token = *new_refresh_token;
  }
  if (new_expires_in && poll_state) {
    poll_state->expires_in = *new_expires_in;
  }
  if (poll_state) {
    poll_state->registration_code.reset();
  }

  auto decode_device_id =
      [](const std::string &token) -> std::optional<std::string> {
    try {
      auto decoded = jwt::decode(token);
      boost::system::error_code ec;
      auto jv = boost::json::parse(decoded.get_payload(), ec);
      if (!ec && jv.is_object()) {
        const auto &obj = jv.as_object();
        if (auto *did = obj.if_contains("device_id")) {
          if (did->is_int64()) {
            return std::to_string(did->as_int64());
          }
          if (did->is_uint64()) {
            return std::to_string(did->as_uint64());
          }
          if (did->is_string()) {
            return std::string(did->as_string().c_str());
          }
        }
      }
    } catch (...) {
    }
    return std::nullopt;
  };

  const std::string effective_access =
      new_access_token
          ? *new_access_token
          : (poll_state && poll_state->access_token ? *poll_state->access_token
                                                    : std::string{});
  const std::string effective_refresh =
      new_refresh_token ? *new_refresh_token
                        : (poll_state && poll_state->refresh_token
                               ? *poll_state->refresh_token
                               : std::string{});

  if (!device_id_str && !effective_access.empty()) {
    device_id_str = decode_device_id(effective_access);
  }

  std::optional<std::string> access_opt;
  std::optional<std::string> refresh_opt;
  if (!effective_access.empty()) {
    access_opt = effective_access;
  }
  if (!effective_refresh.empty()) {
    refresh_opt = effective_refresh;
  }
  std::optional<int> expires_opt = new_expires_in;
  if (!expires_opt && poll_state && poll_state->expires_in) {
    expires_opt = poll_state->expires_in;
  }
  if (access_opt || refresh_opt || expires_opt) {
    if (auto err = self->state_store_.save_tokens(access_opt, refresh_opt,
                                                  expires_opt)) {
      self->output_hub_.logger().warning()
          << "Failed to persist device session tokens: " << *err << std::endl;
    }
  }

  self->registration_completed_ = true;
  self->output_hub_.printer().green()
      << "Device registered successfully" << std::endl;
  if (device_id_str && !device_id_str->empty()) {
    self->output_hub_.printer().green()
        << "Assigned device ID: " << *device_id_str << std::endl;
  }
  co_return monad::MyResult<void>::Ok();
}

} // namespace certctrl
