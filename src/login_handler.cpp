#include "handlers/login_handler.hpp"
#include "base64.h"
#include "customio/spinner.hpp"
#include "data/device_auth_types.hpp"
#include "http_client_monad.hpp"
#include "util/device_fingerprint.hpp"
#include "util/user_key_crypto.hpp"
#include "version.h"
#include <algorithm>
#include <boost/asio/ip/udp.hpp>
#include <boost/beast/http.hpp>
#include <boost/log/trivial.hpp>
#include <boost/system/error_code.hpp>
#include <boost/url.hpp>
#include <chrono>
#include <cctype>
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

using VoidPureIO = monad::IO<void>;

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
  std::string service = port_view.empty() ? std::string("443")
                                          : std::string(port_view);

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
    output_hub_.logger().trace() << "No cached device session tokens present"
                                 << std::endl;
  }

  registration_completed_ = false;
  poll_resp_.reset();
  start_resp_.reset();
}

monad::IO<bool> LoginHandler::reuse_existing_session_if_possible() {
  using namespace monad;

  auto self = shared_from_this();
  auto runtime_dir = self->resolve_runtime_dir();
  if (!runtime_dir) {
    return IO<bool>::pure(false);
  }

  auto cached_access = state_store_.get_access_token();
  auto cached_refresh = state_store_.get_refresh_token();

  const std::chrono::seconds skew(60);
  if (cached_access && is_access_token_valid(*cached_access, skew)) {
    self->registration_completed_ = true;
    return IO<bool>::pure(true);
  }

  if (cached_refresh && !cached_refresh->empty()) {
    return self->refresh_session_with_token(*cached_refresh)
        .catch_then([self](const monad::Error &e) {
          self->output_hub_.logger().warning()
              << "Refresh token attempt failed: " << e.what << std::endl;
          const std::string_view msg = e.what;
          if (msg.find("rotated") != std::string_view::npos ||
              msg.find("family revoked") != std::string_view::npos) {
            self->output_hub_.printer().yellow()
                << "Cached session tokens are no longer valid; please rerun "
                << "`cert-ctrl login --force` to re-authorize this device."
                << std::endl;
          }
          return monad::IO<bool>::pure(false);
        });
  }

  return IO<bool>::pure(false);
}

monad::IO<bool>
LoginHandler::refresh_session_with_token(const std::string &refresh_token) {
  using namespace monad;

  auto self = shared_from_this();
  const auto &base_url = self->certctrl_config_provider_.get().base_url;
  const auto refresh_url = fmt::format("{}/auth/refresh", base_url);
  auto payload_obj = std::make_shared<boost::json::object>(
      boost::json::object{{"refresh_token", refresh_token}});

  return http_io<PostJsonTag>(refresh_url)
      .map([payload_obj](auto ex) {
        ex->setRequestJsonBody(*payload_obj);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(self->http_client_))
      .then([self, refresh_url](auto ex) -> IO<bool> {
        if (!ex->is_2xx()) {
          std::string error_msg =
              std::string("Refresh token request failed via ") + refresh_url;
          if (ex->response) {
            error_msg +=
                " (HTTP " + std::to_string(ex->response->result_int()) + ")";
            if (!ex->response->body().empty()) {
              error_msg += ": " + std::string(ex->response->body());
            }
          }
          const int status =
              static_cast<int>(ex->response ? ex->response->result_int() : 500);
          return IO<bool>::fail(
              monad::make_error(status, std::move(error_msg)));
        }

        auto payload_result =
            ex->template parseJsonDataResponse<boost::json::object>();
        if (payload_result.is_err()) {
          auto err = payload_result.error();
          err.what = std::string("Refresh token response parse failed via ") +
                     refresh_url + ": " + err.what;
          return IO<bool>::fail(std::move(err));
        }
        auto response_obj = payload_result.value();
        const boost::json::object *data_ptr = &response_obj;
        if (auto *data = response_obj.if_contains("data");
            data && data->is_object()) {
          data_ptr = &data->as_object();
        }

        auto get_string =
            [](const boost::json::object &obj,
               std::string_view key) -> std::optional<std::string> {
          if (auto *p = obj.if_contains(key); p && p->is_string()) {
            return boost::json::value_to<std::string>(*p);
          }
          return std::nullopt;
        };

        std::optional<std::string> new_access_token;
        std::optional<std::string> new_refresh_token;
        std::optional<int> new_expires_in;

        if (auto *session_ptr = data_ptr->if_contains("session");
            session_ptr && session_ptr->is_object()) {
          const auto &session_obj = session_ptr->as_object();
          new_access_token = get_string(session_obj, "access_token");
          new_refresh_token = get_string(session_obj, "refresh_token");
          if (auto *p = session_obj.if_contains("expires_in");
              p && p->is_number()) {
            new_expires_in = boost::json::value_to<int>(*p);
          }
        }

        if (!new_access_token || new_access_token->empty() ||
            !new_refresh_token || new_refresh_token->empty()) {
          auto err = monad::make_error(
              my_errors::GENERAL::UNEXPECTED_RESULT,
              "Refresh token response missing required session tokens");
          return IO<bool>::fail(std::move(err));
        }

        if (auto err = self->state_store_.save_tokens(new_access_token,
                                                      new_refresh_token,
                                                      new_expires_in)) {
          self->output_hub_.logger().warning()
              << "Failed to persist refreshed tokens: " << *err << std::endl;
        }
        if (new_expires_in) {
          self->output_hub_.printer().yellow()
              << "Refreshed tokens; expires in " << *new_expires_in << "s"
              << std::endl;
        } else {
          self->output_hub_.printer().yellow()
              << "Refreshed device tokens" << std::endl;
        }
        self->registration_completed_ = true;
        return IO<bool>::pure(true);
      });
}

VoidPureIO LoginHandler::start() {
  using namespace monad;

  auto self = shared_from_this();
  auto begin_authorization = [self]() -> VoidPureIO {
    return self->start_device_authorization().then([self](auto start_resp) {
      self->output_hub_.printer().yellow()
          << "Device Authorization started.\n"
          << "User Code: " << start_resp.user_code << "\n"
          << "Verification URI: " << start_resp.verification_uri << "\n"
          << "Verification URI complete: "
          << start_resp.verification_uri_complete << "\n"
          << "Complete the authorization in your browser." << std::endl;
      return self->poll();
    });
  };
  auto should_use_api_key = [self]() {
    return self->options_.api_key && !self->options_.api_key->empty();
  };
  auto begin_api_key_registration = [self]() -> VoidPureIO {
    if (!self->options_.api_key || self->options_.api_key->empty()) {
      return VoidPureIO::fail(
          monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                            "--apikey requires a non-empty value"));
    }
    self->output_hub_.printer().yellow()
        << "API key supplied; skipping device authorization flow."
        << std::endl;
    return self->register_device_with_api_key(*self->options_.api_key);
  };

  if (options_.force) {
    self->output_hub_.printer().yellow()
        << "--force flag detected; starting fresh device authorization."
        << std::endl;
    self->clear_cached_session();
    if (should_use_api_key()) {
      return begin_api_key_registration();
    }
    return begin_authorization();
  }

  return self->reuse_existing_session_if_possible().then(
      [self, begin_authorization, begin_api_key_registration,
       should_use_api_key](bool reused) {
        if (reused) {
          self->output_hub_.printer().green()
              << "Existing device session is still "
                 "valid; skipping device authorization, add --force to override."
              << std::endl;
          return VoidPureIO::pure();
        }

        if (should_use_api_key()) {
          return begin_api_key_registration();
        }
        return begin_authorization();
      });
}

monad::IO<::data::deviceauth::StartResp>
LoginHandler::start_device_authorization() {
  using namespace monad;
  using ::data::deviceauth::StartResp;
  auto self = this->shared_from_this();
  return http_io<PostJsonTag>(self->device_auth_url_)
      .map([self](auto ex) {
        json::value body{{"action", "device_start"},
                         {"scopes", json::array{"openid", "profile", "email"}},
                         {"interval", 5},
                         {"expires_in", 900}};
        self->output_hub_.logger().trace()
            << "Starting device authorization with body: " << body << std::endl;
        ex->setRequestJsonBody(std::move(body));
        return ex;
      })
      .then(http_request_io<PostJsonTag>(self->http_client_))
      .then([self](auto ex) {
        return monad::IO<StartResp>::from_result(
            ex->template parseJsonDataResponse<StartResp>());
      })
      .then([self](StartResp start_resp) {
        self->start_resp_ = std::move(start_resp);
        return monad::IO<StartResp>::pure(*self->start_resp_);
      });
}

monad::IO<::data::deviceauth::PollResp> LoginHandler::poll_device_once() {
  using namespace monad;
  using ::data::deviceauth::PollResp;
  auto self = shared_from_this();

  if (!self->start_resp_) {
    return monad::IO<PollResp>::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Device authorization has not been started"));
  }

  return http_io<PostJsonTag>(self->device_auth_url_)
      .map([self](auto ex) {
        json::value body{{"action", "device_poll"},
                         {"device_code", self->start_resp_->device_code}};
        ex->setRequestJsonBody(std::move(body));
        return ex;
      })
      .then(http_request_io<PostJsonTag>(self->http_client_))
      .then([](auto ex) {
        return monad::IO<PollResp>::from_result(
            ex->template parseJsonDataResponse<PollResp>());
      })
      .then([self](PollResp resp) {
        self->poll_resp_ = resp;
        return monad::IO<PollResp>::pure(std::move(resp));
      });
}

VoidPureIO LoginHandler::poll() {
  using namespace monad;
  using ::data::deviceauth::PollResp;
  auto self = shared_from_this();

  if (!self->start_resp_) {
    return IO<void>::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Device authorization has not been started"));
  }

  const int interval_seconds = std::max(1, self->start_resp_->interval);
  const auto interval = std::chrono::seconds(interval_seconds);
  const int base_attempts =
      self->start_resp_->expires_in > 0
          ? self->start_resp_->expires_in / interval_seconds
          : 0;
  const int max_retries = std::max(2, base_attempts + 1);

  auto spinner = std::make_shared<customio::Spinner>(
      self->exec_, self->output_hub_.printer().stream(),
      std::string{"Polling... "}, std::chrono::milliseconds(120),
      /*enabled=*/true);
  spinner->start();

  auto attempt_counter = std::make_shared<int>(0);
  auto poll_once = [self, attempt_counter]() {
    return self->poll_device_once().map([self, attempt_counter](auto resp) {
      ++(*attempt_counter);
      self->output_hub_.logger().trace()
          << "Device authorization poll attempt " << *attempt_counter
          << " status=" << resp.status << std::endl;
      return resp;
    });
  };

  return poll_once()
      .poll_if(max_retries, interval, self->exec_,
               [](const PollResp &r) {
                 return r.status == "ready" || r.status == "approved" ||
                        r.status == "denied" || r.status == "access_denied" ||
                        r.status == "expired";
               })
      .then([self, spinner](PollResp resp) {
        spinner->stop("Polling done.");
        self->output_hub_.printer().yellow()
            << "Device Authorization polling finished.\n"
            << "Final Status: " << resp.status << "\n"
            << "Expires In: " << resp.expires_in.value_or(0) << std::endl;
        self->poll_resp_ = std::move(resp);
        if (self->poll_resp_->status == "ready" ||
            self->poll_resp_->status == "approved") {
          return self->register_device();
        }
        return VoidPureIO::pure();
      })
      .catch_then([spinner](const monad::Error &e) {
        spinner->stop();
        return monad::IO<void>::fail(e);
      });
}

VoidPureIO LoginHandler::register_device() {
  using namespace monad;
  auto self = shared_from_this();

  if (self->registration_completed_) {
    self->output_hub_.printer().yellow()
        << "Device already registered; skipping." << std::endl;
    return IO<void>::pure();
  }

  if (!self->poll_resp_) {
    return IO<void>::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Device authorization state unavailable"));
  }

  const std::string status = self->poll_resp_->status;
  if (status != "ready" && status != "approved") {
    self->output_hub_.printer().yellow()
        << "Skipping device registration; status=" << status << std::endl;
    return IO<void>::pure();
  }

  const std::string access_token =
      self->poll_resp_->access_token.value_or(std::string{});
  const std::string refresh_token =
      self->poll_resp_->refresh_token.value_or(std::string{});
  const std::string registration_code =
      self->poll_resp_->registration_code.value_or(std::string{});
  const bool have_access_token = !access_token.empty();
  const bool have_registration_code = !registration_code.empty();

  if (!have_access_token && !have_registration_code) {
    return IO<void>::fail(monad::make_error(
        my_errors::GENERAL::INVALID_ARGUMENT,
        "Device registration requires access_token or registration_code"));
  }

  if (!self->poll_resp_->user_id || self->poll_resp_->user_id->empty()) {
    return IO<void>::fail(monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
        "Device authorization poll response missing user_id"));
  }
  const std::string user_id = *self->poll_resp_->user_id;
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

  return self->perform_device_registration(
      std::move(config), self->poll_resp_ ? &*self->poll_resp_ : nullptr);
}

monad::IO<void>
LoginHandler::register_device_with_api_key(const std::string &api_key) {
  using namespace monad;
  auto self = shared_from_this();

  if (api_key.empty()) {
    return IO<void>::fail(monad::make_error(
        my_errors::GENERAL::INVALID_ARGUMENT,
        "--apikey value must not be empty"));
  }

  DeviceRegistrationRequestConfig config;
  config.api_key = api_key;
  config.include_cached_refresh_token = false;
  config.endpoint_path = "/apiv1/me/devices";

  return self->perform_device_registration(std::move(config), nullptr);
}

monad::IO<void> LoginHandler::perform_device_registration(
    DeviceRegistrationRequestConfig config,
    ::data::deviceauth::PollResp *poll_state) {
  using namespace monad;

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
  auto derived_fp_hex = cjj365::device::generate_device_fingerprint_hex(info);
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
    return IO<void>::fail(monad::make_error(
        my_errors::GENERAL::UNEXPECTED_RESULT,
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
    if (auto err =
            self->state_store_.save_device_identity(device_public_id,
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
        return IO<void>::fail(monad::make_error(
            my_errors::GENERAL::UNEXPECTED_RESULT,
            std::string{"keypair generation failed: "} + e.what()));
      }
    }
  } else {
    try {
      box_kp = cjj365::cryptutil::generate_box_keypair();
      generated_new_keys = true;
    } catch (const std::exception &e) {
      return IO<void>::fail(monad::make_error(
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

  return http_io<PostJsonTag>(devices_url)
      .map([payload = std::move(payload),
             api_key = config.api_key](auto ex) mutable {
        ex->setRequestJsonBody(std::move(payload));
        if (api_key && !api_key->empty()) {
          ex->request.set(http::field::authorization,
                          std::string("Bearer ") + *api_key);
        }
        return ex;
      })
      .then(http_request_io<PostJsonTag>(self->http_client_))
      .then([self, poll_state](auto ex) mutable {
        if (!ex->is_2xx()) {
          std::string error_msg = "Device registration failed";
          if (ex->response) {
            error_msg +=
                " (HTTP " + std::to_string(ex->response->result_int()) + ")";
            if (!ex->response->body().empty()) {
              error_msg += ": " + std::string(ex->response->body());
            }
          }
          return IO<void>::fail(monad::make_error(
              static_cast<int>(ex->response ? ex->response->result_int() : 500),
              std::move(error_msg)));
        }

        auto payload_result =
            ex->template parseJsonDataResponse<json::object>();
        if (payload_result.is_err()) {
          return IO<void>::fail(payload_result.error());
        }
        auto payload_obj = payload_result.value();
        const json::object *data_ptr = &payload_obj;
        if (auto *data = payload_obj.if_contains("data");
            data && data->is_object()) {
          data_ptr = &data->as_object();
        }

        auto get_string =
            [](const json::object &obj,
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
            if (decoded.has_payload_claim("device_id")) {
              return decoded.get_payload_claim("device_id").as_string();
            }
          } catch (...) {
          }
          return std::nullopt;
        };

        const std::string effective_access =
            new_access_token ? *new_access_token
                             : (poll_state && poll_state->access_token
                                    ? *poll_state->access_token
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
          if (auto err =
                  self->state_store_.save_tokens(access_opt, refresh_opt,
                                                 expires_opt)) {
            self->output_hub_.logger().warning()
                << "Failed to persist device session tokens: " << *err
                << std::endl;
          }
        }

        self->registration_completed_ = true;
        self->output_hub_.printer().green()
            << "Device registered successfully" << std::endl;
        if (device_id_str && !device_id_str->empty()) {
          self->output_hub_.printer().green()
              << "Assigned device ID: " << *device_id_str << std::endl;
        }
        return IO<void>::pure();
      });
}

} // namespace certctrl