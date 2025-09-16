#pragma once

#include <boost/json.hpp>
#include <boost/json/conversion.hpp>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace httphandler {

namespace json = boost::json;

struct DeviceAuthRequestBody {
  std::optional<std::string> email;
  std::optional<std::string> password;
  std::optional<std::string> action;
  std::optional<std::vector<std::string>> scopes;
  std::optional<int64_t> interval;
  std::optional<int64_t> expires_in;
  std::optional<std::string> device_code;
  std::optional<std::string> user_code;
  std::optional<bool> approve;

  friend DeviceAuthRequestBody tag_invoke(
      const json::value_to_tag<DeviceAuthRequestBody>&, const json::value& jv) {
    DeviceAuthRequestBody body;
    if (auto* jo_p = jv.if_object()) {
      if (auto* p = jo_p->if_contains("action"); p && p->is_string()) {
        body.action = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("email"); p && p->is_string()) {
        body.email = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("password"); p && p->is_string()) {
        body.password = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("scopes"); p && p->is_array()) {
        body.scopes = json::value_to<std::vector<std::string>>(*p);
      }
      if (auto* p = jo_p->if_contains("interval"); p && p->is_number()) {
        body.interval = json::value_to<int64_t>(*p);
      }
      if (auto* p = jo_p->if_contains("expires_in"); p && p->is_number()) {
        body.expires_in = json::value_to<int64_t>(*p);
      }
      if (auto* p = jo_p->if_contains("device_code"); p && p->is_string()) {
        body.device_code = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("user_code"); p && p->is_string()) {
        body.user_code = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("approve"); p && p->is_bool()) {
        body.approve = json::value_to<bool>(*p);
      }
    }
    return body;
  }
  friend void tag_invoke(const json::value_from_tag&, json::value& jv,
                         const DeviceAuthRequestBody& b) {
    json::object o;
    if (b.email) o["email"] = *b.email;
    if (b.password) o["password"] = *b.password;
    if (b.action) o["action"] = *b.action;
    if (b.scopes) {
      json::array arr;
      arr.reserve(b.scopes->size());
      for (const auto& s : *b.scopes) arr.emplace_back(s);
      o["scopes"] = std::move(arr);
    }
    if (b.interval) o["interval"] = *b.interval;
    if (b.expires_in) o["expires_in"] = *b.expires_in;
    if (b.device_code) o["device_code"] = *b.device_code;
    if (b.user_code) o["user_code"] = *b.user_code;
    if (b.approve) o["approve"] = *b.approve;
    jv = std::move(o);
  }

  monad::MyResult<void> validate() const {
    auto is_valid_user_code = [](const std::string& s) -> bool {
      if (s.size() != 9) return false;
      for (size_t i = 0; i < s.size(); ++i) {
        if (i == 4) {
          if (s[i] != '-') return false;
        } else {
          if (!std::isalnum(static_cast<unsigned char>(s[i]))) return false;
          char up =
              static_cast<char>(std::toupper(static_cast<unsigned char>(s[i])));
          if (!(up >= 'A' && up <= 'Z') && !(up >= '0' && up <= '9'))
            return false;
        }
      }
      return true;
    };

    // Basic sanity by action
    if (!action || action->empty()) {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                       .what = "action is required"});
    }
    const std::string& a = *action;
    if (a == "device_start") {
      if (interval && *interval < 1) {
        return monad::MyResult<void>::Err(
            monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                         .what = "interval must be >= 1"});
      }
      if (expires_in && (*expires_in < 30 || *expires_in > 3600)) {
        return monad::MyResult<void>::Err(
            monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                         .what = "expires_in must be between 30 and 3600"});
      }
      if (scopes) {
        for (const auto& s : *scopes) {
          if (s.empty()) {
            return monad::MyResult<void>::Err(
                monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                             .what = "scope entries must be non-empty"});
          }
        }
      }
    } else if (a == "device_verify") {
      if (!user_code || user_code->empty()) {
        return monad::MyResult<void>::Err(
            monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                         .what = "user_code required for device_verify"});
      }
      if (!is_valid_user_code(*user_code)) {
        return monad::MyResult<void>::Err(monad::Error{
            .code = my_errors::GENERAL::INVALID_ARGUMENT,
            .what = "user_code must be in format XXXX-XXXX (A-Z0-9)"});
      }
    } else if (a == "device_poll") {
      if (!device_code || device_code->empty()) {
        return monad::MyResult<void>::Err(
            monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                         .what = "device_code required for device_poll"});
      }
    } else {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                       .what = "unknown action"});
    }
    return monad::MyResult<void>::Ok();
  }
};

namespace deviceauth {
struct StartResp {
  std::string device_code;
  std::string user_code;
  std::string verification_uri;
  std::string verification_uri_complete;
  int interval{5};
  int expires_in{900};

  friend void tag_invoke(const boost::json::value_from_tag&,
                         boost::json::value& jv,
                         const deviceauth::StartResp& r) {
    jv = boost::json::object{
        {"device_code", r.device_code},
        {"user_code", r.user_code},
        {"verification_uri", r.verification_uri},
        {"verification_uri_complete", r.verification_uri_complete},
        {"interval", r.interval},
        {"expires_in", r.expires_in}};
  }
  monad::MyResult<void> validate() {
    if (device_code.empty() || user_code.empty()) {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::UNEXPECTED_RESULT,
                       .what = "device auth start failed."});
    }
    // user_code format and URIs sanity
    auto is_valid_user_code = [](const std::string& s) -> bool {
      if (s.size() != 9) return false;
      for (size_t i = 0; i < s.size(); ++i) {
        if (i == 4) {
          if (s[i] != '-') return false;
        } else {
          if (!std::isalnum(static_cast<unsigned char>(s[i]))) return false;
          char up =
              static_cast<char>(std::toupper(static_cast<unsigned char>(s[i])));
          if (!(up >= 'A' && up <= 'Z') && !(up >= '0' && up <= '9'))
            return false;
        }
      }
      return true;
    };
    if (!is_valid_user_code(user_code)) {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::UNEXPECTED_RESULT,
                       .what = "invalid user_code format from start response"});
    }
    if (verification_uri.empty() || verification_uri_complete.empty()) {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::UNEXPECTED_RESULT,
                       .what = "missing verification URIs in start response"});
    }
    if (interval <= 0 || expires_in <= 0) {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::UNEXPECTED_RESULT,
                       .what = "interval and expires_in must be positive"});
    }
    return monad::MyResult<void>::Ok();
  }

  friend StartResp tag_invoke(const boost::json::value_to_tag<StartResp>&,
                              const boost::json::value& jv) {
    StartResp startResp;
    if (auto* jo_p = jv.if_object()) {
      if (auto* p = jo_p->if_contains("device_code"); p && p->is_string()) {
        startResp.device_code = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("user_code"); p && p->is_string()) {
        startResp.user_code = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("verification_uri");
          p && p->is_string()) {
        startResp.verification_uri = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("verification_uri_complete");
          p && p->is_string()) {
        startResp.verification_uri_complete = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("interval"); p && p->is_number()) {
        startResp.interval = json::value_to<int>(*p);
      }
      if (auto* p = jo_p->if_contains("expires_in"); p && p->is_number()) {
        startResp.expires_in = json::value_to<int>(*p);
      }
    }
    return startResp;
  }
};
struct PollResp {
  std::string status;
  std::string access_token;
  std::string refresh_token;
  int expires_in{0};
  friend void tag_invoke(boost::json::value_from_tag, boost::json::value& jv,
                         const deviceauth::PollResp& r) {
    jv = boost::json::object{{"status", r.status},
                             {"access_token", r.access_token},
                             {"refresh_token", r.refresh_token},
                             {"expires_in", r.expires_in}};
  }
  friend PollResp tag_invoke(const boost::json::value_to_tag<PollResp>&,
                             const boost::json::value& jv) {
    PollResp r;
    if (auto* jo_p = jv.if_object()) {
      if (auto* p = jo_p->if_contains("status"); p && p->is_string()) {
        r.status = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("access_token"); p && p->is_string()) {
        r.access_token = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("refresh_token"); p && p->is_string()) {
        r.refresh_token = json::value_to<std::string>(*p);
      }
      if (auto* p = jo_p->if_contains("expires_in"); p && p->is_number()) {
        r.expires_in = json::value_to<int>(*p);
      }
    }
    return r;
  }
  monad::MyResult<void> validate() const {
    if (status.empty()) {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                       .what = "status is required"});
    }
    auto is_allowed_status = [](const std::string& s) {
      return s == "pending" || s == "slow_down" || s == "denied" ||
             s == "expired" || s == "ready";
    };
    if (!is_allowed_status(status)) {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                       .what = "invalid status for PollResp"});
    }
    if (status == "ready") {
      if (access_token.empty() || refresh_token.empty() || expires_in <= 0) {
        return monad::MyResult<void>::Err(monad::Error{
            .code = my_errors::GENERAL::UNEXPECTED_RESULT,
            .what = "ready requires tokens and positive expires_in"});
      }
    }
    return monad::MyResult<void>::Ok();
  }
};
struct VerifyResp {
  std::string status;
  friend void tag_invoke(boost::json::value_from_tag, boost::json::value& jv,
                         const deviceauth::VerifyResp& r) {
    jv = boost::json::object{{"status", r.status}};
  }
  friend VerifyResp tag_invoke(const boost::json::value_to_tag<VerifyResp>&,
                               const boost::json::value& jv) {
    VerifyResp r;
    if (auto* jo_p = jv.if_object()) {
      if (auto* p = jo_p->if_contains("status"); p && p->is_string()) {
        r.status = json::value_to<std::string>(*p);
      }
    }
    return r;
  }
  monad::MyResult<void> validate() const {
    if (status.empty()) {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                       .what = "status is required"});
    }
    if (status != "approved" && status != "denied" && status != "pending") {
      return monad::MyResult<void>::Err(
          monad::Error{.code = my_errors::GENERAL::INVALID_ARGUMENT,
                       .what = "invalid status for VerifyResp"});
    }
    return monad::MyResult<void>::Ok();
  }
};
}  // namespace deviceauth

}  // namespace httphandler
