#include "handlers/device_automation_handler.hpp"

#include "http_client_monad.hpp"
#include "my_error_codes.hpp"
#include "util/device_fingerprint.hpp"
#include "version.h"
#include <algorithm>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <fmt/format.h>
#include <optional>
#include <vector>

namespace certctrl {
namespace {

namespace po = boost::program_options;
namespace json = boost::json;
namespace http = boost::beast::http;

std::vector<std::string>
filter_tokens(const std::vector<std::string> &source,
              const std::vector<std::string> &excluded) {
  if (excluded.empty()) {
    return source;
  }

  std::vector<std::string> result;
  result.reserve(source.size());
  std::vector<std::string> remaining = excluded;

  for (const auto &token : source) {
    auto it = std::find(remaining.begin(), remaining.end(), token);
    if (it != remaining.end()) {
      remaining.erase(it);
      continue;
    }
    result.push_back(token);
  }
  return result;
}

std::optional<std::string>
resolve_device_public_id(customio::ConsoleOutput &output,
                         certctrl::IDeviceStateStore &state_store) {
  if (auto stored = state_store.get_device_public_id();
      stored && !stored->empty()) {
    return stored;
  }

  auto device_info = cjj365::device::gather_device_info(
      fmt::format("cert-ctrl/{}", MYAPP_VERSION));
  auto fingerprint =
      cjj365::device::generate_device_fingerprint_hex(device_info);
  if (fingerprint.empty()) {
    output.logger().warning() << "Unable to derive device fingerprint; "
                                 "device_id required for automation."
                              << std::endl;
    return std::nullopt;
  }

  auto derived_id =
      cjj365::device::device_public_id_from_fingerprint(fingerprint);
  if (derived_id.empty()) {
    output.logger().warning()
        << "Unable to derive device_id from fingerprint." << std::endl;
    return std::nullopt;
  }

  const std::optional<std::string> id_payload(derived_id);
  const std::optional<std::string> fp_payload(fingerprint);
  if (auto err = state_store.save_device_identity(id_payload, fp_payload)) {
    output.logger().warning()
        << "Failed to persist derived device identity: " << *err << std::endl;
  }

  return derived_id;
}

} // namespace

DeviceAutomationHandler::DeviceAutomationHandler(
    CliCtx &cli_ctx, customio::ConsoleOutput &output,
    certctrl::ICertctrlConfigProvider &config_provider,
    client_async::HttpClientManager &http_client,
    certctrl::IDeviceStateStore &state_store)
    : cli_ctx_(cli_ctx), output_(output), config_provider_(config_provider),
      http_client_(http_client), state_store_(state_store) {}

monad::IO<void> DeviceAutomationHandler::start() {
  if (cli_ctx_.positionals.size() < 2) {
    return show_usage("Missing device action.");
  }

  const std::string action = cli_ctx_.positionals[1];
  bool requested_help = false;
  auto api_key = parse_api_key_option(action, requested_help);

  if (requested_help) {
    return show_usage();
  }

  if (!api_key || api_key->empty()) {
    return show_usage("--apikey is required for device automation actions.");
  }

  return dispatch_action(action, *api_key);
}

monad::IO<void>
DeviceAutomationHandler::dispatch_action(const std::string &action,
                                         const std::string &api_key) {
  if (action == "assign-cert") {
    return handle_assign_certificate(api_key);
  }

  return show_usage(fmt::format("Unknown device action '{}'.", action));
}

std::optional<std::string>
DeviceAutomationHandler::parse_api_key_option(const std::string &action,
                                              bool &requested_help) const {
  requested_help = false;
  std::string api_key_value;

  po::options_description desc("device options");
  desc.add_options()("apikey", po::value<std::string>(&api_key_value),
                     "API key that carries automation context")(
      "help,h", "Show this help message");

  auto args = filter_tokens(cli_ctx_.unrecognized,
                            std::vector<std::string>{command(), action});

  try {
    po::variables_map vm;
    po::store(
        po::command_line_parser(args).options(desc).allow_unregistered().run(),
        vm);
    po::notify(vm);

    if (vm.count("help")) {
      requested_help = true;
      return std::nullopt;
    }

    if (vm.count("apikey")) {
      return api_key_value;
    }

    return std::nullopt;
  } catch (const std::exception &ex) {
    return std::nullopt;
  }
}

monad::IO<void>
DeviceAutomationHandler::handle_assign_certificate(const std::string &api_key) {
  using namespace monad;

  auto device_public_id = resolve_device_public_id(output_, state_store_);
  if (!device_public_id) {
    return IO<void>::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Unable to resolve device_id; run 'cert-ctrl login' "
                          "to register this device."));
  }

  const auto &base_url = config_provider_.get().base_url;
  const auto url = fmt::format("{}/apiv1/me/certificate-assign", base_url);

  json::object payload;
  payload["device_public_id"] = *device_public_id;

  return http_io<PostJsonTag>(url)
      .map([payload = std::move(payload), api_key](auto ex) mutable {
        ex->setRequestJsonBody(std::move(payload));
        ex->request.set(http::field::authorization,
                        std::string("Bearer ") + api_key);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(http_client_))
      .then([this](auto ex) -> monad::IO<void> {
        if (!ex->is_2xx()) {
          std::string error_msg = "Certificate assignment failed";
          if (ex->response) {
            error_msg += fmt::format(" (HTTP {})", ex->response->result_int());
            if (!ex->response->body().empty()) {
              error_msg += ": " + std::string(ex->response->body());
            }
          }
          return monad::IO<void>::fail(monad::make_error(
              static_cast<int>(ex->response ? ex->response->result_int() : 500),
              std::move(error_msg)));
        }

        std::string status_message =
            "Certificate assignment request completed.";
        auto parsed = ex->template parseJsonDataResponse<json::object>();
        if (!parsed.is_err()) {
          const json::object &root = parsed.value();
          auto extract_message =
              [](const json::object &obj) -> std::optional<std::string> {
            if (auto *msg = obj.if_contains("message");
                msg && msg->is_string()) {
              return std::string(msg->as_string().c_str());
            }
            if (auto *status = obj.if_contains("status");
                status && status->is_string()) {
              return std::string(status->as_string().c_str());
            }
            return std::nullopt;
          };

          if (auto msg = extract_message(root)) {
            status_message = *msg;
          } else if (auto *data = root.if_contains("data");
                     data && data->is_object()) {
            if (auto msg = extract_message(data->as_object())) {
              status_message = *msg;
            }
          }
        }

        output_.printer().green() << status_message << std::endl;
        return monad::IO<void>::pure();
      });
}

monad::IO<void>
DeviceAutomationHandler::show_usage(const std::string &error) const {
  if (!error.empty()) {
    output_.logger().error() << error << std::endl;
  }

  output_.printer().yellow()
      << "Usage: cert-ctrl device <action> --apikey <token>" << std::endl;
  output_.printer().white() << "Available actions:" << std::endl
                            << "  assign-cert    Request certificate "
                               "assignment via /apiv1/me/certificate-assign"
                            << std::endl;
  output_.printer().white()
      << "Example: cert-ctrl device assign-cert --apikey $TOKEN" << std::endl;

  return monad::IO<void>::fail(monad::make_error(
      my_errors::GENERAL::SHOW_OPT_DESC, "cert-ctrl device usage"));
}

} // namespace certctrl
