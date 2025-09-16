#pragma once

#include <fmt/format.h>
#include <google/protobuf/repeated_field.h> // For RepeatedPtrField

#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <filesystem>
#include <string>

#include "conf/certctrl_config.hpp"
#include "common_macros.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace fs = std::filesystem;
namespace po = boost::program_options;

namespace certctrl {

enum class AppKind { One, Two };
// You can expand this with more dimensions if needed

template <typename T>
std::ostream &operator<<(std::ostream &os, const std::vector<T> &vec) {
  os << "[";
  for (size_t i = 0; i < vec.size(); ++i) {
    os << vec[i];
    if (i != vec.size() - 1) {
      os << ", "; // add a comma between elements
    }
  }
  os << "]";
  return os;
}

struct CliParams {
  std::vector<fs::path> config_dirs;
  std::vector<std::string> profiles;
  std::string subcmd;
  bool keep_running = false;
  std::string verbose; // vvvv
  bool silent = false;
  size_t offset = 0;
  size_t limit = 10;
};

struct CliCtx {
  po::variables_map vm;
  std::vector<std::string> positionals;
  std::vector<std::string> unrecognized;
  certctrl::CliParams params_;
  CliCtx(po::variables_map &&vm,                  //
         std::vector<std::string> &&positionals,  //
         std::vector<std::string> &&unrecognized, //
         certctrl::CliParams &&params)
      : vm(std::move(vm)), positionals(std::move(positionals)),
        unrecognized(std::move(unrecognized)), params_(std::move(params)) {}
  // Returns true iff the option exists in variables_map and was not defaulted,
  // i.e., explicitly specified by the user on the command line or in a source
  // that sets it as non-default.
  bool is_specified_by_user(const std::string &opt_name) const {
    auto it = vm.find(opt_name);
    if (it == vm.end()) {
      return false;
    }
    // defaulted() == true means value originated from a default_value
    // (not explicitly provided). Hence user-specified is the negation.
    return !it->second.defaulted();
  }
  bool positional_contains(const std::string &name) const {
    return std::find(positionals.begin(), positionals.end(), name) !=
           positionals.end();
  }
  std::pair<size_t, size_t> offset_limit() const {
    return std::make_pair(params_.offset, params_.limit);
  }

  size_t verbosity_level() const {
    if (params_.silent) {
      return 0;
    }
    if (params_.verbose.empty()) {
      return 3;
    }
    if (params_.verbose == "trace") {
      return 5;
    } else if (params_.verbose == "debug") {
      return 4;
    } else if (params_.verbose == "info") {
      return 3;
    } else if (params_.verbose == "warning") {
      return 2;
    } else if (params_.verbose == "error") {
      return 1;
    }
    return std::count(params_.verbose.begin(), params_.verbose.end(), 'v');
  }
  ~CliCtx() { DEBUG_PRINT("CliCtx destroyed"); }

  bool is_create() { return positional_contains("create"); }
  bool is_delete() { return positional_contains("delete"); }
  bool is_update() { return positional_contains("update"); }
  bool is_show() { return positional_contains("show"); }
  bool is_list() { return positional_contains("list"); }

  bool is_set() { return vm.count("set") > 0 && vm["set"].as<bool>(); }
  bool is_get() { return vm.count("get") > 0 && vm["get"].as<bool>(); }

  monad::MyResult<std::pair<std::string, std::string>> get_set_kv() {
    size_t set_pos{0};
    for (const auto &p : positionals) {
      if (p == "set") {
        break;
      }
      set_pos++;
    }
    // cmd conf set auto_fetch_config true
    if (set_pos + 2 >= positionals.size()) {
      return monad::MyResult<std::pair<std::string, std::string>>::Err(
          {.code = my_errors::GENERAL::SHOW_OPT_DESC,
           .what = "Both key and value must be provided for set operation."});
    }
    return monad::MyResult<std::pair<std::string, std::string>>::Ok(
        {positionals[set_pos + 1], positionals[set_pos + 2]});
  }

  monad::MyResult<std::string> get_get_k() {
    size_t get_pos{0};
    for (const auto &p : positionals) {
      if (p == "get") {
        break;
      }
      get_pos++;
    }
    // cmd conf get auto_fetch_config
    if (get_pos + 1 >= positionals.size()) {
      return monad::MyResult<std::string>::Err(
          {.code = my_errors::GENERAL::SHOW_OPT_DESC,
           .what = "Key must be provided for get operation."});
    }
    return monad::MyResult<std::string>::Ok(positionals[get_pos + 1]);
  }

  size_t positional_count() { return positionals.size(); }
};

inline std::string_view
get_unrecognized(const std::vector<std::string> &unrecognized,
                 const std::string &option_name) {
  auto it = std::find(unrecognized.begin(), unrecognized.end(), option_name);
  if (it != unrecognized.end() && ++it != unrecognized.end()) {
    return *it;
  }
  return "";
}

inline bool parse_bool(const std::string &value) {
  std::string val_lower = value;
  std::transform(val_lower.begin(), val_lower.end(), val_lower.begin(),
                 ::tolower);
  return (val_lower == "1" || val_lower == "true" || val_lower == "yes" ||
          val_lower == "on");
}

} // namespace certctrl
