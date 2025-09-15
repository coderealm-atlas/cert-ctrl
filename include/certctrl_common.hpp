#pragma once

#include <fmt/format.h>
#include <google/protobuf/repeated_field.h> // For RepeatedPtrField

#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <filesystem>
#include <string>

#include "certctrl_config.hpp"
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
};

struct CommonOptions {
  std::string verbose; // vvvv
  bool silent = false;
  size_t offset = 0;
  size_t limit = 10;

  size_t verbosity_level() const {
    if (silent) {
      return 0;
    }
    if (verbose.empty()) {
      return 3;
    }
    if (verbose == "trace") {
      return 5;
    } else if (verbose == "debug") {
      return 4;
    } else if (verbose == "info") {
      return 3;
    } else if (verbose == "warning") {
      return 2;
    } else if (verbose == "error") {
      return 1;
    }
    return std::count(verbose.begin(), verbose.end(), 'v');
  }
  // override << operator
  friend std::ostream &operator<<(std::ostream &os, const CommonOptions &co) {
    os << "offset: " << co.offset << std::endl;
    os << "limit: " << co.limit << std::endl;
    return os;
  }
};

struct CliCtx {
  po::variables_map vm;
  CommonOptions common_options;
  std::vector<std::string> positionals;
  std::vector<std::string> unrecognized;
  certctrl::CliParams params_;
  CliCtx(po::variables_map &&vm, CommonOptions &&common_options,
         std::vector<std::string> &&positionals,
         std::vector<std::string> &&unrecognized, certctrl::CliParams &&params)
      : vm(std::move(vm)), common_options(std::move(common_options)),
        positionals(std::move(positionals)),
        unrecognized(std::move(unrecognized)), params_(std::move(params)) {}
  bool positional_contains(const std::string &name) const {
    return std::find(positionals.begin(), positionals.end(), name) !=
           positionals.end();
  }
  std::pair<size_t, size_t> offset_limit() const {
    return std::make_pair(common_options.offset, common_options.limit);
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
