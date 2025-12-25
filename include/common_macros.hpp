#pragma once

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <thread>

// ---------------------------------------------
// Define the macro to print messages conditionally

inline bool cjj365_is_silent() {
  // When set to a truthy value, suppress debug/verbose macro output.
  // Example: `export CJJ365_SILENT=1`
  const char* v = std::getenv("CJJ365_SILENT");
  if (!v || !*v) {
    return false;
  }

  // Treat "0" and "false" (case-insensitive) as not-silent.
  if (std::strcmp(v, "0") == 0) {
    return false;
  }
  if ((v[0] == 'f' || v[0] == 'F') && (v[1] == 'a' || v[1] == 'A') &&
      (v[2] == 'l' || v[2] == 'L') && (v[3] == 's' || v[3] == 'S') &&
      (v[4] == 'e' || v[4] == 'E') && v[5] == '\0') {
    return false;
  }

  return true;
}

#ifdef DEBUG_BUILD
#define DEBUG_PRINT(...)                                                          \
  do {                                                                            \
    if (cjj365_is_silent()) break;                                                \
    std::ostringstream _cjj365_dbg_oss;                                          \
    _cjj365_dbg_oss << "[DEBUG_PRINT] " << __VA_ARGS__;                                              \
    std::cerr << _cjj365_dbg_oss.str() << std::endl;                             \
  } while (0)
  // std::cout << "File: " << __FILE__ << " Line: " << __LINE__ << std::endl; 

#define PRINT_SEGMENTS(sv)                                               \
  do {                                                                   \
    if (cjj365_is_silent()) break;                                       \
    auto sit = sv.begin();                                               \
    std::vector<std::string> ssit(sv.size());                            \
    std::transform(sit, sv.end(), ssit.begin(),                          \
                   [](std::string_view sv) { return std::string{sv}; }); \
    std::string s = std::reduce(ssit.begin(), ssit.end(), std::string{}, \
                                [](std::string& acc, std::string& sv_) { \
                                  return acc + sv_.data() + ", ";        \
                                });                                      \
    std::cout << "[DEBUG_PRINT_SEGMENTS] " << s << std::endl;                               \
  } while (0)

#else
#define DEBUG_PRINT(...)     // No operation
#define PRINT_SEGMENTS(...)  // No operation
#endif

// ---------------------------------------------
#ifdef DEBUG_BUILD_1
#define DEBUG_PRINT_1(...)                 \
  do {                                     \
    if (cjj365_is_silent()) break;         \
    std::cout << "[DEBUG_PRINT_1] " << __VA_ARGS__ << std::endl; \
  } while (0)
#else
#define DEBUG_PRINT_1(...)  // No operation
#endif

// -------------------------------------------------

#define CJJ365_VERBOSE_LOG(...)                     \
  do {                                              \
    if (cjj365_is_silent()) break;                   \
    if (std::getenv("CJJ365_VERBOSE") != nullptr) { \
      std::cout << "[CJJ365_VERBOSE_LOG] " << __VA_ARGS__ << std::endl;        \
    }                                               \
  } while (0)


#define DECLARE_CLASS_NAME(class_name) \
  virtual std::string getClassName() const { return #class_name; }

