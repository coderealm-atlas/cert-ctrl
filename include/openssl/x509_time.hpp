#pragma once

#include <openssl/asn1.h>

#include <chrono>
#include <ctime>
#include <optional>

namespace cjj365 {
namespace opensslutil {

#ifdef _WIN32
inline std::time_t timegm_portable(std::tm *tm) { return _mkgmtime(tm); }
#else
inline std::time_t timegm_portable(std::tm *tm) { return timegm(tm); }
#endif

inline std::optional<std::chrono::system_clock::time_point>
asn1_time_to_time_point(const ASN1_TIME *asn1_time) {
  if (!asn1_time) {
    return std::nullopt;
  }

  std::tm tm {};
  if (ASN1_TIME_to_tm(asn1_time, &tm) != 1) {
    return std::nullopt;
  }

  std::time_t epoch = timegm_portable(&tm);
  if (epoch == static_cast<std::time_t>(-1)) {
    return std::nullopt;
  }

  return std::chrono::system_clock::from_time_t(epoch);
}

} // namespace opensslutil
} // namespace cjj365
