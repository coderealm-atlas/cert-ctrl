#pragma once

#include <string>

namespace cjj365 {
namespace device {

// Minimal system information used for device fingerprinting
struct DeviceInfo {
  std::string platform;     // e.g., Linux, macOS, Windows, Android
  std::string os_version;   // pretty OS version when available
  std::string model;        // model or distro name where applicable
  std::string cpu_model;    // CPU model string
  std::string memory_info;  // e.g., "MemTotal: 32785472 kB" on Linux
  std::string hostname;     // device hostname
  std::string user_agent;   // optional app-level user agent string
};

// Gather best-effort basic system information (Linux-focused; graceful fallbacks elsewhere)
DeviceInfo gather_device_info(const std::string& user_agent = {});

// Compute deterministic device fingerprint (hex-encoded SHA-256) from DeviceInfo + optional entropy
// The algorithm concatenates key fields and additional_entropy, then hashes with SHA-256.
std::string generate_device_fingerprint_hex(const DeviceInfo& info,
                                            const std::string& additional_entropy = {});

// Convert a SHA-256 hex string into a short public ID using the workflow's 8-4-4-4-12 pattern
// Uses the first 32 hex chars of the SHA-256 digest to produce a 36-char hyphenated ID.
std::string device_public_id_from_fingerprint(const std::string& fingerprint_hex);

}  // namespace device
}  // namespace cjj365
