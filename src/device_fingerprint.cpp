#include "util/device_fingerprint.hpp"

#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#endif

#include "openssl/openssl_raii.hpp"  // for sha256_hex

namespace cjj365 {
namespace device {

static std::string read_first_matching_line(const std::string& path,
                                            const std::string& key_prefix) {
  std::ifstream ifs(path);
  if (!ifs.is_open()) return {};
  std::string line;
  while (std::getline(ifs, line)) {
    if (line.rfind(key_prefix, 0) == 0) {  // starts with
      return line;
    }
  }
  return {};
}

static std::string parse_os_pretty_name() {
#if defined(__linux__)
  std::ifstream os_release("/etc/os-release");
  if (os_release.is_open()) {
    std::string line;
    while (std::getline(os_release, line)) {
      if (line.rfind("PRETTY_NAME=", 0) == 0) {
        std::string v = line.substr(12);
        if (!v.empty() && v.front() == '"' && v.back() == '"') {
          v = v.substr(1, v.size() - 2);
        }
        return v;
      }
    }
  }
  return "Linux (unknown)";
#elif defined(__APPLE__)
  return "macOS";  // TODO: fetch sw_vers when shelling out is allowed
#elif defined(_WIN32) || defined(_WIN64)
  return "Windows";  // TODO: use WinAPI for version info
#elif defined(__ANDROID__)
  return "Android";
#else
  return "Unknown";
#endif
}

static std::string parse_platform() {
#if defined(__linux__)
  return "Linux";
#elif defined(__APPLE__)
  return "macOS";
#elif defined(_WIN32) || defined(_WIN64)
  return "Windows";
#elif defined(__ANDROID__)
  return "Android";
#else
  return "Unknown";
#endif
}

static std::string parse_model() {
#if defined(__linux__)
  // Try PRETTY_NAME as a proxy for model/distro
  std::ifstream os_release("/etc/os-release");
  if (os_release.is_open()) {
    std::string line;
    while (std::getline(os_release, line)) {
      if (line.rfind("PRETTY_NAME=", 0) == 0) {
        std::string v = line.substr(12);
        if (!v.empty() && v.front() == '"' && v.back() == '"') {
          v = v.substr(1, v.size() - 2);
        }
        return v;
      }
    }
  }
  return "Linux";
#elif defined(__APPLE__)
  return "macOS";
#elif defined(_WIN32) || defined(_WIN64)
  return "Windows";
#elif defined(__ANDROID__)
  return "Android";
#else
  return "Unknown";
#endif
}

static std::string parse_cpu_model() {
#if defined(__linux__)
  std::ifstream cpuinfo("/proc/cpuinfo");
  if (cpuinfo.is_open()) {
    std::string line;
    while (std::getline(cpuinfo, line)) {
      if (line.rfind("model name", 0) == 0) {
        auto pos = line.find(':');
        if (pos != std::string::npos && pos + 2 <= line.size()) {
          return line.substr(pos + 2);
        }
      }
    }
  }
  return "Unknown CPU";
#else
  return "Unknown CPU";
#endif
}

static std::string parse_memory_info() {
#if defined(__linux__)
  std::ifstream meminfo("/proc/meminfo");
  if (meminfo.is_open()) {
    std::string line;
    while (std::getline(meminfo, line)) {
      if (line.rfind("MemTotal:", 0) == 0) {
        return line;
      }
    }
  }
  return "Unknown Memory";
#else
  return "Unknown Memory";
#endif
}

static std::string parse_hostname() {
  char buf[256] = {0};
  if (::gethostname(buf, sizeof(buf)) == 0) {
    return std::string(buf);
  }
  return "unknown-host";
}

DeviceInfo gather_device_info(const std::string& user_agent) {
  DeviceInfo info;
  info.platform = parse_platform();
  info.os_version = parse_os_pretty_name();
  info.model = parse_model();
  info.cpu_model = parse_cpu_model();
  info.memory_info = parse_memory_info();
  info.hostname = parse_hostname();
  info.user_agent = user_agent;
  return info;
}

std::string generate_device_fingerprint_hex(const DeviceInfo& info,
                                            const std::string& additional_entropy) {
  // Keep format consistent with docs: concatenate UA + PLATFORM + MODEL + entropy
  // Include more fields for collision resistance while preserving determinism per input
  std::ostringstream oss;
  oss << info.user_agent << '|' << info.platform << '|' << info.model
      << '|' << info.os_version << '|' << info.cpu_model << '|' << info.memory_info
      << '|' << info.hostname << '|' << additional_entropy;
  return cjj365::opensslutil::sha256_hex(oss.str());
}

std::string device_public_id_from_fingerprint(const std::string& fingerprint_hex) {
  // Expect a hex string; take the first 32 chars to match the shell example
  std::string hex32 = fingerprint_hex.size() >= 32 ? fingerprint_hex.substr(0, 32)
                                                   : fingerprint_hex;
  // Pad with zeros if shorter for safety
  if (hex32.size() < 32) hex32.append(32 - hex32.size(), '0');
  // 8-4-4-4-12 split (total 36 with hyphens)
  std::ostringstream id;
  id << hex32.substr(0, 8) << '-'
     << hex32.substr(8, 4) << '-'
     << hex32.substr(12, 4) << '-'
     << hex32.substr(16, 4) << '-'
     << hex32.substr(20, 12);
  return id.str();
}

}  // namespace device
}  // namespace cjj365
