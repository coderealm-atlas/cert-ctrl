#include <gtest/gtest.h>

#include <string>

#include "util/device_fingerprint.hpp"

namespace {

cjj365::device::DeviceInfo make_base_info() {
  cjj365::device::DeviceInfo info;
  info.platform = "Linux";
  info.os_version = "Ubuntu 22.04";
  info.model = "Ubuntu";
  info.cpu_model = "Intel(R) Xeon(R)";
  info.memory_info = "MemTotal: 32785472 kB";
  info.hostname = "mail-gateway-01";
  info.user_agent = "cert-ctrl/1.4.0";
  return info;
}

TEST(DeviceFingerprintTest, StableAcrossUserAgentChanges) {
  auto info_v1 = make_base_info();
  auto fingerprint_v1 =
      cjj365::device::generate_device_fingerprint_hex(info_v1);

  auto info_v2 = info_v1;
  info_v2.user_agent = "cert-ctrl/2.0.0";
  auto fingerprint_v2 =
      cjj365::device::generate_device_fingerprint_hex(info_v2);

  EXPECT_EQ(fingerprint_v1, fingerprint_v2);
  EXPECT_EQ(cjj365::device::device_public_id_from_fingerprint(fingerprint_v1),
            cjj365::device::device_public_id_from_fingerprint(fingerprint_v2));
}

TEST(DeviceFingerprintTest, ChangesWhenStableTraitChanges) {
  auto base_info = make_base_info();
  auto baseline =
      cjj365::device::generate_device_fingerprint_hex(base_info);

  auto moved_host = base_info;
  moved_host.hostname = "mail-gateway-02";
  auto moved_fp =
      cjj365::device::generate_device_fingerprint_hex(moved_host);

  EXPECT_NE(baseline, moved_fp);
  EXPECT_NE(cjj365::device::device_public_id_from_fingerprint(baseline),
            cjj365::device::device_public_id_from_fingerprint(moved_fp));
}

} // namespace
