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
  info.dmi_product_uuid = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";
  info.dmi_product_serial = "SERIAL-ABC-123";
  info.dmi_board_serial = "BOARD-XYZ-789";
  info.dmi_chassis_serial = "CHASSIS-555";
  info.mac_addresses = "00:11:22:33:44:55,66:77:88:99:aa:bb";
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

TEST(DeviceFingerprintTest, EntropyAffectsFingerprint) {
  auto base_info = make_base_info();
  auto fp_a =
      cjj365::device::generate_device_fingerprint_hex(base_info, "alpha");
  auto fp_b =
      cjj365::device::generate_device_fingerprint_hex(base_info, "beta");

  EXPECT_NE(fp_a, fp_b);
  EXPECT_NE(cjj365::device::device_public_id_from_fingerprint(fp_a),
            cjj365::device::device_public_id_from_fingerprint(fp_b));
}

TEST(DeviceFingerprintTest, ChangesWhenHardwareTraitsChange) {
  auto base_info = make_base_info();
  auto baseline =
      cjj365::device::generate_device_fingerprint_hex(base_info);

  auto altered = base_info;
  altered.dmi_product_uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff";
  altered.mac_addresses = "aa:bb:cc:dd:ee:ff";
  auto altered_fp =
      cjj365::device::generate_device_fingerprint_hex(altered);

  EXPECT_NE(baseline, altered_fp);
  EXPECT_NE(cjj365::device::device_public_id_from_fingerprint(baseline),
            cjj365::device::device_public_id_from_fingerprint(altered_fp));
}

} // namespace
