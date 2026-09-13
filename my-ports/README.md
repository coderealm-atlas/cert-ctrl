# Local vcpkg overlays

Reviewed against baseline `a1cae005c39be7b18ba319fced856b68d7276271`
(Boost 1.92.0).

- `minizip-ng`: keep the FreeBSD stat-mode patch; the upstream 4.1.0 port
  does not include it.
- `libsodium`: keep the explicit musl configure prefixes and linkage options;
  the upstream 1.0.22 port does not include this installation-layout fix.
- `bde`: retained but not selected by the current manifest. Do not remove its
  custom compiler/language setup without validating any future BDE consumers.

The c4core overlay was removed in favor of upstream c4core 0.6.0 (used by
ryml 0.16.0). Its old CPack and branch-hint workarounds are no longer needed
for this build.
