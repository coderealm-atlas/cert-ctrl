# Cross platform problems

record the output of the errors.

## suse leap 16

```bash
dev@suseleap16:~> sudo cert-ctrl login
sudo: cert-ctrl: command not found
dev@suseleap16:~> sudo /usr/local/bin/cert-ctrl login
error catched on main: context: unknown option (digital envelope routines) [asio.ssl:50331817]
dev@suseleap16:~> 
```

### Plan

1. **Binary availability** – add `/usr/local/bin` to the default PATH in the install instructions, or symlink `cert-ctrl` into `/usr/bin` to avoid the `command not found` detour.
2. **OpenSSL compatibility** – build a SUSE-specific artifact linked against the distro OpenSSL 3 package (libopenssl3) or ship the appropriate `libssl.so` alongside the binary. Reproduce by running `ldd /usr/local/bin/cert-ctrl` and `openssl version` on Leap 16 to confirm symbol mismatch causing `digital envelope routines` errors.
3. **Installer updates** – extend `install.sh` to detect SUSE (`ID=sles|opensuse`) and install the matching package or emit instructions to install the required `libopenssl1_1` compatibility package when necessary.
4. **Validation** – once rebuilt, run `cert-ctrl login` under SUSE Leap CI runner and capture logs confirming TLS handshake succeeds.


## rocky 10

```bash
[dev1@localhost ~]$ curl -fsSL "https://install.lets-script.com/install.sh?force=1" | sudo bash
[sudo] dev1 的密码：
[INFO] Starting cert-ctrl installation...
[INFO] Resolving latest version...
[INFO] Downloading cert-ctrl v0.1.1-81-ge8446fa4 for linux-x64...
[INFO] Verifying archive integrity...
[SUCCESS] Checksum verified
[INFO] Installing to /usr/local/bin...
[SUCCESS] Binary installed
[INFO] Installing systemd unit at /etc/systemd/system/certctrl.service
[INFO] Creating config directory /etc/certctrl
[INFO] Creating state directory /var/lib/certctrl
[SUCCESS] Systemd unit installed successfully
[INFO] Enabling and starting certctrl.service
Failed to enable unit: Unit certctrl.service does not exist
[WARNING] Service installation completed but failed to start
[INFO] Check logs with: journalctl -u certctrl.service
[INFO] Start manually with: systemctl start certctrl.service
[SUCCESS] cert-ctrl installed successfully!
[SUCCESS] Installation verified! Version: v0.1.1-81-ge8446fa4

[SUCCESS] cert-ctrl installation completed!

Next steps:
  - Run: cert-ctrl --help
  - Check service status: systemctl status certctrl.service
```

### Plan

1. **Service install sequencing** – after dropping `/etc/systemd/system/certctrl.service`, run `systemctl daemon-reload` before `systemctl enable` to ensure systemd sees the new unit.
2. **Unit name audit** – confirm the unit file is `certctrl.service` (matching enable/start command). Update the installer to fail if the file is missing or named differently, and add a checksum/log entry showing its path.
3. **Retry logic** – enhance `install.sh` to retry `systemctl enable` once after a reload and surface stderr if it still fails.
4. **CI coverage** – add a Rocky VM runner that executes the installer end-to-end and asserts `systemctl is-enabled certctrl` succeeds.

## Alpine

```bash
localhost:~$ curl -fsSL "https://install.lets-script.com/install.sh?force=1" | sudo bash
[INFO] Starting cert-ctrl installation...
[ERROR] Required dependency 'systemctl' is not installed.
localhost:~$ 
```