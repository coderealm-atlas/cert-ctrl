# Base agent configuration (YAML template)
auto_apply_config: true
verbose: info
interval_seconds: 300                # Single cadence; no long/short split
url_base: https://api.cjj365.cc # Base API; poll endpoint derived if poll_url is null
update_check_url: https://install.lets-script.com/api/version/check
runtime_dir: /var/lib/certctrl
events_trigger_script:
	- install.updated
	- cert.updated
	- cert.wrap_ready
	- cert.unassigned

short_poll:
	enabled: true                   # Preserve nested shape for compatibility; defaults mirror top-level
	poll_url: null                  # Optional override specific to short-polling
	idle_interval_seconds: 30
	interval_seconds: 5             # If enabled, use this cadence (same as top-level by default)
	jitter_seconds: 1               # Jitter for short-poll window
	backoff_seconds: 30             # Backoff after failures during short-poll
	fast_mode_ttl_seconds: 120
