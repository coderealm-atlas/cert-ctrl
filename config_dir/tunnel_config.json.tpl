{
    "enabled": false,
    "remote_endpoint": "wss://api.cjj365.cc/api/tunnel",
    "webhook_base_url": "https://hook.cjj365.cc/hooks",
    "local_base_url": "http://127.0.0.1:9000",
    "verify_tls": true,
    "request_timeout_seconds": 45,
    "ping_interval_seconds": 20,
    "max_concurrent_requests": 12,
    "max_payload_bytes": 5242880,
    "reconnect_initial_delay_ms": 1000,
    "reconnect_max_delay_ms": 30000,
    "reconnect_jitter_ms": 250,
    "header_allowlist": [
        "content-type",
        "user-agent",
        "stripe-signature"
    ]
}
