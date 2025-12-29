{
    "enabled": true,
    "remote_endpoint": "wss://api.cjj365.cc/api/websocket",
    "webhook_base_url": "https://api.cjj365.cc/hooks",
    "verify_tls": true,
    "request_timeout_seconds": 45,
    "ws_idle_timeout_seconds": 0,
    "ping_interval_seconds": 20,
    "max_concurrent_requests": 12,
    "max_payload_bytes": 5242880,
    "reconnect_initial_delay_ms": 1000,
    "reconnect_max_delay_ms": 30000,
    "reconnect_jitter_ms": 250,
    "tunnel": {
        "local_base_url": "http://127.0.0.1:9000",
        "header_allowlist": [
            "content-type",
            "user-agent",
            "stripe-signature"
        ],
        "routes": []
    }
}
