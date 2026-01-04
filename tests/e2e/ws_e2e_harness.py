#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

import websockets


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _write_json(path: pathlib.Path, obj: Dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _generate_self_signed_cert(cert_path: pathlib.Path, key_path: pathlib.Path) -> None:
    # Uses openssl (expected present since the project already depends on OpenSSL).
    # Certificate is short-lived and only for local integration testing.
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-subj",
        "/CN=127.0.0.1",
        "-days",
        "1",
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class _StubHttpHandler(BaseHTTPRequestHandler):
    server_version = "certctrl-e2e-stub/1.0"

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        # Minimum endpoints to keep the default agent/poll path happy.
        if self.path.startswith("/health"):
            self._send_json(200, {"data": "ok"})
            return

        if self.path.startswith("/apiv1/devices/self/updates"):
            self._send_json(200, {"data": {"cursor": None, "signals": []}})
            return

        self._send_json(404, {"error": {"code": 404, "what": "not found"}})

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep the harness output clean.
        return


class WsHarness:
    def __init__(self) -> None:
        self.received: List[Dict[str, Any]] = []
        self._hello_ack: Optional[Dict[str, Any]] = None
        self._updates_acks: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._active_ws: Optional[websockets.ServerConnection] = None
        self._connected = asyncio.Event()

    async def handler(self, websocket: websockets.ServerConnection) -> None:
        async with self._lock:
            self._active_ws = websocket
            self._connected.set()

        await websocket.send(json.dumps({"type": "hello", "connection_id": "integration-test"}))

        try:
            async for raw in websocket:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue

                if not isinstance(msg, dict):
                    continue

                async with self._lock:
                    self.received.append(msg)
                    if msg.get("type") == "event" and msg.get("name") == "lifecycle.hello_ack":
                        self._hello_ack = msg
                    if msg.get("type") == "event" and msg.get("name") == "updates.ack":
                        self._updates_acks.append(msg)
        except websockets.exceptions.ConnectionClosed:
            # Client shutting down is expected during teardown.
            pass

        async with self._lock:
            self._active_ws = None
            self._connected.clear()

    async def wait_for_connection(self, timeout_s: float) -> None:
        await asyncio.wait_for(self._connected.wait(), timeout=timeout_s)

    async def send_event(self, event_obj: Dict[str, Any]) -> None:
        async with self._send_lock:
            async with self._lock:
                ws = self._active_ws
            if ws is None:
                raise RuntimeError("no active websocket connection")
            await ws.send(json.dumps(event_obj))

    async def wait_for_hello_ack(self, timeout_s: float) -> Dict[str, Any]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            async with self._lock:
                if self._hello_ack is not None:
                    return self._hello_ack
            await asyncio.sleep(0.05)
        raise TimeoutError("did not receive lifecycle.hello_ack")

    async def wait_for_updates_acks(self, expected_ids: List[str], timeout_s: float) -> List[Dict[str, Any]]:
        deadline = time.time() + timeout_s
        expected = set(expected_ids)
        while time.time() < deadline:
            async with self._lock:
                seen = {m.get("id") for m in self._updates_acks if isinstance(m.get("id"), str)}
                if expected.issubset(seen):
                    return list(self._updates_acks)
            await asyncio.sleep(0.05)
        raise TimeoutError(f"did not receive updates.ack for ids={expected_ids}")


def _make_test_jwt(device_id: int) -> str:
    # Minimal JWT that jwt-cpp can decode.
    # Header: {"alg":"none","typ":"JWT"}
    # Payload includes: device_id (number), exp (far future)
    import base64

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
    payload = b64url(json.dumps({"device_id": device_id, "exp": 4102444800}).encode("utf-8"))
    return f"{header}.{payload}."  # empty signature


def _write_minimal_config(config_dir: pathlib.Path, runtime_dir: pathlib.Path, http_port: int, ws_port: int) -> None:
    # application.json
    _write_json(
        config_dir / "application.json",
        {
            "auto_apply_config": False,
            "verbose": "debug",
            "events_trigger_script": ["install.updated", "cert.updated"],
            "interval_seconds": 5,
            "url_base": f"http://127.0.0.1:{http_port}",
            "update_check_url": "",
            "runtime_dir": str(runtime_dir),
            "short_poll": {
                "enabled": False,
                "poll_url": None,
                "idle_interval_seconds": 30,
                "interval_seconds": 5,
                "jitter_seconds": 1,
                "backoff_seconds": 30,
                "fast_mode_ttl_seconds": 120,
            },
        },
    )

    # log_config.json
    _write_json(
        config_dir / "log_config.json",
        {
            "level": "debug",
            "log_dir": str(runtime_dir / "logs"),
            "log_file": "certctrl-e2e",
            "rotation_size": 1048576,
        },
    )

    # httpclient_config.json
    _write_json(
        config_dir / "httpclient_config.json",
        {
            "ssl_method": "tlsv12_client",
            "threads_num": 1,
            "default_verify_path": True,
            "verify_paths": [],
            "certificates": [],
            "certificate_files": [],
        },
    )

    # ioc_config.json
    _write_json(config_dir / "ioc_config.json", {"threads_num": 1, "name": "e2e"})

    # websocket_config.json
    _write_json(
        config_dir / "websocket_config.json",
        {
            "enabled": True,
            "remote_endpoint": f"wss://127.0.0.1:{ws_port}/api/websocket",
            "webhook_base_url": "https://example.invalid/hooks",
            "verify_tls": False,
            "request_timeout_seconds": 2,
            "ws_idle_timeout_seconds": 0,
            "ping_interval_seconds": 60,
            "max_concurrent_requests": 4,
            "max_payload_bytes": 65536,
            "reconnect_initial_delay_ms": 200,
            "reconnect_max_delay_ms": 1000,
            "reconnect_jitter_ms": 50,
            "tunnel": {"local_base_url": "http://127.0.0.1:9", "header_allowlist": [], "routes": []},
        },
    )


def _seed_state(runtime_dir: pathlib.Path) -> pathlib.Path:
    state_dir = runtime_dir / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    # Seed access token in legacy file format; the client migrates it into sqlite.
    (state_dir / "access_token.txt").write_text(_make_test_jwt(1), encoding="utf-8")

    # Seed install config cache in legacy file format so no network fetch is needed.
    marker_file = state_dir / "after_update_script_events.txt"

    script_bundle = "\n".join(
        [
            "@@@BEGIN posix.sh",
            "#!/bin/sh",
            f"echo \"$1\" >> \"{marker_file}\"",
            "exit 0",
            "@@@END",
            "",
        ]
    )

    install_config = {
        "version": 1,
        "installs": [],
        "after_update_script": script_bundle,
    }
    (state_dir / "install_config.json").write_text(json.dumps(install_config), encoding="utf-8")
    (state_dir / "install_version.txt").write_text("1\n", encoding="utf-8")

    return marker_file


async def _wait_for_file_contains(path: pathlib.Path, must_contain: str, must_not_contain: str, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if path.exists():
            data = path.read_text(encoding="utf-8", errors="replace")
            if must_contain in data and (must_not_contain not in data):
                return
        await asyncio.sleep(0.05)
    raise TimeoutError(f"marker file did not reach expected content: {path}")


def _make_updates_signal(event_id: str, resume_token: str, signal_type: str) -> Dict[str, Any]:
    return {
        "type": "event",
        "name": "updates.signal",
        "id": event_id,
        "resume_token": resume_token,
        "ts_ms": int(time.time() * 1000),
        "payload": {"type": signal_type, "ts_ms": int(time.time() * 1000), "ref": {}},
    }


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="Path to cert_ctrl_debug binary")
    ap.add_argument("--timeout", type=float, default=15.0, help="Overall timeout seconds")
    args = ap.parse_args()

    client_bin = pathlib.Path(args.bin)
    if not client_bin.exists():
        raise SystemExit(f"client binary not found: {client_bin}")

    ws_port = _pick_free_port()
    http_port = _pick_free_port()

    with tempfile.TemporaryDirectory(prefix="certctrl-e2e-") as td:
        td_path = pathlib.Path(td)
        config_dir = td_path / "config"
        runtime_dir = td_path / "runtime"
        config_dir.mkdir(parents=True, exist_ok=True)
        (runtime_dir / "logs").mkdir(parents=True, exist_ok=True)

        marker_file = _seed_state(runtime_dir)
        _write_minimal_config(config_dir, runtime_dir, http_port=http_port, ws_port=ws_port)

        # Start HTTP stub
        httpd = ThreadingHTTPServer(("127.0.0.1", http_port), _StubHttpHandler)
        http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        http_thread.start()

        # Start TLS websocket server
        cert_path = td_path / "cert.pem"
        key_path = td_path / "key.pem"
        _generate_self_signed_cert(cert_path, key_path)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        harness = WsHarness()

        client_output: List[str] = []

        def _drain_client_stdout(p: subprocess.Popen[str]) -> None:
            try:
                if p.stdout is None:
                    return
                for line in p.stdout:
                    client_output.append(line.rstrip("\n"))
                    if len(client_output) > 500:
                        del client_output[:100]
            except Exception:
                return

        async with websockets.serve(
            harness.handler,
            "127.0.0.1",
            ws_port,
            ssl=ssl_ctx,
            subprotocols=[],
        ) as _server:
            # Launch client
            env = os.environ.copy()

            cmd = [
                str(client_bin),
                "--config-dirs",
                str(config_dir),
                "--profiles",
                "default",
                "--no-root",
                "--keep-running",
            ]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )

            t = threading.Thread(target=_drain_client_stdout, args=(proc,), daemon=True)
            t.start()

            try:
                await harness.wait_for_connection(timeout_s=args.timeout / 2)
                hello_ack = await harness.wait_for_hello_ack(timeout_s=args.timeout / 2)
                payload = hello_ack.get("payload")
                if not (isinstance(payload, dict) and payload.get("connection_id") == "integration-test"):
                    raise AssertionError(f"unexpected hello_ack payload: {payload}")

                # After hello, emit two realistic signals:
                #  - install.updated should be allow-listed but gated by auto_apply_config=false (script should NOT run)
                #  - cert.updated should bypass auto_apply_config (script SHOULD run)
                install_evt = _make_updates_signal("evt-install-1", "rt-1", "install.updated")
                cert_evt = _make_updates_signal("evt-cert-1", "rt-2", "cert.updated")

                await harness.send_event(install_evt)
                await harness.send_event(cert_evt)

                await harness.wait_for_updates_acks(["evt-install-1", "evt-cert-1"], timeout_s=args.timeout / 2)

                # Script should run for cert.updated even when auto_apply_config=false,
                # but must NOT run for install.updated.
                await _wait_for_file_contains(
                    marker_file,
                    must_contain="cert.updated",
                    must_not_contain="install.updated",
                    timeout_s=args.timeout / 2,
                )

                persisted = runtime_dir / "state" / "after_update_script.sh"
                if not persisted.exists():
                    raise AssertionError(f"expected persisted script missing: {persisted}")
            finally:
                # Tear down client
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                httpd.shutdown()

            if proc.returncode not in (0, None):
                tail = "\n".join(client_output[-80:])
                raise AssertionError(f"client exited with code {proc.returncode}\n--- client output tail ---\n{tail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
