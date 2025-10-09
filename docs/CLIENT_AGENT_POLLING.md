# Client Agent Polling Behavior

## Overview

After successful device registration and obtaining JWT access tokens through the OAuth 2.0 Device Authorization Grant flow, the client agent enters a continuous polling mode to receive updates from the server. This document describes the polling behavior, request/response formats, and update handling mechanisms.

## Agent Execution Modes

The agent supports two primary execution modes:

### 1. Daemon Mode (Long-Running Service)

The agent runs as a systemd service with the `--keep-running` option:

```bash
cert-ctrl -c /etc/cert-ctrl --keep-running
```

**Characteristics:**
- Runs continuously in the background
- Polls server at regular intervals
- Processes updates automatically
- Managed by systemd (start/stop/restart)
- Logs to system journal or configured log files

**Systemd Service Example:**
```ini
[Unit]
Description=Certificate Control Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cert-ctrl
Group=cert-ctrl
ExecStart=/usr/local/bin/cert-ctrl -c /etc/cert-ctrl --keep-running
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

### 2. Command-Line Mode (One-Shot Operations)

Users can invoke the agent for specific operations:

```bash
# Manual certificate renewal
cert-ctrl -c /etc/cert-ctrl renew --domain example.com

# Check status
cert-ctrl -c /etc/cert-ctrl status

# List certificates
cert-ctrl -c /etc/cert-ctrl list-certs
```

**Characteristics:**
- Executes specific command and exits
- Does not interfere with daemon process
- Uses same configuration directory
- Suitable for manual operations and scripting

## Configuration Directory Structure

The agent requires a mandatory `-c` (config directory) parameter. All persistent state and configuration are stored under this directory:

```
/etc/cert-ctrl/                    # Config directory (-c parameter)
├── application.json               # Main configuration
├── httpclient_config.json         # HTTP client settings
├── ioc_config.json                # IoC container configuration
├── log_config.json                # Logging configuration
├── state/                         # Runtime state directory
│   ├── access_token.txt          # Current access token (mode 600)
│   ├── refresh_token.txt         # Refresh token (mode 600)
│   ├── device_id.txt             # Device public ID
│   ├── last_cursor.txt           # Last polling cursor
│   ├── last_poll_time.txt        # Last successful poll timestamp
│   └── pending_acks.json         # Pending acknowledgments queue
├── keys/                          # Cryptographic keys directory
│   ├── dev_pk.bin                # Device public key (mode 600)
│   ├── dev_sk.bin                # Device secret key (mode 600)
│   └── account_keys/             # CA account keys
├── certs/                         # Certificate storage
│   ├── example.com.crt
│   ├── example.com.key           # Private keys (mode 600)
│   └── chains/
└── logs/                          # Application logs (if file logging)
    ├── agent.log
    └── agent.log.1
```

**File Permissions:**
- Config directory: `700` (rwx------)
- Secret files (tokens, keys): `600` (rw-------)
- Public files (certs, config): `644` (rw-r--r--)
- Directories: `700` or `755` as appropriate

**State Persistence:**
All agent state is stored in the config directory, allowing:
- Clean restart without losing context
- Multiple agent instances with different configs
- Easy backup and migration
- Atomic updates using temp files + rename

## Prerequisites

Before entering polling mode, the client must have:

1. ✅ Completed user authentication
2. ✅ Completed OAuth 2.0 device authorization flow
3. ✅ Obtained access token (JWT) and refresh token
4. ✅ Registered device with the server
5. ✅ Stored device credentials (device_public_id, device keys)

## Authentication Context

### Access Token (JWT)
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "aud": "cjj365.cc",
  "exp": 1759471255,
  "iat": 1759470355,
  "iss": "cjj365.cc",
  "sub": "14"
}
```

**Key Claims:**
- `sub`: User ID (used for API authorization)
- `exp`: Token expiration timestamp
- `iat`: Token issued at timestamp
- `aud`: Intended audience
- `iss`: Token issuer

### Refresh Token
Opaque token format: `rt_<hash>.<random_string>`
- Used for obtaining new access tokens when expired
- Longer-lived than access token
- Stored securely on device

## Polling Architecture

### Polling Flow

```mermaid
sequenceDiagram
    participant Agent as Client Agent
    participant Server as Server API
    participant DB as Database
    
    loop Every N seconds
        Agent->>Server: POST /apiv1/client/poll
        Note over Agent,Server: Bearer: access_token
        
        alt Updates Available
            Server->>DB: Check pending updates
            DB-->>Server: Return updates
            Server-->>Agent: 200 OK + Updates
            Agent->>Agent: Process updates
        else No Updates
            Server-->>Agent: 200 OK + Empty
        else Token Expired
            Server-->>Agent: 401 Unauthorized
            Agent->>Server: POST /auth/token/refresh
            Server-->>Agent: New access token
            Agent->>Agent: Retry poll
        end
    end
```

## Polling Endpoint

### Endpoint Details

**URL:** `GET /apiv1/devices/self/updates`

**Authentication:** Bearer Token (JWT access token) containing `sub` (user_id) and `device_id` claim

**Rate Limiting:** 
- Maximum frequency: 1 request per second (burst allowed via token bucket)
- Default interval: 5 seconds recommended
- Long-poll support: Up to 30 seconds with `wait` parameter

### Request Format

#### HTTP Headers
```http
GET /apiv1/devices/self/updates?cursor=1736900000-5&limit=20&wait=0 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
If-None-Match: 1736900000-5
User-Agent: cert-ctrl/1.0
```

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `cursor` | string | No | - | Last seen cursor (opaque string); can use `If-None-Match` header instead |
| `limit` | integer | No | 20 | Max signals to return (min: 1, max: 100) |
| `wait` | integer | No | 0 | Long-poll seconds (min: 0, max: 30); 0 = immediate return |

**Note:** The `device_id` is derived from the JWT token's `device_id` claim, not from query parameters.

### Response Format

#### No Updates (204 No Content)

When no updates are available:

```http
HTTP/1.1 204 No Content
ETag: 1736900000-5
Cache-Control: no-store
```

**No response body.** The `ETag` header contains the current cursor that should be persisted.

#### Updates Available (200 OK)

```http
HTTP/1.1 200 OK
ETag: 1736900123-42
Cache-Control: no-store
Content-Type: application/json
```

```json
{
  "data": {
    "cursor": "1736900123-42",
    "signals": [
      {
        "type": "install.updated",
        "ts_ms": 1736900123421,
        "ref": {
          "config_id": 1234,
          "version": 6,
          "installs_hash_b64": "W7u5...=="
        }
      },
      {
        "type": "cert.renewed",
        "ts_ms": 1736900124500,
        "ref": {
          "cert_id": 9981,
          "serial": "04:ab:..."
        }
      }
    ]
  }
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `data.cursor` | string | Opaque cursor string (e.g., Redis Stream ID like `1736900123-42`) |
| `data.signals` | array | Array of compact update signals for this device |

#### Signal Structure

Each signal is a lightweight notification with:

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Signal type (see Signal Types below) |
| `ts_ms` | integer | Event timestamp in milliseconds since epoch |
| `ref` | object | Compact reference object with IDs/hashes (no large payloads) |

## Signal Types

Signals are compact notifications that indicate what changed. The agent fetches full resource details only when needed. Clients must gracefully ignore unknown signal types for forward compatibility.

### 1. Install Configuration Updated (`install.updated`)

Signals that the device's installation configuration has changed.

```json
{
  "type": "install.updated",
  "ts_ms": 1736900123421,
  "ref": {
    "config_id": 1234,
    "version": 6,
    "installs_hash_b64": "W7u5...=="
  }
}
```

**Reference Fields:**
- `config_id` (int64): Database ID of the install configuration
- `version` (int): Configuration version number
- `installs_hash_b64` (string, optional): Base64-encoded hash of installs BLOB

**Agent Actions:**
1. Fetch full install config via `GET /apiv1/users/{user_id}/devices/{device_id}/install-config`
2. Compare `version` or `installs_hash_b64` with local copy
3. Apply configuration changes if newer
4. Update local state files
5. Execute post-configuration commands if needed

### 2. Certificate Renewed (`cert.renewed`)

Signals that a certificate used by this device has been renewed or rotated.

```json
{
  "type": "cert.renewed",
  "ts_ms": 1736900124500,
  "ref": {
    "cert_id": 9981,
    "serial": "04:ab:..."
  }
}
```

**Reference Fields:**
- `cert_id` (int64): Database ID of the certificate
- `serial` (string, optional): Certificate serial number

**Agent Actions:**
1. Check if this certificate is in use locally
2. Fetch updated certificate material if needed
3. Update certificate files with new version
4. Reload services using the certificate
5. Verify new certificate is valid

### 3. Certificate Revoked (`cert.revoked`)

Signals that a certificate used by this device has been revoked or removed.

```json
{
  "type": "cert.revoked",
  "ts_ms": 1736900125600,
  "ref": {
    "cert_id": 9982
  }
}
```

**Reference Fields:**
- `cert_id` (int64): Database ID of the revoked certificate

**Agent Actions:**
1. Identify local usage of the certificate
2. Stop using the certificate immediately
3. Remove from active configuration
4. Wait for new certificate via install config or `cert.renewed`
5. Log the revocation event

## Error Responses

### 401 Unauthorized - Token Expired

```json
{
  "error": {
    "code": 4001,
    "what": "Access token expired",
    "key": "TOKEN_EXPIRED",
    "params": {
      "expired_at": 1759470355
    }
  }
}
```

**Agent Action:** Use refresh token to obtain new access token

### 403 Forbidden - Device Revoked

```json
{
  "error": {
    "code": 4003,
    "what": "Device has been revoked",
    "key": "DEVICE_REVOKED",
    "params": {
      "revoked_at": 1759470300,
      "reason": "Compromised device"
    }
  }
}
```

**Agent Action:** Stop polling, alert user, await re-registration

### 409 Conflict - Cursor Expired

```json
{
  "error": {
    "code": 40901,
    "what": "Cursor expired. Reset required.",
    "key": "CURSOR_EXPIRED",
    "params": {}
  }
}
```

**Agent Action:** Clear local cursor, retry without cursor to get fresh starting point

### 429 Too Many Requests - Rate Limited

```json
{
  "error": {
    "code": 4029,
    "what": "Rate limit exceeded",
    "key": "RATE_LIMITED",
    "params": {
      "retry_after": 10,
      "current_rate": "2 req/sec",
      "allowed_rate": "1 req/5sec"
    }
  }
}
```

**Agent Action:** Wait for `retry_after` seconds before next poll

### 500 Internal Server Error

```json
{
  "error": {
    "code": 5000,
    "what": "Internal server error",
    "key": "SERVER_ERROR",
    "params": {
      "request_id": "req_xyz123"
    }
  }
}
```

**Agent Action:** Honor any `Retry-After` guidance and retry after that delay (or the configured poll interval if none is provided)

### 503 Service Unavailable

```json
{
  "error": {
    "code": 5003,
    "what": "Service temporarily unavailable",
    "key": "SERVICE_UNAVAILABLE",
    "params": {
      "retry_after": 30
    }
  }
}
```

**Agent Action:** Wait and retry after indicated time

## Cursor Management

### Cursor Semantics

The polling endpoint uses an opaque cursor (e.g., Redis Stream ID like `1736900123-42`) to track the client's position in the update stream:

- **Monotonic per device**: Cursors advance forward only
- **Opaque string**: Don't parse or construct cursors; treat as black box
- **Persistence**: Always save the latest cursor from `ETag` header or `data.cursor` field
- **Resumption**: Send cursor via `If-None-Match` header or `cursor` query parameter

### Cursor Storage

Store cursor in `{config_dir}/state/last_cursor.txt`:

```bash
# Example content
1736900123-42
```

Update atomically using temp file + rename:

```cpp
void save_cursor(const std::string& cursor) {
    auto cursor_file = config_dir_ / "state" / "last_cursor.txt";
    auto temp_file = config_dir_ / "state" / ".last_cursor.txt.tmp";
    
    // Write to temp file
    std::ofstream ofs(temp_file);
    ofs << cursor;
    ofs.close();
    
    // Atomic rename
    std::filesystem::rename(temp_file, cursor_file);
}
```

### Cursor Reset

On `409 Conflict` (cursor expired):
1. Delete local cursor file
2. Retry poll without cursor
3. Server returns recent signals and fresh cursor
4. Save new cursor and continue

Optional: After reset, perform full state resync by fetching install config and comparing versions.

## Token Refresh Flow

When the access token expires (401 response), the agent must use the refresh token to obtain a new one.

### Refresh Token Request

**Endpoint:** `POST /auth/token/refresh`

**Authentication:** None (uses refresh token in body)

```http
POST /auth/token/refresh HTTP/1.1
Host: api.example.com
Content-Type: application/json
```

```json
{
  "refresh_token": "rt_271f3eca9daa6b1a317a89cac16d38b0.OEftln9mNb7HyYIwW8Qpv4oTx8IIQkg8oALzAkw2vsrR1qpjLXknbZeWOkNCBoJP",
  "device_public_id": "23229bf7-5172-02c7-59a2-76d5b4a40090"
}
```

### Refresh Token Response

```json
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 900,
    "token_type": "Bearer"
  }
}
```

**Token Storage:**
- Access token: `{config_dir}/state/access_token.txt` (mode 600)
- Refresh token: `{config_dir}/state/refresh_token.txt` (mode 600)

**Note:** Refresh token is NOT rotated (remains the same) unless explicitly revoked.

### Token Refresh Implementation

```cpp
class TokenManager {
private:
    std::filesystem::path config_dir_;
    std::string access_token_;
    std::string refresh_token_;
    std::chrono::system_clock::time_point expiry_;
    
public:
    bool is_expired() const {
        auto now = std::chrono::system_clock::now();
        // Refresh 60 seconds before actual expiry
        return now >= (expiry_ - std::chrono::seconds(60));
    }
    
    void load_tokens() {
        auto access_file = config_dir_ / "state" / "access_token.txt";
        auto refresh_file = config_dir_ / "state" / "refresh_token.txt";
        
        access_token_ = read_file(access_file);
        refresh_token_ = read_file(refresh_file);
        
        // Parse expiry from JWT
        extract_expiry_from_jwt(access_token_);
    }
    
    void update_access_token(const std::string& token, int expires_in) {
        access_token_ = token;
        expiry_ = std::chrono::system_clock::now() + 
                  std::chrono::seconds(expires_in);
        
        // Save to file
        write_file_secure(config_dir_ / "state" / "access_token.txt", token);
    }
};
```

## Polling State Machine

### Agent States

```mermaid
stateDiagram-v2
    [*] --> Initializing
    Initializing --> Polling: Token valid
    Initializing --> Refreshing: Token expired
    
    Polling --> Processing: Updates received
    Polling --> Polling: No updates
    Polling --> Refreshing: Token expired
    Polling --> Error: Network error
    
    Processing --> Acknowledging: Update processed
    Acknowledging --> Polling: Ack sent
    Acknowledging --> Error: Ack failed
    
    Refreshing --> Polling: New token obtained
    Refreshing --> Terminated: Refresh failed
    
  Error --> Polling: Retryable error
  Error --> Terminated: Fatal error
    
    Terminated --> [*]
```

### State Descriptions

| State | Description | Actions |
|-------|-------------|---------|
| `Initializing` | Agent starting up | Load config, validate tokens |
| `Polling` | Normal polling mode | Send poll request every N seconds |
| `Processing` | Processing received updates | Execute update actions |
| `Acknowledging` | Sending acknowledgments | Send ack in next poll |
| `Refreshing` | Refreshing access token | Use refresh token to get new access token |
| `Error` | Error state | Log error, determine if retryable |
| `Terminated` | Agent stopped | Clean shutdown or fatal error |

## Polling Implementation Guidelines

### 1. Poll Interval Management

The agent supports both immediate polling (`wait=0`, default) and long-polling (`wait=1-30`). Regular polling uses a fixed base interval (default 5 seconds) that operators can adjust. When the server asks the client to slow down (for example via an HTTP `Retry-After` header), the next poll waits for that server-specified delay before resuming the fixed cadence.

```cpp
class PollIntervalManager {
private:
  int base_interval_ms_ = 5000;                 // default 5 seconds
  std::optional<int> server_delay_ms_;          // one-shot delay from Retry-After

public:
  void set_base_interval_ms(int value) {
    base_interval_ms_ = std::max(value, 10);  // never sleep less than 10 ms
  }

  void apply_server_retry_after(std::optional<int> retry_after_seconds) {
    if (retry_after_seconds && *retry_after_seconds > 0) {
      server_delay_ms_ = std::max(base_interval_ms_, *retry_after_seconds * 1000);
    }
  }

  int next_delay_ms() {
    int delay = server_delay_ms_.value_or(base_interval_ms_);
    server_delay_ms_.reset();
    return delay;
  }
};
```

### 2. Token Management

```cpp
class TokenManager {
private:
    std::string access_token_;
    std::string refresh_token_;
    std::chrono::system_clock::time_point expiry_;
    
public:
    bool is_expired() const {
        return std::chrono::system_clock::now() >= expiry_;
    }
    
    void update_access_token(const std::string& token, int expires_in) {
        access_token_ = token;
        expiry_ = std::chrono::system_clock::now() + 
                  std::chrono::seconds(expires_in);
    }
};
```

### 3. Signal Queue

```cpp
class SignalQueue {
private:
    std::queue<Signal> pending_signals_;
    std::mutex mutex_;
    size_t max_queue_size_ = 1000;
    
public:
    bool enqueue(const Signal& signal) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pending_signals_.size() >= max_queue_size_) {
            return false;  // Queue full
        }
        pending_signals_.push(signal);
        return true;
    }
    
    std::optional<Signal> dequeue() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pending_signals_.empty()) {
            return std::nullopt;
        }
        auto signal = pending_signals_.front();
        pending_signals_.pop();
        return signal;
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pending_signals_.size();
    }
};
```

### 4. State Persistence

```cpp
class StatePersistence {
private:
    std::filesystem::path state_dir_;
    
public:
    StatePersistence(const std::filesystem::path& config_dir) 
        : state_dir_(config_dir / "state") {
        std::filesystem::create_directories(state_dir_);
        set_directory_permissions(state_dir_, 0700);
    }
    
    void save_cursor(const std::string& cursor) {
        write_atomic(state_dir_ / "last_cursor.txt", cursor);
    }
    
    std::optional<std::string> load_cursor() {
        return read_file_if_exists(state_dir_ / "last_cursor.txt");
    }
    
    void save_last_poll_time(int64_t timestamp) {
        write_atomic(state_dir_ / "last_poll_time.txt", 
                    std::to_string(timestamp));
    }
    
    std::optional<int64_t> load_last_poll_time() {
        auto content = read_file_if_exists(state_dir_ / "last_poll_time.txt");
        if (!content) return std::nullopt;
        return std::stoll(*content);
    }
    
private:
    void write_atomic(const std::filesystem::path& path, 
                     const std::string& content) {
        auto temp = path;
        temp += ".tmp";
        
        std::ofstream ofs(temp);
        ofs << content;
        ofs.close();
        
        std::filesystem::rename(temp, path);
        std::filesystem::permissions(path, 
            std::filesystem::perms::owner_read | 
            std::filesystem::perms::owner_write);
    }
};
```

## Best Practices

### 1. Connection Management

- **Keep-Alive:** Reuse HTTP connections for multiple polls
- **Timeout:** Set reasonable timeouts (30 seconds for immediate, 35 seconds for long-poll with wait=30)
- **Retry Logic:** Honor server-provided slow-down hints (e.g., `Retry-After`) and otherwise retry at the configured interval
- **Circuit Breaker:** Stop polling after consecutive failures (e.g., 10), alert and require manual intervention

### 2. Error Handling

- **204 Responses:** Normal case with no updates; persist ETag cursor and continue
- **Transient Errors:** Retry after any server-specified delay (network errors, 5xx) or the configured interval if none is provided
- **Authentication Errors:** Refresh token and retry once; if refresh fails, stop and alert
- **Cursor Expired (409):** Clear cursor and retry without cursor
- **Fatal Errors:** Stop polling, log, alert user (device revoked, refresh failed repeatedly)

### 3. Signal Processing

- **Unknown Types:** Gracefully ignore unknown signal types for forward compatibility
- **Idempotency:** Handle duplicate signals gracefully (compare timestamps, track processed signals)
- **Timeout:** Set maximum processing time per signal
- **Fetch-on-Demand:** Fetch full resources only when signal indicates change

### 4. Polling Strategy

- **Default Mode:** Use `wait=0` (immediate return) for simplicity and most deployments
- **Long-Poll Mode:** Use `wait=10-25` only during active rollouts or high-interest windows
- **Fixed Interval:** Keep polling on the configured cadence (default 5 s) for predictable certificate delivery windows
- **Server Slow-Down:** If the server returns `Retry-After`, pause for that duration before resuming the normal cadence
- **Reset on Activity:** On 200 response, reset to base interval (5 seconds)

### 5. Resource Management

- **Memory:** Limit signal queue size (e.g., 1000 items)
- **Disk:** Clean up old state files, rotate logs
- **CPU:** Process signals asynchronously without blocking poll loop
- **Network:** Respect rate limits (1 req/sec burst, avoid sustained high frequency)

### 6. Security

- **Token Storage:** Store tokens with mode 600 in `{config_dir}/state/`
- **Key Storage:** Store device keys with mode 600 in `{config_dir}/keys/`
- **TLS:** Always use HTTPS for polling and resource fetching
- **Validation:** Verify checksums when fetching install configs
- **File Permissions:** Enforce strict permissions on config directory (700)

## Monitoring and Debugging

### Agent Metrics to Track

- Poll request count and success rate by response code (200, 204, 401, 429, 5xx)
- Average poll latency
- Signal processing time by type
- Token refresh frequency
- Error rate by type
- Signal queue depth
- Cursor age (time since last cursor update)
- Most recent `Retry-After` delay applied (if any)

### Logging

**Essential Log Events:**
- Poll requests: cursor used, wait parameter
- Poll responses: HTTP code, signal count, new cursor
- Signal processing: type, timestamp, success/failure
- Token refresh operations
- Cursor resets (409 errors)
- All errors with full context

**Example Log Format:**
```
[2025-10-03 05:45:56] [INFO] [Poll] Request: cursor=1736900000-5, wait=0, limit=20
[2025-10-03 05:45:56] [INFO] [Poll] Response: 204 No Content, cursor=1736900000-5
[2025-10-03 05:46:01] [INFO] [Poll] Request: cursor=1736900000-5, wait=0, limit=20
[2025-10-03 05:46:01] [INFO] [Poll] Response: 200 OK, 2 signals, cursor=1736900123-42
[2025-10-03 05:46:01] [INFO] [Signal] Processing: type=install.updated, ts=1736900123421
[2025-10-03 05:46:02] [INFO] [Signal] Fetching install config: config_id=1234, version=6
[2025-10-03 05:46:03] [INFO] [Signal] Install config applied successfully
[2025-10-03 05:46:03] [INFO] [Signal] Processing: type=cert.renewed, ts=1736900124500
[2025-10-03 05:46:04] [INFO] [Signal] Certificate 9981 updated
[2025-10-03 05:46:05] [WARN] [Token] Access token expires in 60 seconds
[2025-10-03 05:46:06] [INFO] [Token] Token refresh successful, expires in 900s
[2025-10-03 05:47:01] [DEBUG] [Poll] Server requested slow-down (Retry-After=30s); deferring next poll
```

### Daemon Status Command

Provide a status command for operators:

```bash
cert-ctrl -c /etc/cert-ctrl status --daemon
```

**Output:**
```
Daemon Status: Running
Uptime: 2d 14h 32m
Last Poll: 5 seconds ago (204 No Content)
Cursor: 1736900123-42
Poll Interval: 5 seconds (base)
Next Poll In: 5 seconds
Last Retry-After: none
Queue Depth: 0 pending signals
Token Expires: 14m 23s
Last Signal: 2h 15m ago (install.updated)
```

## Future Enhancements

### 1. WebSocket Support

Replace HTTP polling with WebSocket for real-time updates:
- Lower latency
- Reduced server load
- Bidirectional communication

### 2. Delta Updates

Send only changed data instead of full updates:
- Reduced bandwidth
- Faster processing
- Version tracking

### 3. Update Batching

Server batches related updates:
- Fewer round trips
- Atomic operations
- Better consistency

### 4. Priority Queues

Multiple queues for different priority levels:
- Guaranteed critical update delivery
- Better resource allocation
- Configurable processing order

## Complete Agent Lifecycle

### 1. Initial Setup (First Run)

```bash
# Create config directory
mkdir -p /etc/cert-ctrl
chmod 700 /etc/cert-ctrl

# Create required subdirectories
mkdir -p /etc/cert-ctrl/{state,keys,certs,logs}
chmod 700 /etc/cert-ctrl/{state,keys}

# Copy configuration files
cp application.json /etc/cert-ctrl/

# Run device registration flow
cert-ctrl -c /etc/cert-ctrl register
```

### 2. Daemon Operation

```bash
# Start as systemd service
systemctl start cert-ctrl

# Or run manually in foreground
cert-ctrl -c /etc/cert-ctrl --keep-running
```

### 3. Manual Operations

```bash
# Check status while daemon runs
cert-ctrl -c /etc/cert-ctrl status

# Force immediate poll
cert-ctrl -c /etc/cert-ctrl poll-now

# List certificates
cert-ctrl -c /etc/cert-ctrl list-certs

# Manual certificate renewal
cert-ctrl -c /etc/cert-ctrl renew --domain example.com
```

## Conclusion

The client agent polling mechanism provides a lightweight, efficient way to receive update notifications from the server after device registration. By following the patterns and best practices outlined in this document, implementations can achieve:

- **Efficiency:** Minimal bandwidth via 204 responses and compact signals; fixed polling cadence keeps behavior predictable while still honoring server slow-down hints
- **Reliability:** Cursor-based resumption, robust error handling and retry logic
- **Security:** Secure token/key storage with proper file permissions
- **Scalability:** Support for large device fleets with configurable polling strategies
- **Flexibility:** Daemon mode for continuous operation, command-line mode for manual tasks

The polling system integrates seamlessly with the OAuth 2.0 device authorization flow and provides a foundation for advanced certificate management operations. The fetch-on-demand design ensures agents only download full resources when changes occur, minimizing network traffic and server load.
