# Login & Account Workflow

This document describes the unified authentication endpoints contract: primary multi‑action `POST /auth`, auxiliary `GET /auth/general?name=...` (name availability), and `GET /auth/status` (session inspection). It lists request/response bodies, state transitions, and canonical test cases.

> Source references: `apps/bbserver/include/handler_login.hpp`, `auth_base.hpp`, `user_service_mysql.cpp`, test file `gtest/login_page_handler_monad_test.cpp`.

---
## 1. Unified Endpoints
### 1.1 `POST /auth`
Multi‑action endpoint selected by the `action` field in the JSON body.

Supported actions:
- `login` – Email/password authentication
- `register` – Create a new inactive user (requires email verification)
- `activate-user` – Verify account using emailed code (returns activation_successful)
- `request-reset-password` – Initiate password reset (sends verification code)
- `reset-password` – Complete password reset with code + new password

(Additional internal / future actions may exist; clients should ignore unknown values.)

All request/response bodies are JSON. Success responses use HTTP 200 (or 204 for empty) with:
```
{ "data": { ... action-specific ... } }
```
Errors use an HTTP status (commonly 400/401/409/429/500) and body:
```
{ "error": { "code": <int>, "what": <string>, "key"?: <i18n-key>, "params"?: {...} } }
```
`code` maps to internal `my_errors` / domain codes.

### 1.2 `GET /auth/general?name=<candidate>`
Checks username availability.
Response:
```
{ "data": { "available": true|false } }
```
`400` on invalid name format.

### 1.3 `GET /auth/status`
Returns the full enriched login/session information if a valid session cookie (`cjj365`) is present. Otherwise returns HTTP 200 with an error envelope containing NOT_AN_ERROR and `alternative_body` (implementation detail) – effectively signaling “not logged in” without 401.

Success shape (fields omitted when absent):
```
{
  "data": {
    "user": {
      "id": 1,
      "name": "alice",
      "email": "alice@example.com",
      "roles": ["user"],
      "country_of_residence": "US"
    },
    "to": "",
    "amr": ["pwd"],
    "acr": "aal1",
    "auth_time": 1690001111,
    "mfa": false,
    "webauthn_platform": true,
    "credential_id": "...",
    "attestation_verified": true
  }
}
```
Note: `amr`, `acr`, `auth_time`, and WebAuthn fields DO NOT appear in the basic login response; they are exposed here after session creation.

---
## 2. Common Request Base (LoginBody)
Fields accepted (some conditional by action):
| Field | Type | Actions | Required | Notes |
|-------|------|---------|----------|-------|
| `action` | string | all | yes | One of actions above |
| `email` | string | all except name availability | yes | Valid email format required |
| `password` | string | login, register | yes (login/register) | Raw password; registration strength enforced |
| `name` | string | register | optional (auto-generated if empty, but frontend requires) |
| `country_of_residence` | string(2) | register | required (server defaults to `US` if invalid/empty) |
| `verify_code` | string | activate-user, reset-password | required for these actions |
| `new_password` | string | reset-password | required (strength rules apply) |
| `next` | string | login | optional redirect hint (currently unused server-side) |
| `remote_ip` | string | internal | server injects from request context |

Password Strength Policy (registration & reset new_password):
- Minimum 12 characters
- At least one uppercase, one lowercase, one digit, one non-alphanumeric

Username (name) Policy:
- 3–64 chars, only `[A-Za-z0-9._-]`
- Uniqueness enforced (checked by `get_user` before create) – duplicates lead to existing user path.

---
## 3. Responses
### 3.1 Login Success
Current implementation returns only a minimal structure plus a Set-Cookie header.
```
POST /auth {"action":"login","email":"u@example.com","password":"StrongPass1!"}
=> 200  (Set-Cookie: cjj365=<opaque-session-id>; Path=/; ...)
{
  "data": {
    "user": {"id": 1, "email": "u@example.com", "roles": []},
    "to": "/"
  }
}
```
Notes:
- No `session_id` field in JSON; the session identifier lives only in the cookie.
- No `amr`, `acr`, or `auth_time` fields here; they are discoverable via `GET /auth/status`.

### 3.2 Registration Success (initial)
```
POST /auth {"action":"register","email":"new@example.com","password":"StrongPass1!","name":"newuser","country_of_residence":"US"}
=> 200
{
  "data": {
    "email": "new@example.com",
    "status": "waiting_for_verification"
  }
}
```
User is created with state = `INACTIVE`.
A verification code email (or fake in test) is generated using key: `activate-user:<email>`.

### 3.3 Registration Weak Password
```
=> 400 { "error": { "code": <policy>, "what": "Password must be at least ..." } }
```

### 3.4 Activate User
```
POST /auth {"action":"activate-user","email":"new@example.com","verify_code":"123456"}
=> 200
{
  "data": {
    "email": "new@example.com",
    "status": "activation_successful"
  }
}
```
Errors: invalid or mismatched code -> 400 (currently all mapped to 400, not 401).

### 3.5 Request Reset Password
```
POST /auth {"action":"request-reset-password","email":"u@example.com"}
=> 200 {"data":{"email":"u@example.com","status":"reset_code_sent"}}
```

### 3.6 Reset Password
```
POST /auth {"action":"reset-password","email":"u@example.com","verify_code":"654321","new_password":"StrongerPass9!"}
=> 200 {"data":{"email":"u@example.com","status":"password_reset_success"}}
```
If code invalid -> error. Strength rules re-applied.

### 3.7 Error: Existing Active User During Register
If user already exists and is ACTIVE:
```
POST /auth {"action":"register",...}
=> 409 {"error": {"code": <already_exists>, "what": "User already exists"}}
```

### 3.8 Rate Limiting
Some actions (register, reset flows) invoke in-memory or Redis-based limiters. Limit exceed -> 429 with:
```
{"error": {"code": <rate_limited>, "what": "Too many requests, please try again later"}}
```

---
## 4. State Transitions
| From | Action | To | Notes |
|------|--------|----|-------|
| (none) | register | INACTIVE | Creates user with INACTIVE state, sends activation code |
| INACTIVE | activate-user (valid code) | ACTIVE | Status string: activation_successful |
| ACTIVE | request-reset-password | ACTIVE | Issues reset code (no state change) |
| ACTIVE | reset-password (valid code) | ACTIVE | Re-hashes password |

Deletion or other states (DELETED) handled elsewhere.

---
## 5. Validation & Error Codes (Representative)
| Scenario | Code (current) | HTTP | Notes |
|----------|----------------|------|-------|
| Invalid email format | INVALID_ARGUMENT | 400 | Simple format check |
| Password weak | INVALID_ARGUMENT | 400 | Policy helper result; message explains |
| Username invalid chars | INVALID_ARGUMENT | 400 | Name policy reject |
| User not found (login) | AUTH_FAILED or NOT_FOUND | 401/404 | Depends on service mapping |
| Wrong password | AUTH_FAILED | 401 | Authentication failure |
| Existing active user registers again | INVALID_ARGUMENT | 400 | Returns "User already exists" (future: consider 409 ALREADY_EXISTS) |
| Rate limited (register/ip) | RATE_LIMITED | 429 | IP-based limiter `registerLimiter` |
| Rate limited (action+email) | RATE_LIMITED | 429 | Email+action composite key limiter |
| Bad activation/reset code | INVALID_ARGUMENT | 400 | All mapped to 400 presently |

(Inspect `my_errors` enums for exact integer codes in tests.)

---
## 6. Test Matrix Guidance
| Test | Purpose | Key Assertions |
|------|---------|----------------|
| RegisterWeakPasswordRejected | Weak password triggers validation error | HTTP error; password policy message |
| RegisterStrongPasswordSucceeds | Creates INACTIVE + sends code | status = waiting_for_verification; user state INACTIVE in DB |
| ActivateUserInvalidCodeFails | Invalid code path | Error response; no state change |
| UserPassLoginSuccess | Successful auth | session created; status ok; acr/ amr present |
| UserPassLoginBadPassword | Wrong password | Error response; no session |
| NameAvailabilitySuccess (GET) | Name query parameter flow | available=true in JSON |
| Reset Flow (add) | request-reset-password + reset-password | Code issuance + password change |

Add future tests:
- Rate limiting exceeded on rapid register attempts (IP + action/email cases)
- Duplicate register after INACTIVE (should resend code) – currently yes, returns waiting_for_verification
- Activation with expired code (if TTL enforced)
- /auth/status when authenticated vs not (ensure NOT_AN_ERROR pattern for unauthenticated)

---
## 7. Example Curl Snippets
```
# Register
curl -X POST http://localhost:8080/auth \
  -H 'Content-Type: application/json' \
  -d '{"action":"register","email":"new@example.com","password":"StrongPass1!","name":"newuser","country_of_residence":"US"}'

# Login (Set-Cookie header carries session)
curl -i -X POST http://localhost:8080/auth \
  -H 'Content-Type: application/json' \
  -d '{"action":"login","email":"new@example.com","password":"StrongPass1!"}'

# Session status (after login, cookie sent automatically by curl with -b/-c if configured)
curl -X GET http://localhost:8080/auth/status
```

---
## 8. Backend Implementation Notes
- Monadic IO (`IO<T>`) ensures non-blocking MySQL + Redis operations.
- Registration sets initial state to INACTIVE (recent fix) unless explicitly overridden for admin/internal creation.
- Email codes derived from key pattern: `<action>:<email>`.
- Passwords hashed with OpenSSL helper (`hash_password_openssl`).
- `country_of_residence` is currently not forwarded in the handler's `create_user` call (only email, name, password, state). Service layer may need enhancement to persist it; update pending.
- Login response is intentionally minimal; richer auth context only exposed via `/auth/status`.

---
## 9. Open Questions / TODO
- Standardize error codes for "User already exists" (dedicated ALREADY_EXISTS?).
- Implement resend verification endpoint? (Currently implicit via re-register attempt.)
- Enforce code expiration (current doc assumes TTL but not described here).
- Add structured field for password strength feedback (currently message text only).

---
## 10. Changelog (Relevant to Tests)
| Date | Change | Impact |
|------|--------|--------|
| 2025-09-19 | Default registration state corrected to INACTIVE | Enables correct waiting_for_verification path |
| 2025-09-19 | Logging segfault fix in MySQL monad | Stability; no contract change |
| 2025-09-19 | Added `country_of_residence` to register body | Tests include field; persistence WIP |
| 2025-09-20 | Document synced with code; added /auth/status & clarified activation status | Removes outdated fields (session_id,status ok) from login example |

---
## 11. Quick Assertions for Tests
- Strong register: response.data.status == "waiting_for_verification".
- After activation (with real code): response.data.status == "activation_successful" and user.state == ACTIVE.
- Reset password: password hash changes; old password fails login; new one succeeds.
- /auth/status (logged in): includes extended auth context fields; (logged out): NOT_AN_ERROR wrapper with 200.

---
Generated to aid test authors. Keep this file updated when handler contract changes.
