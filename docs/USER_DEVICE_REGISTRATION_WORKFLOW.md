# User Device Registration Workflow

## Overview

This document describes the complete workflow for registering a user device using OAuth 2.0 Device Authorization Grant flow. The process involves user authentication, device authorization, token acquisition, and device registration.

## Key Distinction: Device Auth vs Device Registration

It's important to understand the relationship between **Device Authentication** and **Device Registration**:

### Device Authentication (`device_auth` table)
- **Purpose**: Temporary OAuth 2.0 authorization flow
- **Lifespan**: Short-lived (10 minutes max)
- **Function**: Allows a device to obtain access tokens
- **Database**: `device_auth` table
- **Process**: device_start → user_verify → device_poll → tokens
- **Result**: Access/refresh tokens for API calls

### Device Registration (`user_devices` table)  
- **Purpose**: Permanent device record for user
- **Lifespan**: Long-lived (until revoked)
- **Function**: Tracks and manages user's trusted devices
- **Database**: `user_devices` table
- **Process**: Uses session auth to register device info
- **Result**: Persistent device record for management

### Shared Components
Both processes share:
- **Device Fingerprinting**: Same algorithm and `device_public_id`
- **User Authentication**: Both require authenticated user
- **Security Model**: Both use cryptographic identification
- **Device Information**: Platform, model, IP, user agent

### Relationship Flow
```
1. Device Auth Flow → Temporary authorization (device_auth table)
2. Obtain Tokens → Access/refresh tokens for API calls  
3. Device Registration → Permanent device record (user_devices table)
4. Device Sessions → Link tokens to registered device (device_sessions table)
```

## Architecture Components

### Backend Services
- **bbserver**: Main authentication and API server
- **Device Auth Handler**: Manages OAuth 2.0 device flow (`/auth/device`)
- **General Auth Handler**: Handles user login (`/auth/general`)
- **Devices API**: Manages user devices (`/apiv1/users/{user_id}/devices`)

### Database Tables
- **device_auth**: Temporary OAuth 2.0 authorization requests (short-lived)
- **user_devices**: Permanent registered devices for users (long-lived)
- **device_sessions**: Links access tokens to registered devices
- **users**: User account information

### Database Relationships
```
cjj365_users (id) ←─┐
                    ├── user_devices (user_id, device_public_id)
                    │   └── device_sessions (user_device_id, refresh_token_id)
                    └── device_auth (user_id) [temporary records]
```

### Authentication Methods
- **Session-based**: For device management API calls (uses cookies)
- **Bearer Token**: For API access after device authorization
- **Device Code**: Temporary authorization during device flow

## Complete Workflow

### Relationship Between Device Auth and Device Registration

The complete device workflow involves **two separate but related processes**:

```mermaid
graph TD
    A[User Login] --> B[Device Auth Flow]
    B --> C[Temporary device_auth Record]
    C --> D[User Approval]
    D --> E[Access Tokens]
    E --> F[Device Registration]
    F --> G[Permanent user_devices Record]
    G --> H[Device Sessions]
    
    subgraph "OAuth 2.0 Device Flow"
        B
        C
        D
        E
    end
    
    subgraph "Device Management"
        F
        G
        H
    end
```

**Key Points:**
1. **Device Authentication** is temporary and OAuth-focused
2. **Device Registration** is permanent and management-focused
3. **Same device fingerprint** used in both processes
4. **Device Sessions** link OAuth tokens to registered devices
5. **Different authentication methods** (session vs bearer tokens)

### Phase 1: User Authentication

```mermaid
sequenceDiagram
    participant U as User
    participant D as Device/Script
    participant S as bbserver
    
    U->>D: Initiate device registration
    D->>S: POST /auth/general (action: login)
    S-->>D: Session cookie + user info
    Note over D: Store session cookie for device management
```

**Step 1: User Login**
- User provides credentials (email/password)
- System authenticates and creates session
- Session cookie stored for subsequent device API calls

### Phase 2: OAuth 2.0 Device Authorization Grant

```mermaid
sequenceDiagram
    participant U as User
    participant D as Device/Script
    participant S as bbserver
    
    D->>S: POST /auth/device (action: device_start)
    S-->>D: device_code, user_code, verification_uri
    
    Note over D,S: User authorization required
    U->>S: Visit verification_uri + user_code
    U->>S: Authorize device (using session)
    
    loop Polling
        D->>S: POST /auth/device (action: device_poll)
        alt Authorization pending
            S-->>D: authorization_pending
        else Authorized
            S-->>D: access_token, refresh_token
        end
    end
```

**Step 2: Device Authorization Start**
- Device initiates authorization request
- Server generates device code, user code, and verification URI
- Response format:
```json
{
  "data": {
    "device_code": "unique-device-identifier",
    "user_code": "ABCD-EFGH",
    "verification_uri": "https://domain.com/device",
    "verification_uri_complete": "https://domain.com/device?user_code=ABCD-EFGH",
    "expires_in": 600,
    "interval": 5
  }
}
```

Note: verification_uri_complete is defined by RFC 8628 (Device Authorization Grant) as an optional convenience field. It contains a browser-friendly URL with the user_code embedded as a query parameter. This allows clients to present a single clickable link (or a QR code) to users, avoiding manual code entry. Our test script reads this field into VERIFICATION_URI_COMPLETE when the server provides it; if absent, users can still visit verification_uri and enter user_code manually.

**Step 3: User Verification**
- User visits verification URI
- Enters user code to authorize device
- Uses existing session for authentication

**Step 4: Device Polling**
- Device polls for authorization status
- Continues until user authorizes or timeout
- Returns access token upon successful authorization

### Phase 3: Device Registration

```mermaid
sequenceDiagram
    participant D as Device/Script
    participant S as bbserver
    participant DB as Database
    
    D->>D: Generate device fingerprint
    D->>S: POST /apiv1/users/{user_id}/devices
    Note over D,S: Uses session authentication
    S->>DB: Insert device record
    S-->>D: Device registration confirmation
```

**Step 5: Device Registration**
- Generate unique device fingerprint
- Collect device information (platform, model, IP, etc.)
- Register device using session authentication
- Device information includes:
```json
{
  "device_public_id": "unique-fingerprint",
  "platform": "linux",
  "model": "x86_64",
  "app_version": "1.0.0",
  "name": "Test Device",
  "ip": "192.168.1.100",
  "user_agent": "DeviceApp/1.0"
}
```

### Phase 4: Device Management

**Step 6: List Registered Devices**
- Retrieve all devices for authenticated user
- Uses session authentication
- Returns device list with metadata

## Implementation Details

### Authentication Flow

1. **Session-based Authentication**
   - Used for: User login, device verification, device management
   - Cookie format: `connect.sid=s%3A...`
   - Persists across requests for device management

2. **Bearer Token Authentication**
   - Used for: API access after device authorization
   - Header format: `Authorization: Bearer eyJhbGciOiJIUzI1NiI...`
   - JWT tokens with expiration

### Device Fingerprinting

Both device auth and device registration use the same fingerprinting algorithm:
```bash
# Same fingerprint used for both processes
DEVICE_FINGERPRINT=$(echo -n "${USER_AGENT}${PLATFORM}${MODEL}$(date +%s)$(openssl rand -hex 8)" | sha256sum | cut -d' ' -f1)
DEVICE_PUBLIC_ID=$(echo "$DEVICE_FINGERPRINT" | cut -c1-8)-$(echo "$DEVICE_FINGERPRINT" | cut -c9-12)-$(echo "$DEVICE_FINGERPRINT" | cut -c13-16)-$(echo "$DEVICE_FINGERPRINT" | cut -c17-20)-$(echo "$DEVICE_FINGERPRINT" | cut -c21-32)
```

**Shared Usage:**
- **Device Auth**: Uses `device_public_id` as device identifier in OAuth flow
- **Device Registration**: Uses same `device_public_id` as permanent device identifier
- **Device Sessions**: Links OAuth tokens to registered device via `user_device_id`

### Database Table Details

#### `device_auth` Table (Temporary)
```sql
CREATE TABLE `device_auth` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `device_code_hash` varbinary(32) NOT NULL,    -- Hashed device_code for security
  `user_code` varchar(16) NOT NULL,             -- Human-readable code (ABCD-EFGH)
  `status` enum('PENDING','APPROVED','DENIED','EXPIRED','ISSUED'),
  `user_id` bigint DEFAULT NULL,                -- Set when user approves
  `scopes` text,                                -- Requested permissions
  `expires_at` datetime NOT NULL,               -- Short expiration (10 min)
  -- ... other fields
);
```

#### `user_devices` Table (Permanent)
```sql
CREATE TABLE `user_devices` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `device_public_id` char(36) NOT NULL,         -- Same fingerprint from device auth
  `device_secret_hash` varbinary(32) NOT NULL,  -- Device-specific secret
  `fp_hash` varbinary(32) DEFAULT NULL,         -- Fingerprint hash for verification
  `platform` varchar(64) DEFAULT NULL,          -- "linux", "windows", "ios", etc.
  `model` varchar(128) DEFAULT NULL,            -- Device model information
  `status` enum('ACTIVE','REVOKED','LOST'),     -- Long-term device status
  `last_seen_at` datetime,                      -- Activity tracking
  -- ... other fields
);
```

#### `device_sessions` Table (Token Linking)
```sql
CREATE TABLE `device_sessions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_device_id` bigint NOT NULL,             -- Links to user_devices.id
  `refresh_token_id` varbinary(16) DEFAULT NULL, -- Links OAuth tokens
  `started_at` datetime NOT NULL,
  `expires_at` datetime NOT NULL,
  `terminated_at` datetime DEFAULT NULL,
  -- ... other fields
);
```

### Error Handling

The workflow handles various error scenarios:

1. **Authentication Errors**
   - Invalid credentials → `401 Unauthorized`
   - Session timeout → Re-authentication required

2. **Device Authorization Errors**
   - Invalid device code → `400 Bad Request`
   - Expired authorization → `400 Bad Request`
   - User denial → `access_denied`

3. **Device Registration Errors**
   - Duplicate device → Conflict handling
   - Invalid device data → Validation errors
   - Unauthorized access → `403 Forbidden`

## API Endpoints

### Authentication Endpoints

| Endpoint | Method | Purpose | Authentication |
|----------|--------|---------|----------------|
| `/auth/general` | POST | User login | None |
| `/auth/device` | POST | Device flow operations | Session (for verify) |

### Device Management Endpoints

| Endpoint | Method | Purpose | Authentication |
|----------|--------|---------|----------------|
| `/apiv1/users/{user_id}/devices` | GET | List user devices | Session |
| `/apiv1/users/{user_id}/devices` | POST | Register device | Session |
| `/apiv1/users/{user_id}/devices/{device_id}` | DELETE | Remove device | Session |

## Security Considerations

### Device Authorization Security
- Device codes expire after 10 minutes
- User codes are single-use
- Rate limiting on polling requests
- Secure random code generation

### Device Registration Security
- Unique device fingerprinting
- IP address tracking
- User agent validation
- Session-based authorization

### Token Security
- JWT tokens with expiration
- Secure token storage recommendations
- Refresh token rotation
- Token revocation capabilities

## Testing Scripts

### Available Test Scripts

1. **`device_registration_workflow.sh`**
   - Complete end-to-end workflow testing
   - All 7 steps with error handling
   - Comprehensive logging and debugging

2. **`test_device_auth.sh`**
   - Focused device authentication testing
   - Automatic verification simulation
   - Session-based flow

3. **`quick_device_test.sh`**
   - Simple device start testing
   - Manual verification required
   - Basic flow validation

### Usage Examples

```bash
# Run complete workflow
./device_registration_workflow.sh

# Test specific device auth flow
./test_device_auth.sh

# Quick device start test
./quick_device_test.sh
```

## Current Implementation Status

### ✅ Fully Implemented
- User authentication and session management
- OAuth 2.0 Device Authorization Grant flow
- Device code generation and verification
- Token acquisition (access + refresh tokens)
- Device fingerprint generation
- Error handling and validation

### ⚠️ Partially Implemented
- Device registration API (GET works, POST endpoint exists but not fully implemented)
- Device listing with proper data structure
- Device removal functionality

### 🔄 Future Enhancements
- Device management UI
- Push notification support for device authorization
- Device trust levels and permissions
- Multi-factor authentication integration
- Device location tracking
- Automated device cleanup

## Troubleshooting

### Common Issues

1. **"Cookie not found" errors**
   - Ensure session cookie is properly stored and sent
   - Check cookie expiration and domain settings

2. **"bad_value_access" errors**
   - Verify request payload format
   - Check required fields in device auth requests

3. **Authorization timeout**
   - User must complete verification within 10 minutes
   - Check verification URI accessibility

4. **Invalid user code**
   - Ensure user code is entered correctly
   - Check code expiration status

### Debug Mode

Enable debug mode in test scripts:
```bash
export DEBUG=1
./device_registration_workflow.sh
```

This provides detailed request/response logging for troubleshooting.

## Summary: What Device Auth and Device Registration Share

### Shared Components ✅
1. **Device Fingerprinting Algorithm**: Same `device_public_id` generation
2. **Device Information**: Platform, model, IP address, user agent
3. **User Authentication**: Both require authenticated user
4. **Security Model**: Cryptographic device identification
5. **Backend Services**: Same bbserver handles both processes

### Different Purposes 🔄
1. **Temporary vs Permanent**: 
   - Device Auth: Short-lived authorization (10 minutes)
   - Device Registration: Long-lived device management (until revoked)

2. **Database Storage**:
   - Device Auth: `device_auth` table (temporary records)
   - Device Registration: `user_devices` table (permanent records)

3. **Authentication Methods**:
   - Device Auth: OAuth device codes + user verification
   - Device Registration: Session cookies + API calls

4. **End Goals**:
   - Device Auth: Obtain access tokens for API calls
   - Device Registration: Create manageable device records

### Integration Flow 🔗
```
Device Auth Success → Access Tokens → Device Registration → Device Management
     ↓                     ↓               ↓                    ↓
device_auth table → JWT tokens → user_devices table → device_sessions table
```

The workflow demonstrates a **complete device onboarding process** where OAuth 2.0 device authorization provides the security framework, and device registration provides the management framework.

## Conclusion

The user device registration workflow provides a secure, standards-compliant method for registering devices using OAuth 2.0 Device Authorization Grant. The implementation includes comprehensive error handling, security measures, and testing capabilities, making it suitable for production use with proper backend API completion.
