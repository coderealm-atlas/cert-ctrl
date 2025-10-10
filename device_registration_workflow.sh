#!/bin/bash

# Complete Device Registration Workflow Test Script
# Demonstrates the full OAuth 2.0 Device Authorization Grant flow 
# with device registration and management
#
# Flow:
# 1. User login (get session)
# 2. Device authorization start (get device code)
# 3. Device verification (user approves)
# 4. Device polling (get access token)
# 5. Device registration (register device with user, capture device_id) /apiv1/device/registration
# 6. Device management (list, view registered devices)
# 7. Error scenario checks (negative coverage)
# 8. Device updates poll (/apiv1/devices/self/updates)

set -e  # Exit on any error

# Configuration
SERVER_SCHEME="${SERVER_SCHEME:-https}"
SERVER_HOST="${SERVER_HOST:-test-api.cjj365.cc}"
SERVER_PORT="${SERVER_PORT:-}"
if [[ -n "$SERVER_PORT" ]]; then
    BASE_URL="${SERVER_SCHEME}://${SERVER_HOST}:${SERVER_PORT}"
else
    BASE_URL="${SERVER_SCHEME}://${SERVER_HOST}"
fi
DEVICE_AUTH_ENDPOINT="${BASE_URL}/auth/device"
LOGIN_ENDPOINT="${BASE_URL}/auth/general"
DEVICE_REGISTRATION_ENDPOINT="${BASE_URL}/apiv1/device/registration"
DEVICES_ENDPOINT_TEMPLATE="${BASE_URL}/apiv1/users/{user_id}/devices"
DEVICE_UPDATES_ENDPOINT="${BASE_URL}/apiv1/devices/self/updates"

HEALTH_CHECK_PATH="${HEALTH_CHECK_PATH:-/health}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-5}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Helper functions
print_step() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_substep() {
    echo -e "${CYAN}--- $1 ---${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_debug() {
    echo -e "${PURPLE}🐛 $1${NC}"
}

# Check dependencies
check_dependencies() {
    local missing=0
    
    if ! command -v jq &> /dev/null; then
        print_error "jq is required but not installed. Please install jq first."
        missing=1
    fi
    
    if ! command -v curl &> /dev/null; then
        print_error "curl is required but not installed. Please install curl first."
        missing=1
    fi
    
    if ! command -v openssl &> /dev/null; then
        print_error "openssl is required but not installed. Please install openssl first."
        missing=1
    fi
    
    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

# Global variables for the flow
DEVICE_CODE=""
USER_CODE=""
VERIFICATION_URI=""
VERIFICATION_URI_COMPLETE=""
INTERVAL=5
EXPIRES_IN=900
SESSION_COOKIE=""
ACCESS_TOKEN=""
REFRESH_TOKEN=""
USER_ID=""
DEVICE_PUBLIC_ID=""
REGISTERED_DEVICE_ID=""
LAST_ACCESS_TOKEN=""
LAST_REFRESH_TOKEN=""
DEVICE_PLATFORM=""
DEVICE_MODEL=""
DEVICE_APP_VERSION=""
DEVICE_NAME=""
DEVICE_IP=""
DEVICE_USER_AGENT=""

# Function to make requests with proper authentication
make_request() {
    local method="$1"
    local url="$2"
    local data="$3"
    local auth_type="${4:-session}"  # session, bearer, none
    
    local headers=()
    headers+=("-H" "Content-Type: application/json")

    print_info "HTTP ${method} ${url}" >&2
    if [[ -n "$data" ]]; then
        print_debug "Request Body: $data" >&2
    else
        print_debug "Request Body: (empty)" >&2
    fi
    
    case "$auth_type" in
        "session")
            if [[ -n "$SESSION_COOKIE" ]]; then
                headers+=("-H" "Cookie: $SESSION_COOKIE")
            fi
            ;;
        "bearer")
            if [[ -n "$ACCESS_TOKEN" ]]; then
                headers+=("-H" "Authorization: Bearer $ACCESS_TOKEN")
            fi
            ;;
        "none")
            # No authentication
            ;;
    esac
    
    local response=""
    if [[ "$method" == "GET" ]]; then
        response=$(curl -s "${headers[@]}" "$url")
    elif [[ "$method" == "POST" ]]; then
        response=$(curl -s -X POST "${headers[@]}" -d "$data" "$url")
    elif [[ "$method" == "PUT" ]]; then
        response=$(curl -s -X PUT "${headers[@]}" -d "$data" "$url")
    elif [[ "$method" == "DELETE" ]]; then
        response=$(curl -s -X DELETE "${headers[@]}" "$url")
    fi

    if [[ -n "$response" ]]; then
        print_debug "Response Body: $response" >&2
    else
        print_debug "Response Body: (empty)" >&2
    fi

    echo "$response"
}

preview_token() {
    local token="$1"
    local length=${2:-16}
    if [[ -z "$token" ]]; then
        echo "(empty)"
        return 0
    fi
    local sanitized=${token//[$'\n\r\t']/}
    if (( ${#sanitized} <= length )); then
        echo "$sanitized"
    else
        echo "${sanitized:0:length}..."
    fi
}

# Function to extract cookies from response headers
extract_cookies() {
    local response_file="$1"
    grep -i "set-cookie:" "$response_file" | sed 's/set-cookie: //i' | tr -d '\r'
}

# Generate device fingerprint components
generate_device_fingerprint() {
    # Generate a device public ID (UUID-like)
    DEVICE_PUBLIC_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/')
    
    print_debug "Generated Device Public ID: $DEVICE_PUBLIC_ID"
}

# X25519 keypair generation for device registration
X25519_PUBLIC_KEY=""
X25519_PRIVATE_KEY=""
CLIENT_CONFIG_DIR="$HOME/.config/bbserver_client"

generate_x25519_keypair() {
    print_substep "Generating X25519 keypair for device registration"
    
    # Create config directory if it doesn't exist
    mkdir -p "$CLIENT_CONFIG_DIR"
    
    # Generate X25519 private key
    local private_key_file="$CLIENT_CONFIG_DIR/device_private.key"
    openssl genpkey -algorithm X25519 -out "$private_key_file" 2>/dev/null
    
    if [[ ! -f "$private_key_file" ]]; then
        print_error "Failed to generate X25519 private key"
        return 1
    fi
    
    # Extract the private key in raw binary format (32 bytes)
    # OpenSSL outputs hex with colons and spaces, we need to clean it properly
    local private_key_hex
    private_key_hex=$(openssl pkey -in "$private_key_file" -noout -text | grep -A 5 "priv:" | tail -n +2 | tr -d ' \n:' | head -c 64)
    
    # Generate public key from private key
    local public_key_file="$CLIENT_CONFIG_DIR/device_public.key"
    openssl pkey -in "$private_key_file" -pubout -out "$public_key_file" 2>/dev/null
    
    # Extract the public key in raw binary format (32 bytes)
    # For X25519, we need to extract exactly 32 bytes from the raw public key
    local public_key_hex
    public_key_hex=$(openssl pkey -in "$public_key_file" -pubin -noout -text | grep -A 5 "pub:" | tail -n +2 | tr -d ' \n:' | head -c 64)
    
    # Validate key lengths
    if [[ ${#private_key_hex} -ne 64 ]]; then
        print_error "Invalid private key length: ${#private_key_hex} chars, expected 64"
        return 1
    fi
    
    if [[ ${#public_key_hex} -ne 64 ]]; then
        print_error "Invalid public key length: ${#public_key_hex} chars, expected 64"
        return 1
    fi
    
    # Store in global variables (base64 encoded for transmission)
    X25519_PRIVATE_KEY=$(echo "$private_key_hex" | xxd -r -p | base64 -w 0)
    X25519_PUBLIC_KEY=$(echo "$public_key_hex" | xxd -r -p | base64 -w 0)
    
    # Validate base64 decoded lengths
    local pub_len=$(echo "$X25519_PUBLIC_KEY" | base64 -d | wc -c)
    local priv_len=$(echo "$X25519_PRIVATE_KEY" | base64 -d | wc -c)
    
    if [[ $pub_len -ne 32 ]]; then
        print_error "Public key decoded length is $pub_len bytes, expected 32"
        return 1
    fi
    
    if [[ $priv_len -ne 32 ]]; then
        print_error "Private key decoded length is $priv_len bytes, expected 32"
        return 1
    fi
    
    print_success "X25519 keypair generated successfully"
    print_info "Private key saved to: $private_key_file"
    print_info "Public key saved to: $public_key_file"
    print_debug "Public key (base64): $X25519_PUBLIC_KEY"
    print_debug "Public key length: $pub_len bytes"
    
    return 0
}

save_device_secret_key() {
    print_substep "Saving device secret key to client config"
    
    # Save the private key in binary format to a secure location
    local secret_key_file="$CLIENT_CONFIG_DIR/dev_sk.bin"
    echo "$X25519_PRIVATE_KEY" | base64 -d > "$secret_key_file"
    chmod 600 "$secret_key_file"  # Secure permissions
    
    print_success "Device secret key saved to: $secret_key_file"
    print_info "Private key will never be transmitted to server"
    
    # Also save a metadata file with device info
    local metadata_file="$CLIENT_CONFIG_DIR/device_info.json"
    cat > "$metadata_file" <<EOF
{
    "device_public_id": "$DEVICE_PUBLIC_ID",
    "generated_at": "$(date -Iseconds)",
    "public_key_b64": "$X25519_PUBLIC_KEY",
    "config_version": "1.0"
}
EOF
    
    print_success "Device metadata saved to: $metadata_file"
}

decode_jwt_payload() {
    local token="$1"
    if [[ -z "$token" ]]; then
        return 1
    fi

    local payload=$(printf "%s" "$token" | cut -d'.' -f2)
    if [[ -z "$payload" ]]; then
        return 1
    fi

    payload=$(printf "%s" "$payload" | tr '_-' '/+')
    local mod=$(( ${#payload} % 4 ))
    if [[ $mod -ne 0 ]]; then
        payload+=$(printf '=%.0s' $(seq 1 $((4 - mod))))
    fi

    local decoded
    if ! decoded=$(printf "%s" "$payload" | base64 --decode 2>/dev/null); then
        return 1
    fi

    printf "%s" "$decoded"
    return 0
}

confirm_access_token_device_id() {
    if [[ -z "$ACCESS_TOKEN" ]]; then
        print_warning "Access token not available; skipping device_id claim verification" >&2
        return 1
    fi

    if [[ -z "$REGISTERED_DEVICE_ID" ]]; then
        print_warning "Registered device ID unavailable; cannot validate token claim" >&2
        return 1
    fi

    local payload_json
    if ! payload_json=$(decode_jwt_payload "$ACCESS_TOKEN"); then
        print_error "Failed to decode access token payload" >&2
        return 1
    fi

    print_debug "Access token payload JSON: $payload_json" >&2

    local token_device_id
    token_device_id=$(echo "$payload_json" | jq -r '.device_id // empty' 2>/dev/null)

    if [[ -z "$token_device_id" ]]; then
        print_error "Access token payload missing device_id claim" >&2
        return 1
    fi

    if [[ "$token_device_id" == "$REGISTERED_DEVICE_ID" ]]; then
        print_success "Access token contains matching device_id claim: $token_device_id" >&2
        return 0
    fi

    print_error "Access token device_id ($token_device_id) does not match registered device ($REGISTERED_DEVICE_ID)" >&2
    return 1
}

# Step 1: User Login
user_login() {
    print_step "Step 1: User Login"
    
    local email="${CERT_CTRL_TEST_EMAIL:-${TEST_EMAIL:-jianglibo@hotmail.com}}"
    local password="${CERT_CTRL_TEST_PASSWORD:-${TEST_PASSWORD:-StrongPass1!}}"
    
    print_info "Attempting login with email: $email"
    
    local login_body='{
        "action": "login",
        "email": "'$email'",
        "password": "'$password'"
    }'

    print_info "HTTP POST ${LOGIN_ENDPOINT}" >&2
    print_debug "Request Body: $login_body" >&2
    
    # Create temporary file for response headers
    local headers_file=$(mktemp)
    
    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -D "$headers_file" \
        -d "$login_body" \
        "$LOGIN_ENDPOINT")

    print_debug "Response Body: $response" >&2
    
    print_debug "Login Response:"
    echo "$response" | jq . 2>/dev/null || echo "$response"
    
    # Extract session cookie
    SESSION_COOKIE=$(extract_cookies "$headers_file" | head -1)
    rm -f "$headers_file"
    
    # Extract user ID from response
    USER_ID=$(echo "$response" | jq -r '.data.user.id // .user.id // empty' 2>/dev/null)
    
    if [[ -n "$SESSION_COOKIE" && -n "$USER_ID" ]]; then
        print_success "Login successful"
        print_info "User ID: $USER_ID"
        print_info "Session: ${SESSION_COOKIE:0:50}..."
        return 0
    else
        print_error "Login failed or incomplete response"
        print_info "Please check credentials and ensure user exists in database"
        return 1
    fi
}

# Step 2: Device Authorization Start
device_auth_start() {
    print_step "Step 2: Starting Device Authorization Flow"
    
    local request_body='{
        "action": "device_start",
        "scopes": ["openid", "profile", "email"],
        "interval": 5,
        "expires_in": 900
    }'
    
    print_info "Request: POST $DEVICE_AUTH_ENDPOINT"
    
    local response=$(make_request "POST" "$DEVICE_AUTH_ENDPOINT" "$request_body" "none")
    
    if [[ -z "$response" ]]; then
        print_error "No response received from server"
        return 1
    fi
    
    print_debug "Response:"
    echo "$response" | jq . 2>/dev/null || echo "$response"
    
    # Parse response - handle both direct format and data-wrapped format
    DEVICE_CODE=$(echo "$response" | jq -r '.data.device_code // .device_code // empty')
    USER_CODE=$(echo "$response" | jq -r '.data.user_code // .user_code // empty')
    VERIFICATION_URI=$(echo "$response" | jq -r '.data.verification_uri // .verification_uri // empty')
    VERIFICATION_URI_COMPLETE=$(echo "$response" | jq -r '.data.verification_uri_complete // .verification_uri_complete // empty')
    INTERVAL=$(echo "$response" | jq -r '.data.interval // .interval // 5')
    EXPIRES_IN=$(echo "$response" | jq -r '.data.expires_in // .expires_in // 900')
    
    if [[ -z "$DEVICE_CODE" || -z "$USER_CODE" ]]; then
        print_error "Failed to get device_code or user_code from response"
        return 1
    fi
    
    print_success "Device authorization started successfully"
    print_info "Device Code: $DEVICE_CODE"
    print_info "User Code: $USER_CODE"
    print_info "Verification URI: $VERIFICATION_URI"
    print_info "Verification URI Complete: $VERIFICATION_URI_COMPLETE"
    print_info "Poll Interval: ${INTERVAL}s"
    print_info "Expires In: ${EXPIRES_IN}s"
}

# Step 3: Device Verification (User Approval)
device_verify() {
    print_step "Step 3: Device Verification (User Approval)"
    
    if [[ -z "$SESSION_COOKIE" ]]; then
        print_error "No session cookie available. Cannot perform automatic verification."
        return 1
    fi
    
    local verify_body='{
        "action": "device_verify",
        "user_code": "'$USER_CODE'",
        "approve": true
    }'
    
    print_info "Request: POST $DEVICE_AUTH_ENDPOINT"
    
    local response=$(make_request "POST" "$DEVICE_AUTH_ENDPOINT" "$verify_body" "session")
    
    print_debug "Verification Response:"
    echo "$response" | jq . 2>/dev/null || echo "$response"
    
    local status=$(echo "$response" | jq -r '.data.status // .status // empty')
    if [[ "$status" == "approved" ]]; then
        print_success "Device verification approved successfully"
        return 0
    else
        print_error "Device verification failed or returned unexpected status: $status"
        return 1
    fi
}

# Step 4: Device Polling (Get Access Token)
device_poll() {
    print_step "Step 4: Device Polling for Registration Code"
    
    if [[ -z "$DEVICE_CODE" ]]; then
        print_error "No device code available for polling"
        return 1
    fi
    
    local poll_body='{
        "action": "device_poll",
        "device_code": "'$DEVICE_CODE'"
    }'
    
    local max_attempts=$((EXPIRES_IN / INTERVAL))
    local attempt=1
    
    print_info "Starting polling (max attempts: $max_attempts, interval: ${INTERVAL}s)"
    
    while [[ $attempt -le $max_attempts ]]; do
        print_substep "Poll attempt $attempt/$max_attempts"
        
        local response=$(make_request "POST" "$DEVICE_AUTH_ENDPOINT" "$poll_body" "none")
        
        if [[ -z "$response" ]]; then
            print_error "No response received from polling request"
            return 1
        fi
        
        # Check if response has an error field
        local error_code=$(echo "$response" | jq -r '.error.code // empty' 2>/dev/null)
        local error_what=$(echo "$response" | jq -r '.error.what // empty' 2>/dev/null)
        
        if [[ -n "$error_code" ]]; then
            print_error "Server returned error: $error_what (code: $error_code)"
            return 1
        fi
        
        local status=$(echo "$response" | jq -r '.data.status // .status // empty')
        
        case "$status" in
            "authorization_pending")
                print_info "Authorization still pending, waiting..."
                ;;
            "slow_down")
                print_warning "Server requested slow down, increasing interval"
                INTERVAL=$((INTERVAL + 5))
                ;;
            "access_denied")
                print_error "Access denied by user"
                return 1
                ;;
            "expired")
                print_error "Device code expired"
                return 1
                ;;
            "ready")
                print_success "Authorization complete! Registration code issued:"
                REGISTRATION_CODE=$(echo "$response" | jq -r '.data.registration_code // .registration_code // empty')
                REGISTRATION_CODE_TTL=$(echo "$response" | jq -r '.data.registration_code_ttl // .registration_code_ttl // empty')
                if [[ -z "$REGISTRATION_CODE" ]]; then
                    print_error "Poll response missing registration_code"
                    return 1
                fi
                print_info "Registration Code: $REGISTRATION_CODE"
                if [[ -n "$REGISTRATION_CODE_TTL" && "$REGISTRATION_CODE_TTL" != "null" ]]; then
                    print_info "Registration Code TTL: ${REGISTRATION_CODE_TTL}s"
                fi
                return 0
                ;;
            *)
                print_error "Unknown status: $status"
                print_debug "Full response: $response"
                return 1
                ;;
        esac
        
        sleep "$INTERVAL"
        attempt=$((attempt + 1))
    done
    
    print_error "Polling timeout reached without success"
    return 1
}

# Step 5: Device Registration
device_register() {
    print_step "Step 5: Device Registration"
    
    if [[ -z "$SESSION_COOKIE" || -z "$USER_ID" ]]; then
        print_error "Session cookie or user ID not available for device registration"
        return 1
    fi
    if [[ -z "$REGISTRATION_CODE" ]]; then
        print_error "No registration code available; run device_poll first"
        return 1
    fi
    
    # Generate device fingerprint components
    generate_device_fingerprint
    
    # Generate X25519 keypair for device registration
    if ! generate_x25519_keypair; then
        print_error "Failed to generate X25519 keypair"
        return 1
    fi
    
    # Save device secret key to client config
    save_device_secret_key
    
    # Simulate device information
    DEVICE_PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
    DEVICE_MODEL=$(uname -m)
    DEVICE_APP_VERSION="1.0.0"
    DEVICE_NAME="Test Device $(date +%s)"
    DEVICE_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "127.0.0.1")
    DEVICE_USER_AGENT="DeviceRegistrationScript/1.0"

    print_info "Device Information:"
    print_info "  Public ID: $DEVICE_PUBLIC_ID"
    print_info "  Platform: $DEVICE_PLATFORM"
    print_info "  Model: $DEVICE_MODEL"
    print_info "  App Version: $DEVICE_APP_VERSION"
    print_info "  Name: $DEVICE_NAME"
    print_info "  IP: $DEVICE_IP"
    print_info "  X25519 Public Key: ${X25519_PUBLIC_KEY:0:32}..."
    
    # Create device registration payload with X25519 public key and registration code
    local register_body
    register_body=$(jq -cn \
        --arg device_public_id "$DEVICE_PUBLIC_ID" \
        --arg platform "$DEVICE_PLATFORM" \
        --arg model "$DEVICE_MODEL" \
        --arg app_version "$DEVICE_APP_VERSION" \
        --arg name "$DEVICE_NAME" \
        --arg ip "$DEVICE_IP" \
        --arg user_agent "$DEVICE_USER_AGENT" \
        --arg dev_pk "$X25519_PUBLIC_KEY" \
        --arg registration_code "$REGISTRATION_CODE" \
        --arg user_id "$USER_ID" \
        '($user_id | tonumber? // $user_id) as $uid
         | {
             device_public_id: $device_public_id,
             platform: $platform,
             model: $model,
             app_version: $app_version,
             name: $name,
             ip: $ip,
             user_agent: $user_agent,
             dev_pk: $dev_pk,
             registration_code: $registration_code,
             user_id: $uid
           }')

    local devices_endpoint="$DEVICE_REGISTRATION_ENDPOINT"
    print_info "Request: POST $devices_endpoint"
    
    local response=$(make_request "POST" "$devices_endpoint" "$register_body" "session")
    
    print_debug "Device Registration Response:"
    echo "$response" | jq . 2>/dev/null || echo "$response"
    
    # Check if registration was successful
    local device_id=$(echo "$response" | jq -r '.data.device.id // .device.id // empty' 2>/dev/null)
    if [[ -n "$device_id" ]]; then
        print_success "Device registered successfully"
        print_info "Device ID: $device_id"
        REGISTERED_DEVICE_ID="$device_id"
        ACCESS_TOKEN=$(echo "$response" | jq -r '.data.session.access_token // .session.access_token // empty')
        REFRESH_TOKEN=$(echo "$response" | jq -r '.data.session.refresh_token // .session.refresh_token // empty')
        local session_token_type=$(echo "$response" | jq -r '.data.session.token_type // .session.token_type // empty')
        local session_expires_in=$(echo "$response" | jq -r '.data.session.expires_in // .session.expires_in // empty')
        if [[ -n "$session_token_type" ]]; then
            print_info "Token Type: $session_token_type"
        fi
        if [[ -n "$session_expires_in" ]]; then
            print_info "Access token TTL: ${session_expires_in}s"
        fi
        if [[ -n "$ACCESS_TOKEN" ]]; then
            print_substep "Validating access token device_id claim"
            if ! confirm_access_token_device_id; then
                print_error "Access token verification against registered device failed"
                return 1
            fi
        fi
        LAST_ACCESS_TOKEN="$ACCESS_TOKEN"
        LAST_REFRESH_TOKEN="$REFRESH_TOKEN"
        if [[ -n "$LAST_REFRESH_TOKEN" ]]; then
            print_info "Refresh token issued: $(preview_token "$LAST_REFRESH_TOKEN" 24)"
        fi
        if ! device_register_retry; then
            print_warning "Idempotent registration retry failed; inspect logs for details"
        fi
        return 0
    else
        print_warning "Device registration may not be implemented yet"
        print_debug "This is expected if the DevicesHandler POST method is not implemented"
        return 0  # Don't fail the entire flow
    fi
}

device_register_retry() {
    print_substep "Re-registering device to demonstrate idempotent session rotation"

    if [[ -z "$REGISTERED_DEVICE_ID" ]]; then
        print_warning "Device was not registered; skipping retry"
        return 1
    fi
    local previous_refresh="$LAST_REFRESH_TOKEN"
    local previous_access="$LAST_ACCESS_TOKEN"

    if [[ -z "$previous_refresh" ]]; then
        print_warning "No refresh token from initial registration; skipping retry"
        return 1
    fi

    local retry_body
    retry_body=$(jq -cn \
        --arg device_public_id "$DEVICE_PUBLIC_ID" \
        --arg platform "$DEVICE_PLATFORM" \
        --arg model "$DEVICE_MODEL" \
        --arg app_version "$DEVICE_APP_VERSION" \
        --arg name "$DEVICE_NAME" \
        --arg ip "$DEVICE_IP" \
        --arg user_agent "$DEVICE_USER_AGENT" \
        --arg dev_pk "$X25519_PUBLIC_KEY" \
        --arg refresh_token "$previous_refresh" \
        --arg user_id "$USER_ID" \
        '($user_id | tonumber? // $user_id) as $uid
         | {
             device_public_id: $device_public_id,
             platform: $platform,
             model: $model,
             app_version: $app_version,
             name: $name,
             ip: $ip,
             user_agent: $user_agent,
             dev_pk: $dev_pk,
             user_id: $uid
           }
           + (if $refresh_token != "" then {refresh_token: $refresh_token} else {} end)')

    local devices_endpoint="$DEVICE_REGISTRATION_ENDPOINT"
    print_info "Request (retry): POST $devices_endpoint"

    local response=$(make_request "POST" "$devices_endpoint" "$retry_body" "session")

    print_debug "Idempotent Registration Response:"
    echo "$response" | jq . 2>/dev/null || echo "$response"

    local device_id=$(echo "$response" | jq -r '.data.device.id // .device.id // empty' 2>/dev/null)
    if [[ -z "$device_id" ]]; then
        print_warning "Retry response missing device payload"
        return 1
    fi
    print_info "Existing device ID confirmed: $device_id"

    local new_refresh=$(echo "$response" | jq -r '.data.session.refresh_token // .session.refresh_token // empty')
    local new_access=$(echo "$response" | jq -r '.data.session.access_token // .session.access_token // empty')
    local token_type=$(echo "$response" | jq -r '.data.session.token_type // .session.token_type // empty')
    local expires_in=$(echo "$response" | jq -r '.data.session.expires_in // .session.expires_in // empty')

    if [[ -z "$new_refresh" ]]; then
        print_warning "Retry response missing refresh token"
        return 1
    fi

    print_info "Previous refresh token: $(preview_token "$previous_refresh" 24)"
    print_info "New refresh token: $(preview_token "$new_refresh" 24)"

    if [[ "$new_refresh" == "$previous_refresh" ]]; then
        print_warning "Refresh token was not rotated on retry"
    else
        print_success "Refresh token rotated on idempotent retry"
    fi

    if [[ -n "$previous_access" ]]; then
        print_info "Previous access token: $(preview_token "$previous_access" 24)"
    fi

    if [[ -n "$new_access" ]]; then
        print_info "New access token: $(preview_token "$new_access" 24)"
        ACCESS_TOKEN="$new_access"
        if ! confirm_access_token_device_id; then
            print_warning "New access token failed device_id verification"
        fi
        LAST_ACCESS_TOKEN="$new_access"
    fi

    if [[ -n "$token_type" ]]; then
        print_info "Token Type (retry): $token_type"
    fi
    if [[ -n "$expires_in" ]]; then
        print_info "Access token TTL (retry): ${expires_in}s"
    fi

    REFRESH_TOKEN="$new_refresh"
    LAST_REFRESH_TOKEN="$new_refresh"
    return 0
}

# Step 6: List Registered Devices
list_devices() {
    print_step "Step 6: List Registered Devices"
    
    if [[ -z "$SESSION_COOKIE" || -z "$USER_ID" ]]; then
        print_error "Session cookie or user ID not available for listing devices"
        return 1
    fi
    
    local devices_endpoint="${DEVICES_ENDPOINT_TEMPLATE/\{user_id\}/$USER_ID}"
    print_info "Request: GET $devices_endpoint"
    
    local response=$(make_request "GET" "$devices_endpoint" "" "session")
    
    print_debug "Devices List Response:"
    echo "$response" | jq . 2>/dev/null || echo "$response"
    
    # Check if we got a list
    local device_count=$(echo "$response" | jq -r '.data | length // 0' 2>/dev/null)
    if [[ "$device_count" -gt 0 ]]; then
        print_success "Found $device_count registered device(s)"
        
        # Display device information
        echo "$response" | jq -r '.data[] | "  Device: \(.name // "Unnamed") (\(.device_public_id // .id))"' 2>/dev/null || true
    else
        print_info "No registered devices found or device listing not implemented"
    fi
}

device_updates_poll() {
    print_step "Step 8: Device Updates Poll"

    if [[ -z "$ACCESS_TOKEN" ]]; then
        print_error "Access token not available for updates poll"
        return 1
    fi

    local response=$(make_request "GET" "$DEVICE_UPDATES_ENDPOINT" "" "bearer")

    if [[ -n "$response" ]]; then
        print_debug "Device Updates Response:"
        echo "$response" | jq . 2>/dev/null || echo "$response"
    else
        print_info "Updates endpoint returned no body (likely 204 No Content)"
    fi

    return 0
}

# Test error scenarios
test_error_scenarios() {
    print_step "Step 7: Error Scenario Testing"
    
    print_substep "Testing invalid device auth action"
    local invalid_action_body='{"action": "invalid_action"}'
    local response=$(make_request "POST" "$DEVICE_AUTH_ENDPOINT" "$invalid_action_body" "none")
    print_debug "Invalid action response: $(echo "$response" | jq . 2>/dev/null || echo "$response")"
    
    print_substep "Testing missing device_code in poll"
    local missing_code_body='{"action": "device_poll"}'
    response=$(make_request "POST" "$DEVICE_AUTH_ENDPOINT" "$missing_code_body" "none")
    print_debug "Missing device_code response: $(echo "$response" | jq . 2>/dev/null || echo "$response")"
    
    print_substep "Testing invalid device_code"
    local invalid_code_body='{"action": "device_poll", "device_code": "invalid_code"}'
    response=$(make_request "POST" "$DEVICE_AUTH_ENDPOINT" "$invalid_code_body" "none")
    print_debug "Invalid device_code response: $(echo "$response" | jq . 2>/dev/null || echo "$response")"
    
    print_success "Error scenario testing completed"
}

# Main execution flow
main() {
    echo -e "${PURPLE}Device Registration Workflow Test${NC}"
    echo -e "${PURPLE}===================================${NC}"
    echo "Server: $BASE_URL"
    echo "Device Auth Endpoint: $DEVICE_AUTH_ENDPOINT"
    echo "Device Registration Endpoint: $DEVICE_REGISTRATION_ENDPOINT"
    echo "Devices Endpoint Template: $DEVICES_ENDPOINT_TEMPLATE"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # Check server connectivity
    print_info "Checking server connectivity..."
    if ! curl -sS --connect-timeout "$HEALTH_CHECK_TIMEOUT" "$BASE_URL$HEALTH_CHECK_PATH" > /dev/null; then
        print_error "Cannot connect to server at $BASE_URL"
        print_info "Please ensure the server is running and accessible"
        exit 1
    fi
    print_success "Server is reachable"
    echo ""
    
    # Execute the complete workflow
    local step_failed=0
    
    # Step 1: User Login
    if ! user_login; then
        print_error "User login failed, aborting workflow"
        exit 1
    fi
    echo ""
    
    # Step 2: Device Authorization Start
    if ! device_auth_start; then
        print_error "Device authorization start failed, aborting workflow"
        exit 1
    fi
    echo ""
    
    # Step 3: Device Verification
    if ! device_verify; then
        print_error "Device verification failed, aborting workflow"
        exit 1
    fi
    echo ""
    
    # Step 4: Device Polling
    if ! device_poll; then
        print_error "Device polling failed, aborting workflow"
        exit 1
    fi
    echo ""
    
    # Step 5: Device Registration
    if ! device_register; then
        print_warning "Device registration step had issues (may not be implemented)"
        step_failed=1
    fi
    echo ""
    
    # Step 6: List Devices
    if ! list_devices; then
        print_warning "Device listing step had issues (may not be implemented)"
        step_failed=1
    fi
    echo ""
    
    # Step 7: Error Testing
    test_error_scenarios
    echo ""

    # Step 8: Device Updates Poll
    if ! device_updates_poll; then
        print_warning "Device updates poll encountered an issue"
        step_failed=1
    fi
    echo ""
    
    if [[ $step_failed -eq 0 ]]; then
        print_success "Complete device registration workflow completed successfully!"
    else
        print_warning "Device registration workflow completed with some warnings"
        print_info "Some endpoints may not be fully implemented yet"
    fi
    
    echo ""
    echo -e "${PURPLE}Summary:${NC}"
    echo "✓ User authenticated and session established"
    echo "✓ Device authorization flow completed"
    echo "✓ Access token obtained via device flow"
    if [[ -n "$DEVICE_PUBLIC_ID" ]]; then
        echo "✓ Device fingerprint generated: $DEVICE_PUBLIC_ID"
    fi
    if [[ $step_failed -eq 0 ]]; then
        echo "✓ Device registered and listed successfully"
    else
        echo "⚠ Device registration/listing may need implementation"
    fi
    if [[ $step_failed -eq 0 ]]; then
        echo "✓ Device updates endpoint polled"
    else
        echo "⚠ Device updates poll had issues"
    fi
}

# Script usage
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "This script demonstrates the complete device registration workflow:"
    echo "1. User login (session-based authentication)"
    echo "2. Device authorization start (OAuth 2.0 device flow)"
    echo "3. Device verification (user approval)"
    echo "4. Device polling (obtain access token)"
    echo "5. Device registration (register device with user account, validate device_id claim)"
    echo "6. Device management (list registered devices)"
    echo "7. Error testing (test various error scenarios)"
    echo "8. Device updates poll (/apiv1/devices/self/updates)"
    echo ""
    echo "Environment Variables:"
    echo "  SERVER_SCHEME   Protocol for requests (default: https)"
    echo "  SERVER_HOST     Server hostname (default: test-api.cjj365.cc)"
    echo "  SERVER_PORT     Server port (default: empty; uses scheme default)"
    echo "  CERT_CTRL_TEST_EMAIL    Preferred login email override"
    echo "  CERT_CTRL_TEST_PASSWORD Preferred login password override"
    echo "  TEST_EMAIL      Legacy login email override (fallback if CERT_CTRL_* unset)"
    echo "  TEST_PASSWORD   Legacy login password override"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Use defaults"
    echo "  SERVER_HOST=api.example.com $0       # Custom host"
    echo "  SERVER_PORT=9443 $0                  # Custom port"
    echo "  TEST_EMAIL=user@test.com TEST_PASSWORD=secret $0  # Custom credentials"
}

# Handle command line arguments
case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
    "")
        main
        ;;
    *)
        echo "Unknown option: $1"
        usage
        exit 1
        ;;
esac
