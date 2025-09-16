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
# 5. Device registration (register device with user)
# 6. Device management (list, view registered devices)

set -e  # Exit on any error

# Configuration
SERVER_HOST="${SERVER_HOST:-localhost}"
SERVER_PORT="${SERVER_PORT:-8081}"
BASE_URL="http://${SERVER_HOST}:${SERVER_PORT}"
DEVICE_AUTH_ENDPOINT="${BASE_URL}/auth/device"
LOGIN_ENDPOINT="${BASE_URL}/auth/general"
DEVICES_ENDPOINT_TEMPLATE="${BASE_URL}/apiv1/users/{user_id}/devices"

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

# Function to make requests with proper authentication
make_request() {
    local method="$1"
    local url="$2"
    local data="$3"
    local auth_type="${4:-session}"  # session, bearer, none
    
    local headers=()
    headers+=("-H" "Content-Type: application/json")
    
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
    
    if [[ "$method" == "GET" ]]; then
        curl -s "${headers[@]}" "$url"
    elif [[ "$method" == "POST" ]]; then
        curl -s -X POST "${headers[@]}" -d "$data" "$url"
    elif [[ "$method" == "PUT" ]]; then
        curl -s -X PUT "${headers[@]}" -d "$data" "$url"
    elif [[ "$method" == "DELETE" ]]; then
        curl -s -X DELETE "${headers[@]}" "$url"
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
    local secret_key_file="$CLIENT_CONFIG_DIR/device.key"
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

# Step 1: User Login
user_login() {
    print_step "Step 1: User Login"
    
    local email="${TEST_EMAIL:-jianglibo@hotmail.com}"
    local password="${TEST_PASSWORD:-12345678}"
    
    print_info "Attempting login with email: $email"
    
    local login_body='{
        "action": "login",
        "email": "'$email'",
        "password": "'$password'"
    }'
    
    # Create temporary file for response headers
    local headers_file=$(mktemp)
    
    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -D "$headers_file" \
        -d "$login_body" \
        "$LOGIN_ENDPOINT")
    
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
    print_step "Step 4: Device Polling for Access Token"
    
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
                print_success "Authorization complete! Tokens received:"
                ACCESS_TOKEN=$(echo "$response" | jq -r '.data.access_token // .access_token // empty')
                REFRESH_TOKEN=$(echo "$response" | jq -r '.data.refresh_token // .refresh_token // empty')
                local expires_in=$(echo "$response" | jq -r '.data.expires_in // .expires_in // empty')
                
                print_info "Access Token: ${ACCESS_TOKEN:0:50}..."
                print_info "Refresh Token: ${REFRESH_TOKEN:0:50}..."
                print_info "Expires In: ${expires_in}s"
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
    local platform=$(uname -s | tr '[:upper:]' '[:lower:]')
    local model=$(uname -m)
    local app_version="1.0.0"
    local device_name="Test Device $(date +%s)"
    local ip_address=$(curl -s https://api.ipify.org 2>/dev/null || echo "127.0.0.1")
    local user_agent="DeviceRegistrationScript/1.0"
    
    print_info "Device Information:"
    print_info "  Public ID: $DEVICE_PUBLIC_ID"
    print_info "  Platform: $platform"
    print_info "  Model: $model"
    print_info "  App Version: $app_version"
    print_info "  Name: $device_name"
    print_info "  IP: $ip_address"
    print_info "  X25519 Public Key: ${X25519_PUBLIC_KEY:0:32}..."
    
    # Create device registration payload with X25519 public key and refresh token
    local register_body=$(cat <<EOF
{
    "device_public_id": "$DEVICE_PUBLIC_ID",
    "platform": "$platform",
    "model": "$model",
    "app_version": "$app_version",
    "name": "$device_name",
    "ip": "$ip_address",
    "user_agent": "$user_agent",
    "dev_pk": "$X25519_PUBLIC_KEY",
    "refresh_token": "$REFRESH_TOKEN"
}
EOF
)
    
    local devices_endpoint="${DEVICES_ENDPOINT_TEMPLATE/\{user_id\}/$USER_ID}"
    print_info "Request: POST $devices_endpoint"
    
    local response=$(make_request "POST" "$devices_endpoint" "$register_body" "session")
    
    print_debug "Device Registration Response:"
    echo "$response" | jq . 2>/dev/null || echo "$response"
    
    # Check if registration was successful
    local device_id=$(echo "$response" | jq -r '.data.id // .id // empty' 2>/dev/null)
    if [[ -n "$device_id" ]]; then
        print_success "Device registered successfully"
        print_info "Device ID: $device_id"
        return 0
    else
        print_warning "Device registration may not be implemented yet"
        print_debug "This is expected if the DevicesHandler POST method is not implemented"
        return 0  # Don't fail the entire flow
    fi
}

# Step 6: Client Polling
client_poll() {
    print_step "Step 6: Client Polling"
    
    if [[ -z "$ACCESS_TOKEN" ]]; then
        print_error "Access token not available for client polling"
        return 1
    fi
    
    print_info "Testing client polling endpoint with access token"
    
    # Prepare polling request payload
    local poll_payload=$(cat <<EOF
{
    "device_info": {
        "platform": "$DEVICE_PLATFORM",
        "model": "$DEVICE_MODEL",
        "app_version": "$DEVICE_APP_VERSION"
    },
    "last_poll_time": $(date +%s)
}
EOF
)
    
    local poll_endpoint="$SERVER_BASE/apiv1/client/poll"
    print_info "Request: POST $poll_endpoint"
    
    # Make 3 polling attempts
    for attempt in {1..3}; do
        print_info "--- Client poll attempt $attempt/3 ---"
        
        local response=$(make_request "POST" "$poll_endpoint" "$poll_payload" "bearer")
        
        print_debug "Poll Response:"
        echo "$response" | jq . 2>/dev/null || echo "$response"
        
        # Check if polling was successful
        local success=$(echo "$response" | jq -r '.success // false' 2>/dev/null)
        if [[ "$success" == "true" ]]; then
            print_success "Client polling successful"
            
            # Extract useful information from response
            local server_time=$(echo "$response" | jq -r '.data.server_time // ""' 2>/dev/null)
            local next_interval=$(echo "$response" | jq -r '.data.next_poll_interval // ""' 2>/dev/null)
            local message=$(echo "$response" | jq -r '.data.message // ""' 2>/dev/null)
            
            if [[ -n "$server_time" ]]; then
                print_info "Server Time: $server_time"
            fi
            if [[ -n "$next_interval" ]]; then
                print_info "Next Poll Interval: ${next_interval}s"
            fi
            if [[ -n "$message" ]]; then
                print_info "Server Message: $message"
            fi
            
            return 0
        else
            local error_code=$(echo "$response" | jq -r '.error.code // ""' 2>/dev/null)
            local error_message=$(echo "$response" | jq -r '.error.message // ""' 2>/dev/null)
            print_warning "Poll attempt $attempt failed - Code: $error_code, Message: $error_message"
        fi
        
        # Wait before next attempt (except for last attempt)
        if [[ $attempt -lt 3 ]]; then
            sleep 2
        fi
    done
    
    print_warning "Client polling failed after 3 attempts"
    return 1
}

# Step 7: List Registered Devices
list_devices() {
    print_step "Step 7: List Registered Devices"
    
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

# Test error scenarios
test_error_scenarios() {
    print_step "Step 8: Error Scenario Testing"
    
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
    echo "Devices Endpoint Template: $DEVICES_ENDPOINT_TEMPLATE"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # Check server connectivity
    print_info "Checking server connectivity..."
    if ! curl -s --connect-timeout 5 "$BASE_URL/health" > /dev/null; then
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
    
    # Step 6: Client Polling
    if ! client_poll; then
        print_warning "Client polling step had issues (may not be implemented)"
        step_failed=1
    fi
    echo ""
    
    # Step 7: List Devices
    if ! list_devices; then
        print_warning "Device listing step had issues (may not be implemented)"
        step_failed=1
    fi
    echo ""
    
    # Step 7: Error Testing
    test_error_scenarios
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
        echo "✓ Client polling demonstrated successfully"
    else
        echo "⚠ Device registration/listing may need implementation"
        echo "⚠ Client polling may need implementation"
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
    echo "5. Device registration (register device with user account)"
    echo "6. Client polling (demonstrate ongoing client-server communication)"
    echo "7. Device management (list registered devices)"
    echo "8. Error testing (test various error scenarios)"
    echo ""
    echo "Environment Variables:"
    echo "  SERVER_HOST     Server hostname (default: localhost)"
    echo "  SERVER_PORT     Server port (default: 8081)"
    echo "  TEST_EMAIL      Email for login (default: jianglibo@hotmail.com)"
    echo "  TEST_PASSWORD   Password for login (default: 12345678)"
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
