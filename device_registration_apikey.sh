#!/bin/bash

# Device Registration Workflow via API Key
# -----------------------------------------
# This script illustrates how to register a device using an API key
# instead of a browser-driven device authorization flow. It mirrors
# the behaviour covered by the integration test
# `DevicesHandler_ApiKeyRegistersWithoutRegistrationCode` and borrows
# helper patterns from `device_registration_workflow_real.sh`.

set -euo pipefail

# ---- Configuration -------------------------------------------------------
SERVER_SCHEME="${SERVER_SCHEME:-https}"
SERVER_HOST="${SERVER_HOST:-test-api.cjj365.cc}"
SERVER_PORT="${SERVER_PORT:-}"
if [[ -n "${SERVER_PORT}" ]]; then
  BASE_URL="${SERVER_SCHEME}://${SERVER_HOST}:${SERVER_PORT}"
else
  BASE_URL="${SERVER_SCHEME}://${SERVER_HOST}"
fi

LOGIN_ENDPOINT="${BASE_URL}/auth/general"
APIKEY_ENDPOINT_TEMPLATE="${BASE_URL}/apiv1/users/{user_id}/apikeys"
DEVICES_ENDPOINT_TEMPLATE="${BASE_URL}/apiv1/users/{user_id}/devices"
DEVICE_LIST_ENDPOINT_TEMPLATE="${BASE_URL}/apiv1/users/{user_id}/devices"

CERT_CTRL_EMAIL="${CERT_CTRL_TEST_EMAIL:-${TEST_EMAIL:-jianglibo@hotmail.com}}"
CERT_CTRL_PASSWORD="${CERT_CTRL_TEST_PASSWORD:-${TEST_PASSWORD:-StrongPass1!}}"

API_KEY_NAME="${API_KEY_NAME:-device-apikey-$(date +%s)}"
API_KEY_PERMISSION_OBTYPE="${API_KEY_PERMISSION_OBTYPE:-ForDeviceAuthenticate}"
API_KEY_PERMISSION_OBID="${API_KEY_PERMISSION_OBID:-*}"
API_KEY_ACTIONS="${API_KEY_ACTIONS:-authenticate,validate,revoke}"
API_KEY_EXPIRES_SECONDS=${API_KEY_EXPIRES_SECONDS:-2592000} # 30 days

DEVICE_PLATFORM_OVERRIDE="${DEVICE_PLATFORM_OVERRIDE:-}"
DEVICE_MODEL_OVERRIDE="${DEVICE_MODEL_OVERRIDE:-}"
DEVICE_APP_VERSION="${DEVICE_APP_VERSION:-1.0.0}"
DEVICE_NAME_PREFIX="${DEVICE_NAME_PREFIX:-API Key Device}"
DEVICE_IP_OVERRIDE="${DEVICE_IP_OVERRIDE:-127.0.0.1}"
DEVICE_USER_AGENT="${DEVICE_USER_AGENT:-ApiKeyDeviceClient/1.0}"

VERBOSE=${VERBOSE:-0}
IFS=' ' read -r -a CURL_EXTRA_ARGS <<< "${CURL_EXTRA_OPTS:-}"

# ---- Styling ------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

print_step() {
  echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
  echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
  echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
  echo -e "${RED}✗ $1${NC}" >&2
}

print_info() {
  echo -e "${CYAN}$1${NC}"
}

print_debug() {
  if [[ "${VERBOSE}" == "1" ]]; then
    echo -e "${PURPLE}🐛 $1${NC}" >&2
  fi
}

# ---- Utilities ----------------------------------------------------------
check_dependencies() {
  local missing=0
  for bin in curl jq openssl base64; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      print_error "Required dependency '$bin' is missing"
      missing=1
    fi
  done
  if [[ $missing -ne 0 ]]; then
    exit 1
  fi
}

HTTP_STATUS=""
HTTP_BODY=""

make_request() {
  local method="$1"; shift
  local url="$1"; shift
  local data="${1:-}"; shift || true
  local -a headers
  while (($#)); do
    headers+=(-H "$1")
    shift
  done

  local response
  case "$method" in
    GET|DELETE)
      response=$(curl -sS -w '\n%{http_code}' "${CURL_EXTRA_ARGS[@]}" "${headers[@]}" "$url")
      ;;
    POST|PUT|PATCH)
      response=$(curl -sS -w '\n%{http_code}' "${CURL_EXTRA_ARGS[@]}" "${headers[@]}" -X "$method" -d "$data" "$url")
      ;;
    *)
      print_error "Unsupported HTTP method: $method"
      exit 1
      ;;
  esac

  HTTP_STATUS="${response##*$'\n'}"
  HTTP_BODY="${response%$'\n'*}"

  print_debug "HTTP ${method} ${url} -> ${HTTP_STATUS}"
  if [[ -n "$data" ]]; then
    print_debug "Request Body: ${data}"
  fi
  if [[ -n "$HTTP_BODY" ]]; then
    print_debug "Response Body: ${HTTP_BODY}"
  fi
}

extract_primary_cookie() {
  local header_file="$1"
  local raw
  raw=$(grep -i '^set-cookie:' "$header_file" | head -1 | sed 's/[\r\n]*$//') || true
  if [[ -z "$raw" ]]; then
    echo ""
    return 0
  fi
  raw=${raw#*: }
  echo "$raw" | cut -d';' -f1
}

preview_token() {
  local token="$1"
  local length=${2:-16}
  if [[ -z "$token" ]]; then
    echo "(empty)"
    return 0
  fi
  local sanitized=${token//$'\n'/}
  sanitized=${sanitized//$'\r'/}
  sanitized=${sanitized//$'\t'/}
  if (( ${#sanitized} <= length )); then
    echo "$sanitized"
  else
    echo "${sanitized:0:length}..."
  fi
}

# ---- Global State -------------------------------------------------------
SESSION_COOKIE=""
USER_ID=""
API_KEY_TOKEN=""
API_KEY_ID=""

DEVICE_PUBLIC_ID=""
DEVICE_PK_B64=""
DEVICE_NAME=""
DEVICE_PLATFORM=""
DEVICE_MODEL=""
ACCESS_TOKEN=""
REFRESH_TOKEN=""
REGISTERED_DEVICE_ID=""

# ---- Steps --------------------------------------------------------------
user_login() {
  print_step "User Login"
  print_info "Logging in as ${CERT_CTRL_EMAIL}"
  local login_payload
  login_payload=$(jq -n --arg email "$CERT_CTRL_EMAIL" --arg password "$CERT_CTRL_PASSWORD" '{action:"login", email:$email, password:$password}')

  local headers_file
  headers_file=$(mktemp)
  trap 'rm -f "$headers_file"' EXIT

  local response
  response=$(curl -sS -X POST -H 'Content-Type: application/json' -D "$headers_file" -d "$login_payload" "$LOGIN_ENDPOINT")
  HTTP_BODY="$response"

  SESSION_COOKIE=$(extract_primary_cookie "$headers_file")
  rm -f "$headers_file"
  trap - EXIT

  if [[ -z "$SESSION_COOKIE" ]]; then
    print_error "Failed to capture session cookie from login response"
    exit 1
  fi

  USER_ID=$(echo "$HTTP_BODY" | jq -r '.data.user.id // .user.id // empty')
  if [[ -z "$USER_ID" ]]; then
    print_error "Login response missing user id"
    exit 1
  fi

  print_success "Login successful (user_id=${USER_ID})"
  print_info "Session cookie captured"
}

create_api_key() {
  print_step "Create API Key"
  local actions_array
  actions_array=$(jq -n --arg csv "$API_KEY_ACTIONS" '($csv | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0)))')
  if [[ "$(echo "$actions_array" | jq 'length')" -eq 0 ]]; then
    actions_array='["authenticate"]'
  fi

  local body
  body=$(jq -n \
    --arg name "$API_KEY_NAME" \
    --arg obtype "$API_KEY_PERMISSION_OBTYPE" \
    --arg obid "$API_KEY_PERMISSION_OBID" \
    --argjson actions "$actions_array" \
    --argjson expires "$API_KEY_EXPIRES_SECONDS" \
    '{name:$name, permissions:[{obtype:$obtype, obid:$obid, actions:$actions}], expires_in_seconds:$expires}')

  local endpoint="${APIKEY_ENDPOINT_TEMPLATE/\{user_id\}/$USER_ID}"
  make_request POST "$endpoint" "$body" "Content-Type: application/json" "Cookie: $SESSION_COOKIE"

  if [[ "$HTTP_STATUS" -ge 400 ]]; then
    print_error "API key creation failed (status ${HTTP_STATUS})"
    echo "$HTTP_BODY" | jq . || echo "$HTTP_BODY"
    exit 1
  fi

  API_KEY_TOKEN=$(echo "$HTTP_BODY" | jq -r '.data.token // .token // empty')
  API_KEY_ID=$(echo "$HTTP_BODY" | jq -r '.data.id // .id // empty')

  if [[ -z "$API_KEY_TOKEN" ]]; then
    print_error "API key response missing token"
    exit 1
  fi

  print_success "API key created (id=${API_KEY_ID:-unknown})"
  print_info "Token preview: $(preview_token "$API_KEY_TOKEN" 24)"
}

generate_device_payload() {
  print_step "Prepare Device Payload"

  if command -v uuidgen >/dev/null 2>&1; then
    DEVICE_PUBLIC_ID=$(uuidgen)
  else
    DEVICE_PUBLIC_ID=$(openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
  fi

  DEVICE_PK_B64=$(openssl rand -base64 32 | tr -d '\n')
  local pk_len
  pk_len=$(echo "$DEVICE_PK_B64" | base64 --decode 2>/dev/null | wc -c | tr -d ' ')
  if [[ "$pk_len" != "32" ]]; then
    print_error "Generated device public key is not 32 bytes (decoded length ${pk_len})"
    exit 1
  fi

  DEVICE_PLATFORM=${DEVICE_PLATFORM_OVERRIDE:-$(uname -s | tr '[:upper:]' '[:lower:]')}
  DEVICE_MODEL=${DEVICE_MODEL_OVERRIDE:-$(uname -m)}
  DEVICE_NAME="${DEVICE_NAME_PREFIX} $(date +%s)"

  print_success "Device fingerprint generated"
  print_info "Device public id: ${DEVICE_PUBLIC_ID}"
  print_info "dev_pk preview: $(preview_token "$DEVICE_PK_B64" 16)"
}

register_device_with_apikey() {
  print_step "Register Device (API Key)"

  local body
  body=$(jq -n \
    --arg device_public_id "$DEVICE_PUBLIC_ID" \
    --arg dev_pk "$DEVICE_PK_B64" \
    --arg platform "$DEVICE_PLATFORM" \
    --arg model "$DEVICE_MODEL" \
    --arg app_version "$DEVICE_APP_VERSION" \
    --arg name "$DEVICE_NAME" \
    --arg ip "$DEVICE_IP_OVERRIDE" \
    --arg ua "$DEVICE_USER_AGENT" \
    '{device_public_id:$device_public_id, dev_pk:$dev_pk, platform:$platform, model:$model, app_version:$app_version, name:$name, ip:$ip, user_agent:$ua}')

  local endpoint="${DEVICES_ENDPOINT_TEMPLATE/\{user_id\}/$USER_ID}"
  make_request POST "$endpoint" "$body" "Content-Type: application/json" "Authorization: Bearer $API_KEY_TOKEN"

  if [[ "$HTTP_STATUS" -ge 400 ]]; then
    print_error "Device registration failed (status ${HTTP_STATUS})"
    echo "$HTTP_BODY" | jq . || echo "$HTTP_BODY"
    exit 1
  fi

  local error_code
  error_code=$(echo "$HTTP_BODY" | jq -r '.error.code // empty')
  if [[ -n "$error_code" && "$error_code" != "null" ]]; then
    print_error "Device registration returned error code ${error_code}"
    echo "$HTTP_BODY" | jq . || echo "$HTTP_BODY"
    exit 1
  fi

  REGISTERED_DEVICE_ID=$(echo "$HTTP_BODY" | jq -r '.data.device.id // .device.id // empty')
  ACCESS_TOKEN=$(echo "$HTTP_BODY" | jq -r '.data.session.access_token // .session.access_token // empty')
  REFRESH_TOKEN=$(echo "$HTTP_BODY" | jq -r '.data.session.refresh_token // .session.refresh_token // empty')

  if [[ -z "$REGISTERED_DEVICE_ID" ]]; then
    print_warning "Response did not include a device id"
  else
    print_success "Device registered (id=${REGISTERED_DEVICE_ID})"
  fi

  if [[ -n "$ACCESS_TOKEN" ]]; then
    print_info "Access token preview: $(preview_token "$ACCESS_TOKEN" 24)"
  fi
  if [[ -n "$REFRESH_TOKEN" ]]; then
    print_info "Refresh token preview: $(preview_token "$REFRESH_TOKEN" 24)"
  fi
}

list_devices_via_session() {
  print_step "List Devices via Session"
  if [[ -z "$SESSION_COOKIE" ]]; then
    print_warning "No session cookie available; skipping device list"
    return 0
  fi
  local endpoint="${DEVICE_LIST_ENDPOINT_TEMPLATE/\{user_id\}/$USER_ID}"
  make_request GET "$endpoint" "" "Cookie: $SESSION_COOKIE"

  if [[ "$HTTP_STATUS" -ge 400 ]]; then
    print_warning "Device listing failed (status ${HTTP_STATUS})"
    echo "$HTTP_BODY" | jq . || echo "$HTTP_BODY"
    return 0
  fi

  local device_count
  device_count=$(echo "$HTTP_BODY" | jq -r '.data | length // 0')
  print_success "Device list fetched (count=${device_count})"
  if [[ "$device_count" -gt 0 ]]; then
    echo "$HTTP_BODY" | jq -r '.data[] | "  • \(.name // "Unnamed") [\(.device_public_id // "-")]"' || true
  fi
}

print_summary() {
  echo
  echo -e "${PURPLE}Summary${NC}"
  echo "Server: ${BASE_URL}"
  echo "User ID: ${USER_ID}"
  echo "API Key ID: ${API_KEY_ID:-unknown}"
  echo "API Key Token: $(preview_token "$API_KEY_TOKEN" 32)"
  echo "Device Public ID: ${DEVICE_PUBLIC_ID}"
  if [[ -n "$REGISTERED_DEVICE_ID" ]]; then
    echo "Registered Device ID: ${REGISTERED_DEVICE_ID}"
  fi
  if [[ -n "$ACCESS_TOKEN" ]]; then
    echo "Access Token: $(preview_token "$ACCESS_TOKEN" 32)"
  fi
  if [[ -n "$REFRESH_TOKEN" ]]; then
    echo "Refresh Token: $(preview_token "$REFRESH_TOKEN" 32)"
  fi
}

usage() {
  cat <<EOF
Usage: $0 [--help]

This script logs in with user credentials, creates a scoped API key for
device authentication, and registers a device using that API key. It mimics
the behaviour of DevicesHandler_ApiKeyRegistersWithoutRegistrationCode.

Environment variables:
  SERVER_SCHEME, SERVER_HOST, SERVER_PORT   Override target API base URL
  CERT_CTRL_TEST_EMAIL / TEST_EMAIL         Login email
  CERT_CTRL_TEST_PASSWORD / TEST_PASSWORD   Login password
  API_KEY_NAME                              Name for the generated API key
  API_KEY_PERMISSION_OBTYPE                 Permission object type (default: ForDeviceAuthenticate)
  API_KEY_PERMISSION_OBID                   Permission object id (default: *)
  API_KEY_ACTIONS                           Comma list of actions (default: authenticate,validate,revoke)
  API_KEY_EXPIRES_SECONDS                   API key validity in seconds (default: 2592000)
  DEVICE_PLATFORM_OVERRIDE                  Override detected platform string
  DEVICE_MODEL_OVERRIDE                     Override detected model string
  DEVICE_APP_VERSION                        App version sent during registration
  DEVICE_NAME_PREFIX                        Prefix for generated device name
  DEVICE_IP_OVERRIDE                        IP reported to the server (default: 127.0.0.1)
  DEVICE_USER_AGENT                         User-Agent string for registration
  CURL_EXTRA_OPTS                           Extra arguments forwarded to curl
  VERBOSE                                   Set to 1 to enable debug logging

Examples:
  $0
  SERVER_HOST=api.example.com VERBOSE=1 $0
  TEST_EMAIL=user@example.test TEST_PASSWORD='StrongPass1!' $0
EOF
}

main() {
  case "${1:-}" in
    -h|--help)
      usage
      exit 0
      ;;
    "")
      ;;
    *)
      print_error "Unknown option: $1"
      usage
      exit 1
      ;;
  esac

  echo -e "${PURPLE}API Key Device Registration${NC}"
  echo "Server: ${BASE_URL}"
  echo

  check_dependencies
  user_login
  create_api_key
  generate_device_payload
  register_device_with_apikey
  list_devices_via_session
  print_summary
}

main "$@"