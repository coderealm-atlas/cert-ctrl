#!/usr/bin/env bash
set -euo pipefail

# Capture a fresh device certificate bundle and preserve all artifacts for backend inspection.
# The script performs the complete device authorization flow, registers a device, fetches the
# install configuration, downloads referenced certificate/CA bundles, and stores:
#   - Device key material (X25519 key pair)
#   - Raw API responses (login, device auth, registration, updates)
#   - Install configuration snapshot
#   - Certificate bundle payloads and quick integrity analysis
# Output is written to an isolated run directory so the backend team can reproduce and examine
# mismatches such as AES-GCM authentication failures.

#############################################
# Logging helpers
#############################################

ts() { date -Iseconds; }
log_info() { echo "[$(ts)] INFO  $*" >&2; }
log_warn() { echo "[$(ts)] WARN  $*" >&2; }
log_error() { echo "[$(ts)] ERROR $*" >&2; }
fail() {
  log_error "$*"
  exit 1
}

#############################################
# Configuration
#############################################

SERVER_SCHEME=${SERVER_SCHEME:-https}
SERVER_HOST=${SERVER_HOST:-api.cjj365.cc}
SERVER_PORT=${SERVER_PORT:-}
if [[ -n "${SERVER_PORT}" ]]; then
  BASE_URL="${SERVER_SCHEME}://${SERVER_HOST}:${SERVER_PORT}"
else
  BASE_URL="${SERVER_SCHEME}://${SERVER_HOST}"
fi

DEVICE_AUTH_ENDPOINT="${BASE_URL}/auth/device"
LOGIN_ENDPOINT="${BASE_URL}/auth/general"
INSTALL_CONFIG_ENDPOINT="${BASE_URL}/apiv1/devices/self/install-config"
DEVICE_UPDATES_ENDPOINT="${BASE_URL}/apiv1/devices/self/updates"

OUTPUT_ROOT=${OUTPUT_ROOT:-"bundle_captures"}
RUN_LABEL=""
PRINT_HELP=false

usage() {
  cat <<'USAGE'
Usage: capture_device_bundle.sh [--output-root DIR] [--label NAME]

Environment variables:
  SERVER_SCHEME, SERVER_HOST, SERVER_PORT   API location (defaults: https://api.cjj365.cc)
  CERT_CTRL_TEST_EMAIL / TEST_EMAIL         Login email (defaults to jianglibo@hotmail.com)
  CERT_CTRL_TEST_PASSWORD / TEST_PASSWORD   Login password (defaults to StrongPass1!)

The script creates a timestamped run directory under --output-root. All generated key material,
API responses, and bundles are stored for offline analysis.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-root)
      [[ $# -lt 2 ]] && fail "--output-root requires a value"
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --label)
      [[ $# -lt 2 ]] && fail "--label requires a value"
      RUN_LABEL="$2"
      shift 2
      ;;
    -h|--help)
      PRINT_HELP=true
      shift
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

if [[ "$PRINT_HELP" == "true" ]]; then
  usage
  exit 0
fi

#############################################
# Dependency checks & temp setup
#############################################

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "Missing dependency: $1"
  fi
}

for bin in jq curl openssl python3 xxd; do
  require_cmd "$bin"
done

RUN_ID=$(date +%Y%m%d-%H%M%S)
if [[ -n "$RUN_LABEL" ]]; then
  RUN_DIR="${OUTPUT_ROOT}/${RUN_ID}-${RUN_LABEL}"
else
  RUN_DIR="${OUTPUT_ROOT}/${RUN_ID}"
fi
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
mkdir -p "$RUN_DIR" "$RUN_DIR/device" "$RUN_DIR/responses" "$RUN_DIR/state"
mkdir -p "$RUN_DIR/device/keys" "$RUN_DIR/resources" "$RUN_DIR/updates"

log_info "Artifacts will be stored under: $RUN_DIR"

#############################################
# Global state for workflow
#############################################

SESSION_COOKIE=""
USER_ID=""
DEVICE_CODE=""
USER_CODE=""
VERIFICATION_URI=""
VERIFICATION_URI_COMPLETE=""
POLL_INTERVAL=5
POLL_EXPIRES=900
REGISTRATION_CODE=""
DEVICE_PUBLIC_ID=""
X25519_PRIVATE_KEY_B64=""
X25519_PUBLIC_KEY_B64=""
ACCESS_TOKEN=""
REFRESH_TOKEN=""
REGISTERED_DEVICE_ID=""
CURSOR=""
CA_ID=""
CA_NAME=""
ACME_ACCOUNT_ID=""
CERT_ID=""
CERT_DOMAIN=""
INSTALL_SUFFIX=""

#############################################
# Helper utilities
#############################################

store_response() {
  local name="$1" body_file="$2" headers_file="$3"
  local dst_body="$RUN_DIR/responses/${name}.json"
  cp "$body_file" "$dst_body"
  if [[ -n "$headers_file" && -f "$headers_file" ]]; then
    cp "$headers_file" "$RUN_DIR/responses/${name}.headers"
  fi
}

http_post_json() {
  local url="$1" payload="$2" auth_mode="$3" name="$4"
  local body_file="$TMP_DIR/${name}.body"
  local headers_file="$TMP_DIR/${name}.headers"
  local args=(-sS -X POST -H "Content-Type: application/json" -D "$headers_file" -o "$body_file" -w '%{http_code}' "$url")
  case "$auth_mode" in
    session)
      [[ -z "$SESSION_COOKIE" ]] && fail "Session cookie not set before $name"
      args+=(-H "Cookie: $SESSION_COOKIE")
      ;;
    bearer)
      [[ -z "$ACCESS_TOKEN" ]] && fail "Access token not available before $name"
      args+=(-H "Authorization: Bearer $ACCESS_TOKEN")
      ;;
    none) ;;
    *) fail "Unknown auth mode: $auth_mode" ;;
  esac

  local status
  status=$(curl "${args[@]}" --data "$payload")

  store_response "$name" "$body_file" "$headers_file"

  if [[ "$status" != "200" && "$status" != "201" && "$status" != "202" && "$status" != "204" ]]; then
    log_error "HTTP $status for $name"
    if [[ -s "$body_file" ]]; then
      log_error "Response: $(cat "$body_file")"
    fi
    exit 1
  fi

  cat "$body_file"
}

http_get_json() {
  local url="$1" auth_mode="$2" name="$3"
  local body_file="$TMP_DIR/${name}.body"
  local headers_file="$TMP_DIR/${name}.headers"
  local args=(-sS -X GET -D "$headers_file" -o "$body_file" -w '%{http_code}' "$url")
  case "$auth_mode" in
    session)
      [[ -z "$SESSION_COOKIE" ]] && fail "Session cookie not set before $name"
      args+=(-H "Cookie: $SESSION_COOKIE")
      ;;
    bearer)
      [[ -z "$ACCESS_TOKEN" ]] && fail "Access token not available before $name"
      args+=(-H "Authorization: Bearer $ACCESS_TOKEN")
      ;;
    none) ;;
    *) fail "Unknown auth mode: $auth_mode" ;;
  esac

  local status
  status=$(curl "${args[@]}")

  store_response "$name" "$body_file" "$headers_file"

  echo "$status"
}

http_put_json() {
  local url="$1" payload="$2" auth_mode="$3" name="$4"
  local body_file="$TMP_DIR/${name}.body"
  local headers_file="$TMP_DIR/${name}.headers"
  local args=(-sS -X PUT -H "Content-Type: application/json" -D "$headers_file" -o "$body_file" -w '%{http_code}' "$url")
  case "$auth_mode" in
    session)
      [[ -z "$SESSION_COOKIE" ]] && fail "Session cookie not set before $name"
      args+=(-H "Cookie: $SESSION_COOKIE")
      ;;
    bearer)
      [[ -z "$ACCESS_TOKEN" ]] && fail "Access token not available before $name"
      args+=(-H "Authorization: Bearer $ACCESS_TOKEN")
      ;;
    none) ;;
    *) fail "Unknown auth mode: $auth_mode" ;;
  esac

  local status
  status=$(curl "${args[@]}" --data "$payload")

  store_response "$name" "$body_file" "$headers_file"

  if [[ "$status" != "200" && "$status" != "201" && "$status" != "202" && "$status" != "204" ]]; then
    log_error "HTTP $status for $name"
    if [[ -s "$body_file" ]]; then
      log_error "Response: $(cat "$body_file")"
    fi
    exit 1
  fi

  cat "$body_file"
}

write_json() {
  local path="$1" json_payload="$2"
  printf '%s' "$json_payload" | jq '.' > "$path"
}

generate_suffix() {
  local rand_hex
  rand_hex=$(openssl rand -hex 4 2>/dev/null)
  if [[ -z "$rand_hex" ]]; then
    rand_hex=$(dd if=/dev/urandom bs=2 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
  fi
  printf '%s-%s' "$(date +%Y%m%d%H%M%S)" "$rand_hex"
}

#############################################
# Workflow steps
#############################################

step_login() {
  log_info "Logging in user"
  local email="${CERT_CTRL_TEST_EMAIL:-${TEST_EMAIL:-jianglibo@hotmail.com}}"
  local password="${CERT_CTRL_TEST_PASSWORD:-${TEST_PASSWORD:-StrongPass1!}}"
  local payload
  payload=$(jq -n --arg email "$email" --arg password "$password" '{action:"login",email:$email,password:$password}')

  local body_file="$TMP_DIR/login.body"
  local headers_file="$TMP_DIR/login.headers"
  local status
  status=$(curl -sS -X POST -H "Content-Type: application/json" -D "$headers_file" -o "$body_file" -w '%{http_code}' --data "$payload" "$LOGIN_ENDPOINT")
  store_response "login" "$body_file" "$headers_file"
  if [[ "$status" != "200" ]]; then
    fail "Login failed with status $status: $(cat "$body_file")"
  fi

  SESSION_COOKIE=$(grep -i '^set-cookie:' "$headers_file" | head -n1 | sed -E 's/[Ss]et-[Cc]ookie: ([^;]+).*/\1/' || true)
  [[ -z "$SESSION_COOKIE" ]] && fail "Session cookie missing in login response"

  USER_ID=$(jq -r '.data.user.id // .user.id // empty' "$body_file")
  [[ -z "$USER_ID" || "$USER_ID" == "null" ]] && fail "User ID missing in login response"

  log_info "Login succeeded for user_id=$USER_ID"
}

step_device_start() {
  log_info "Starting device authorization flow"
  local payload
  payload=$(jq -n '{action:"device_start",scopes:["openid","profile","email"],interval:5,expires_in:900}')
  local body
  body=$(http_post_json "$DEVICE_AUTH_ENDPOINT" "$payload" none "device_start")

  DEVICE_CODE=$(echo "$body" | jq -r '.data.device_code // .device_code // empty')
  USER_CODE=$(echo "$body" | jq -r '.data.user_code // .user_code // empty')
  VERIFICATION_URI=$(echo "$body" | jq -r '.data.verification_uri // .verification_uri // empty')
  VERIFICATION_URI_COMPLETE=$(echo "$body" | jq -r '.data.verification_uri_complete // .verification_uri_complete // empty')
  POLL_INTERVAL=$(echo "$body" | jq -r '.data.interval // .interval // 5')
  POLL_EXPIRES=$(echo "$body" | jq -r '.data.expires_in // .expires_in // 900')

  [[ -z "$DEVICE_CODE" || -z "$USER_CODE" ]] && fail "Device authorization start response missing codes"
  log_info "User code: $USER_CODE"
  log_info "Verification URI: ${VERIFICATION_URI_COMPLETE:-$VERIFICATION_URI}"
}

step_device_verify() {
  log_info "Approving device authorization"
  local payload
  payload=$(jq -n --arg code "$USER_CODE" '{action:"device_verify",user_code:$code,approve:true}')
  local body
  body=$(http_post_json "$DEVICE_AUTH_ENDPOINT" "$payload" session "device_verify")
  local status
  status=$(echo "$body" | jq -r '.data.status // .status // empty')
  if [[ "$status" != "approved" ]]; then
    fail "Device verification returned status='$status'"
  fi
  return 0
}

step_device_poll() {
  log_info "Polling for registration code"
  local attempts=$((POLL_EXPIRES / POLL_INTERVAL))
  attempts=$(( attempts > 0 ? attempts : 1 ))
  local payload
  payload=$(jq -n --arg code "$DEVICE_CODE" '{action:"device_poll",device_code:$code}')

  for ((i=1; i<=attempts; ++i)); do
    log_info "Poll attempt $i/$attempts"
    local body
    body=$(http_post_json "$DEVICE_AUTH_ENDPOINT" "$payload" none "device_poll_$i")
    local status
    status=$(echo "$body" | jq -r '.data.status // .status // empty')
    case "$status" in
      ready)
        REGISTRATION_CODE=$(echo "$body" | jq -r '.data.registration_code // .registration_code // empty')
        [[ -z "$REGISTRATION_CODE" ]] && fail "Poll ready but registration_code missing"
        log_info "Received registration code"
        return
        ;;
      authorization_pending)
        sleep "$POLL_INTERVAL"
        ;;
      slow_down)
        POLL_INTERVAL=$((POLL_INTERVAL + 5))
        log_warn "Server requested slow down; new interval=${POLL_INTERVAL}s"
        sleep "$POLL_INTERVAL"
        ;;
      access_denied)
        fail "User denied device authorization"
        ;;
      expired)
        fail "Device code expired during polling"
        ;;
      *)
        fail "Unexpected poll status '$status'"
        ;;
    esac
  done
  fail "Polling timed out without registration code"
}

step_generate_device_keys() {
  log_info "Generating X25519 key pair"
  local priv_pem="$RUN_DIR/device/keys/device_private.pem"
  local pub_pem="$RUN_DIR/device/keys/device_public.pem"
  openssl genpkey -algorithm X25519 -out "$priv_pem" >/dev/null 2>&1 || fail "Failed to generate X25519 private key"
  openssl pkey -in "$priv_pem" -pubout -out "$pub_pem" >/dev/null 2>&1 || fail "Failed to derive X25519 public key"

  # Extract raw keys without relying on human-formatted text (which drifts between OpenSSL versions)
  local priv_der priv_der_tmp
  priv_der_tmp="$TMP_DIR/device_private.der"
  priv_der="$RUN_DIR/device/keys/device_private_raw.bin"
  openssl pkey -in "$priv_pem" -outform DER -out "$priv_der_tmp" >/dev/null 2>&1 || fail "Failed to export private key DER"
  # X25519 DER private key contains a 16-byte prefix (AlgorithmIdentifier) + OCTET STRING header.
  # Use openssl pkey -in ... -text -noout | xxd to extract the actual 32-byte scalar reliably.
  X25519_PRIVATE_KEY_B64=$(openssl pkey -in "$priv_pem" -outform DER 2>/dev/null | tail -c 32 | base64 -w0)
  printf '%s' "$X25519_PRIVATE_KEY_B64" | base64 -d > "$priv_der"

  local pub_der pub_der_tmp
  pub_der_tmp="$TMP_DIR/device_public.der"
  pub_der="$RUN_DIR/device/keys/device_public_raw.bin"
  openssl pkey -in "$pub_pem" -pubin -outform DER -out "$pub_der_tmp" >/dev/null 2>&1 || fail "Failed to export public key DER"
  X25519_PUBLIC_KEY_B64=$(openssl pkey -in "$pub_pem" -pubin -outform DER 2>/dev/null | tail -c 32 | base64 -w0)
  printf '%s' "$X25519_PUBLIC_KEY_B64" | base64 -d > "$pub_der"

  printf '%s' "$X25519_PRIVATE_KEY_B64" > "$RUN_DIR/device/keys/device_private_raw.b64"
  printf '%s' "$X25519_PUBLIC_KEY_B64" > "$RUN_DIR/device/keys/device_public_raw.b64"

  # Also export binary blobs for backend convenience
  chmod 600 "$priv_der" "$priv_pem" || true
}

step_register_device() {
  log_info "Registering device"
  DEVICE_PUBLIC_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/')

  local platform model app_version name ip ua
  platform=$(uname -s | tr '[:upper:]' '[:lower:]')
  model=$(uname -m)
  app_version="capture-script-1.0"
  name="Bundle Capture $(date +%F\ %T)"
  ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "127.0.0.1")
  ua="capture-device-bot/1.0"

  local payload
  payload=$(jq -n \
    --arg dev_id "$DEVICE_PUBLIC_ID" \
    --arg platform "$platform" \
    --arg model "$model" \
    --arg app_version "$app_version" \
    --arg name "$name" \
    --arg ip "$ip" \
    --arg ua "$ua" \
    --arg dev_pk "$X25519_PUBLIC_KEY_B64" \
    --arg reg "$REGISTRATION_CODE" \
    '{device_public_id:$dev_id, platform:$platform, model:$model, app_version:$app_version, name:$name, ip:$ip, user_agent:$ua, dev_pk:$dev_pk, registration_code:$reg}')

  local devices_endpoint
  devices_endpoint="${BASE_URL}/apiv1/users/${USER_ID}/devices"
  local body
  body=$(http_post_json "$devices_endpoint" "$payload" session "device_register")

  REGISTERED_DEVICE_ID=$(echo "$body" | jq -r '.data.device.id // .device.id // empty')
  ACCESS_TOKEN=$(echo "$body" | jq -r '.data.session.access_token // .session.access_token // empty')
  REFRESH_TOKEN=$(echo "$body" | jq -r '.data.session.refresh_token // .session.refresh_token // empty')

  [[ -z "$REGISTERED_DEVICE_ID" ]] && fail "Device registration succeeded but device.id missing"
  [[ -z "$ACCESS_TOKEN" ]] && fail "Device registration did not return access token"

  write_json "$RUN_DIR/device/registration.json" "$body"
  printf '%s' "$ACCESS_TOKEN" > "$RUN_DIR/device/access_token.txt"
  if [[ -n "$REFRESH_TOKEN" && "$REFRESH_TOKEN" != "null" ]]; then
    printf '%s' "$REFRESH_TOKEN" > "$RUN_DIR/device/refresh_token.txt"
  fi

  log_info "Registered device_id=$REGISTERED_DEVICE_ID"
}

step_create_self_ca() {
  log_info "Creating self CA for bundle capture"
  CA_NAME="capture-ca-$(generate_suffix)"
  local common_name="Capture Test CA ${CA_NAME}"
  local body
  body=$(jq -n --arg name "$CA_NAME" --arg cn "$common_name" '{
    name: $name,
    algorithm: "ECDSA",
    key_size: 256,
    curve_name: "prime256v1",
    country: "US",
    organization: "Capture Org",
    organizational_unit: "Automation",
    common_name: $cn,
    state: "CA",
    locality: "San Jose",
    valid_days: 3650,
    max_path_length: 0,
    key_usage: "keyCertSign,cRLSign"
  }')
  local response
  response=$(http_post_json "${BASE_URL}/apiv1/users/${USER_ID}/cas" "$body" session "create_self_ca")
  CA_ID=$(echo "$response" | jq -r '.data.id // .id // empty')
  [[ -z "$CA_ID" || "$CA_ID" == "null" ]] && fail "Self CA creation response missing id: $response"
  echo "$response" | jq '.' > "$RUN_DIR/resources/self_ca.json"
}

step_create_acme_account() {
  log_info "Creating ACME account linked to self CA"
  local acct_name="capture-acme-$(generate_suffix)"
  local body
  body=$(jq -n --arg name "$acct_name" --arg email "capture@example.com" --arg provider "letsencrypt" --arg ca "$CA_ID" '{
    name: $name,
    email: $email,
    provider: $provider,
    ca_id: ($ca|tonumber)
  }')
  local response
  response=$(http_post_json "${BASE_URL}/apiv1/users/${USER_ID}/acme-accounts" "$body" session "create_acme_account")
  ACME_ACCOUNT_ID=$(echo "$response" | jq -r '.data.id // .id // empty')
  [[ -z "$ACME_ACCOUNT_ID" || "$ACME_ACCOUNT_ID" == "null" ]] && fail "ACME account creation failed: $response"
  echo "$response" | jq '.' > "$RUN_DIR/resources/acme_account.json"
}

step_create_cert_record() {
  log_info "Creating certificate record"
  CERT_DOMAIN="capture-bundle.local"
  local body
  body=$(jq -n --arg domain "$CERT_DOMAIN" --arg acct "$ACME_ACCOUNT_ID" '{
    domain_name: $domain,
    sans: ["*.capture-bundle.local"],
    acct_id: ($acct|tonumber),
    action: "create",
    organization: "Capture Org",
    organizational_unit: "Automation",
    country: "US",
    state: "CA",
    locality: "San Jose"
  }')
  local response
  response=$(http_post_json "${BASE_URL}/apiv1/users/${USER_ID}/certificates" "$body" session "create_cert_record")
  CERT_ID=$(echo "$response" | jq -r '.data.id // .id // empty')
  [[ -z "$CERT_ID" || "$CERT_ID" == "null" ]] && fail "Certificate record creation failed: $response"
  echo "$response" | jq '.' > "$RUN_DIR/resources/cert_record.json"
}

step_issue_certificate() {
  log_info "Issuing certificate id=$CERT_ID"
  local body
  body=$(jq -n '{validity_seconds: 7776000}')
  local response
  response=$(http_post_json "${BASE_URL}/apiv1/users/${USER_ID}/certificates/${CERT_ID}/issues" "$body" session "issue_certificate")
  if [[ -n "$response" ]]; then
    echo "$response" | jq '.' > "$RUN_DIR/resources/cert_issue.json"
  fi
  sleep 2
}

step_associate_ca_with_device() {
  log_info "Associating CA $CA_ID with device $REGISTERED_DEVICE_ID"
  local body
  body=$(jq -n --arg ca "$CA_ID" '{ca_id: ($ca|tonumber)}')
  local response
  response=$(http_post_json "${BASE_URL}/apiv1/users/${USER_ID}/devices/${REGISTERED_DEVICE_ID}/cas" "$body" session "associate_ca")
  if [[ -n "$response" ]]; then
    echo "$response" | jq '.' > "$RUN_DIR/resources/device_ca_assoc.json"
  fi
}

step_assign_cert_to_device() {
  log_info "Assigning certificate $CERT_ID to device $REGISTERED_DEVICE_ID"
  local body
  body=$(jq -n --arg cert "$CERT_ID" '{cert_id: ($cert|tonumber)}')
  local response
  response=$(http_post_json "${BASE_URL}/apiv1/users/${USER_ID}/devices/${REGISTERED_DEVICE_ID}/certificates" "$body" session "assign_cert")
  if [[ -n "$response" ]]; then
    echo "$response" | jq '.' > "$RUN_DIR/resources/device_cert_assign.json"
  fi
}

step_create_install_config() {
  log_info "Creating install configuration for device"
  INSTALL_SUFFIX=$(generate_suffix)
  local install_base="/opt/cert-ctrl/${INSTALL_SUFFIX}"
  local body
  body=$(jq -n \
    --arg suffix "$INSTALL_SUFFIX" \
    --arg install_base "$install_base" \
    --arg cert_id "$CERT_ID" \
    --arg cert_name "$CERT_DOMAIN" \
    --arg ca_id "$CA_ID" \
    --arg ca_name "$CA_NAME" \
    --arg note "capture install $INSTALL_SUFFIX" '{
      installs: [
        {
          id: ("cert-" + $suffix),
          type: "copy",
          continue_on_error: false,
          depends_on: [],
          tags: [],
          ob_type: "cert",
          ob_id: ($cert_id|tonumber),
          ob_name: $cert_name,
          from: ["private.key","certificate.pem","chain.pem","fullchain.pem","certificate.der","bundle.pfx","meta.json"],
          to: [
            ($install_base + "/cert/private.key"),
            ($install_base + "/cert/certificate.pem"),
            ($install_base + "/cert/chain.pem"),
            ($install_base + "/cert/fullchain.pem"),
            ($install_base + "/cert/certificate.der"),
            ($install_base + "/cert/bundle.pfx"),
            ($install_base + "/cert/meta.json")
          ],
          cmd: "",
          cmd_argv: [],
          timeout_ms: 0,
          run_as: "",
          env: {},
          verify: {type: "cert_fingerprint"}
        },
        {
          id: ("ca-" + $suffix),
          type: "copy",
          continue_on_error: false,
          depends_on: [],
          tags: ["ca-install"],
          ob_type: "ca",
          ob_id: ($ca_id|tonumber),
          ob_name: $ca_name,
          from: ["ca.pem"],
          to: [($install_base + "/ca/ca.pem")],
          cmd: "",
          cmd_argv: [],
          timeout_ms: 0,
          run_as: "",
          env: {},
          verify: {}
        }
      ],
      change_note: $note
    }')
  echo "$body" | jq '.' > "$RUN_DIR/state/install_config_request.json"
  http_put_json "${BASE_URL}/apiv1/users/${USER_ID}/devices/${REGISTERED_DEVICE_ID}/install-config" "$body" session "upsert_install_config" >/dev/null
  log_info "Install config submitted; waiting for bundle wraps"
  sleep 5
}

step_fetch_install_config() {
  log_info "Fetching install configuration"
  local attempts=6
  local delay=3
  local admin_url
  admin_url="${BASE_URL}/apiv1/users/${USER_ID}/devices/${REGISTERED_DEVICE_ID}/install-config"
  local admin_body="$RUN_DIR/responses/install_config.json"
  local status

  for ((attempt=1; attempt<=attempts; ++attempt)); do
    status=$(http_get_json "$admin_url" session "install_config")
    if [[ "$status" == "200" ]]; then
      local extracted
      extracted=$(jq '.data' "$admin_body" 2>/dev/null || echo "null")
      if [[ "$extracted" == "null" || -z "$extracted" ]]; then
        fail "Install config response missing data payload: $(cat "$admin_body")"
      fi
      local normalized
      normalized=$(printf '%s\n' "$extracted" | jq 'def ensure_installs: if (.installs? and (.installs|type=="array")) then . elif (.installs_json? and (.installs_json|type=="string")) then . + {installs: ((.installs_json | try (fromjson) catch []) // [])} else . end; ensure_installs')
      printf '%s\n' "$normalized" > "$RUN_DIR/state/install_config.json"
      break
    fi

    if [[ "$status" == "503" && $attempt -lt $attempts ]]; then
      log_warn "Install config (user endpoint) returned 503 (attempt ${attempt}/${attempts}); retrying after ${delay}s"
      sleep "$delay"
      continue
    fi

    fail "Install config fetch (user endpoint) failed with status $status: $(cat "$admin_body")"
  done

  if [[ "$status" != "200" ]]; then
    fail "Install config fetch (user endpoint) exhausted retries"
  fi

  # Attempt device-self endpoint as an extra data point. Do not fail the run on errors here.
  local self_status
  self_status=$(http_get_json "$INSTALL_CONFIG_ENDPOINT" bearer "install_config_self")
  if [[ "$self_status" == "200" ]]; then
    local self_extracted
    self_extracted=$(jq '.data' "$RUN_DIR/responses/install_config_self.json" 2>/dev/null || echo "null")
    if [[ "$self_extracted" != "null" && -n "$self_extracted" ]]; then
      local normalized_self
      normalized_self=$(printf '%s\n' "$self_extracted" | jq 'def ensure_installs: if (.installs? and (.installs|type=="array")) then . elif (.installs_json? and (.installs_json|type=="string")) then . + {installs: ((.installs_json | try (fromjson) catch []) // [])} else . end; ensure_installs')
      printf '%s\n' "$normalized_self" > "$RUN_DIR/state/install_config_self.json"
    fi
  else
    log_warn "Self install-config endpoint responded with status $self_status"
  fi
}

bundle_analysis() {
  local raw_path="$1" out_path="$2" private_key_b64_path="$3"
  python3 - "$raw_path" "$out_path" "$private_key_b64_path" <<'PY'
import base64
import json
import sys
from pathlib import Path

raw_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
priv_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None


def decode_field(obj, name):
    if obj is None or not isinstance(obj, dict):
        return None
    value = obj.get(name)
    if not value or not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value)
    except Exception:
        return None


analysis = {
    "has_data": False,
    "enc_privkey_length": None,
    "tag_length": None,
    "provided_tag_b64": None,
    "libsodium_available": False,
    "aesgcm_available": False,
    "fingerprint_match": None,
    "bundle_device_keyfp_b64": None,
    "derived_fingerprint_b64": None,
    "unsealed_key_length": None,
    "plaintext_length": None,
    "plaintext_b64": None,
    "missing_fields": [],
}


def record_error(key, message):
    if key not in analysis:
        analysis[key] = message


try:
    payload = json.loads(raw_path.read_text())
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, dict):
        analysis["has_data"] = True
        analysis["provided_tag_b64"] = data.get("privkey_tag_b64")
        required = [
            "enc_privkey_b64",
            "privkey_tag_b64",
            "privkey_nonce_b64",
            "enc_data_key_b64",
        ]
        analysis["missing_fields"] = [
            name
            for name in required
            if name not in data or data.get(name) in (None, "")
        ]

        enc_priv = decode_field(data, "enc_privkey_b64")
        if enc_priv is not None:
            analysis["enc_privkey_length"] = len(enc_priv)

        tag_bytes = decode_field(data, "privkey_tag_b64")
        if tag_bytes is not None:
            analysis["tag_length"] = len(tag_bytes)

        bundle_fp = data.get("device_keyfp_b64")
        if isinstance(bundle_fp, str):
            analysis["bundle_device_keyfp_b64"] = bundle_fp

        if priv_path is not None and priv_path.is_file():
            try:
                priv_bytes = base64.b64decode(priv_path.read_text().strip())
            except Exception as exc:
                record_error(
                    "error_private_key",
                    f"Failed to decode device private key: {exc}",
                )
            else:
                analysis["device_private_key_length"] = len(priv_bytes)
                if len(priv_bytes) == 32:
                    try:
                        from nacl import bindings as sodium

                        analysis["libsodium_available"] = True
                    except ImportError as exc:
                        record_error(
                            "error_libsodium",
                            f"PyNaCl not available: {exc}",
                        )
                    else:
                        pub_bytes = sodium.crypto_scalarmult_base(priv_bytes)
                        derived_fp = base64.b64encode(pub_bytes).decode()
                        analysis["derived_fingerprint_b64"] = derived_fp
                        if bundle_fp:
                            analysis["fingerprint_match"] = derived_fp == bundle_fp

                        sealed = decode_field(data, "enc_data_key_b64")
                        if sealed is not None:
                            try:
                                unsealed = sodium.crypto_box_seal_open(
                                    sealed, pub_bytes, priv_bytes
                                )
                            except Exception as exc:
                                record_error(
                                    "error_unseal",
                                    f"crypto_box_seal_open failed: {exc}",
                                )
                            else:
                                analysis["unsealed_key_length"] = len(unsealed)
                                if len(unsealed) == 32:
                                    try:
                                        from cryptography.hazmat.primitives.ciphers.aead import (
                                            AESGCM,
                                        )

                                        analysis["aesgcm_available"] = True
                                    except Exception as exc:
                                        record_error(
                                            "error_aesgcm",
                                            f"AESGCM unavailable: {exc}",
                                        )
                                    else:
                                        nonce = decode_field(data, "privkey_nonce_b64")
                                        ciphertext = decode_field(data, "enc_privkey_b64")
                                        tag = decode_field(data, "privkey_tag_b64")
                                        if (
                                            nonce is None
                                            or ciphertext is None
                                            or tag is None
                                        ):
                                            record_error(
                                                "error_decrypt",
                                                "Missing nonce/ciphertext/tag for AES-GCM",
                                            )
                                        else:
                                            try:
                                                aesgcm = AESGCM(unsealed)
                                                plaintext = aesgcm.decrypt(
                                                    nonce, ciphertext + tag, None
                                                )
                                            except Exception as exc:
                                                record_error(
                                                    "error_decrypt",
                                                    f"AES-GCM decrypt failed: {exc}",
                                                )
                                            else:
                                                analysis["plaintext_length"] = len(plaintext)
                                                analysis["plaintext_b64"] = base64.b64encode(
                                                    plaintext
                                                ).decode()
                                else:
                                    record_error(
                                        "error_unseal_len",
                                        f"Unsealed key length {len(unsealed)} != 32",
                                    )
                        else:
                            record_error(
                                "error_sealed_missing",
                                "enc_data_key_b64 missing",
                            )
                else:
                    record_error(
                        "error_private_key_length",
                        f"Expected 32-byte X25519 key, got {len(priv_bytes)}",
                    )
    else:
        record_error("error_data", "Payload missing data object")
except Exception as exc:
    record_error("error", str(exc))

out_path.write_text(json.dumps(analysis, indent=2))
PY
}

fetch_bundle_for() {
  local ob_type="$1" ob_id="$2"
  local url=""
  case "$ob_type" in
    cert)
      url="${BASE_URL}/apiv1/devices/self/certificates/${ob_id}/bundle?pack=download"
      ;;
    ca)
      url="${BASE_URL}/apiv1/devices/self/cas/${ob_id}/bundle?pack=download"
      ;;
    *)
      log_warn "Skipping unsupported ob_type '$ob_type'"
      return
      ;;
  esac

  log_info "Fetching bundle for ${ob_type} ${ob_id}"
  local body_file="$TMP_DIR/bundle_${ob_type}_${ob_id}.json"
  local headers_file="$TMP_DIR/bundle_${ob_type}_${ob_id}.headers"
  local status
  status=$(curl -sS -X GET -D "$headers_file" -o "$body_file" -w '%{http_code}' -H "Authorization: Bearer $ACCESS_TOKEN" "$url")
  if [[ "$status" != "200" ]]; then
    log_error "Bundle fetch for ${ob_type} ${ob_id} failed with status $status"
    log_error "Response: $(cat "$body_file")"
    exit 1
  fi

  local target_root="$RUN_DIR/resources/${ob_type}s/${ob_id}"
  mkdir -p "$target_root"
  cp "$body_file" "$target_root/bundle_raw.json"
  cp "$headers_file" "$target_root/bundle.headers"
  bundle_analysis "$target_root/bundle_raw.json" "$target_root/bundle_analysis.json" "$RUN_DIR/device/keys/device_private_raw.b64"
}

step_materialize_bundles() {
  log_info "Downloading bundles referenced by install config"
  local config="$RUN_DIR/state/install_config.json"
  local installs_json
  installs_json=$(jq -c '.installs[] | {ob_type:.ob_type, ob_id:.ob_id, from:.from}' "$config") || fail "Failed to parse install config"
  if [[ -z "$installs_json" ]]; then
    log_warn "Install config had no install entries"
    return
  fi

  while IFS= read -r line; do
    local ob_type ob_id
    ob_type=$(echo "$line" | jq -r '.ob_type // empty')
    ob_id=$(echo "$line" | jq -r '.ob_id // empty')
    if [[ -z "$ob_type" || -z "$ob_id" ]]; then
      log_warn "Skipping install entry missing ob_type/ob_id"
      continue
    fi
    fetch_bundle_for "$ob_type" "$ob_id"
  done <<< "$installs_json"
}

step_poll_updates() {
  log_info "Polling device updates endpoint"
  local status
  status=$(http_get_json "$DEVICE_UPDATES_ENDPOINT" bearer "device_updates")
  if [[ "$status" != "200" && "$status" != "204" ]]; then
    local body_path="$RUN_DIR/responses/device_updates.json"
    fail "Updates poll failed with status $status: $(cat "$body_path")"
  fi
  if [[ "$status" == "200" ]]; then
    CURSOR=$(jq -r '.data.cursor // empty' "$RUN_DIR/responses/device_updates.json" || true)
  fi
  cp "$RUN_DIR/responses/device_updates.json" "$RUN_DIR/updates/updates_response.json" 2>/dev/null || true
}

write_summary() {
  local summary="$RUN_DIR/summary.json"
  jq -n \
    --arg run_id "$RUN_ID" \
    --arg base_url "$BASE_URL" \
    --arg user_id "$USER_ID" \
    --arg device_public_id "$DEVICE_PUBLIC_ID" \
    --arg device_id "$REGISTERED_DEVICE_ID" \
    --arg access_token_preview "$(printf '%s' "$ACCESS_TOKEN" | cut -c1-24)" \
    --arg cursor "$CURSOR" \
    --arg output_dir "$RUN_DIR" \
    '{run_id:$run_id, base_url:$base_url, user_id:$user_id, device_public_id:$device_public_id, device_id:$device_id, access_token_preview:$access_token_preview, cursor:$cursor, output_dir:$output_dir}' \
    > "$summary"
}

#############################################
# Execute workflow
#############################################

step_login
step_device_start
step_device_verify
step_device_poll
step_generate_device_keys
step_register_device
step_create_self_ca
step_create_acme_account
step_create_cert_record
step_issue_certificate
step_associate_ca_with_device
step_assign_cert_to_device
step_create_install_config
step_fetch_install_config
step_materialize_bundles
step_poll_updates
write_summary

log_info "Bundle capture completed. Inspect artifacts under: $RUN_DIR"
