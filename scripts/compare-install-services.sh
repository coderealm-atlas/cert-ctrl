#!/usr/bin/env bash
set -euo pipefail

base_a="${1:-https://install.lets-script.com}"
base_b="${2:-https://install-selfhost.lets-script.com}"

tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

headers_to_check=(
  content-type
  cache-control
  vary
  x-platform
  x-platform-confidence
  x-architecture
  x-mirror
  x-version
  x-cache
  x-source
  retry-after
)

say() {
  printf '%s\n' "$*"
}

safe_id() {
  printf '%s' "$1" | sed -E 's#[^A-Za-z0-9]+#_#g' | sed -E 's/^_+|_+$//g'
}

curl_capture() {
  local method="$1"
  local url="$2"
  local out_prefix="$3"
  local headers="${out_prefix}.headers"
  local body="${out_prefix}.body"
  local status

  : > "$headers"
  : > "$body"

  if [[ "$method" == "HEAD" ]]; then
    status="$(curl -sS --connect-timeout 10 --max-time 30 -o /dev/null -D "$headers" -I -w "%{http_code}" "$url" || true)"
  else
    status="$(curl -sS --connect-timeout 10 --max-time 30 -D "$headers" -o "$body" -X "$method" -w "%{http_code}" "$url" || true)"
  fi

  printf '%s' "$status" > "${out_prefix}.status"
}

get_header_value() {
  local headers_file="$1"
  local key="$2"
  awk -v key="$key" 'BEGIN{IGNORECASE=1}
    /^[A-Za-z0-9-]+:/ {
      name=$1
      sub(/:$/, "", name)
      if (tolower(name) == tolower(key)) {
        sub(/^[^:]+:[[:space:]]*/, "")
        value=$0
      }
    }
    END{print value}
  ' "$headers_file"
}

normalize_json() {
  local input="$1"
  local output="$2"
  python3 - "$input" "$output" <<'PY'
import json
import sys

src = sys.argv[1]
dst = sys.argv[2]

try:
    with open(src, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    sys.exit(1)

with open(dst, "w", encoding="utf-8") as f:
    json.dump(data, f, sort_keys=True, indent=2)
PY
}

normalize_text() {
  local input="$1"
  local output="$2"
  python3 - "$input" "$output" "$base_a" "$base_b" <<'PY'
import sys

src = sys.argv[1]
dst = sys.argv[2]
base_a = sys.argv[3]
base_b = sys.argv[4]

with open(src, "r", encoding="utf-8", errors="replace") as f:
    data = f.read()

data = data.replace(base_a, "<BASE_URL>").replace(base_b, "<BASE_URL>")

with open(dst, "w", encoding="utf-8") as f:
    f.write(data)
PY
}

compare_bodies() {
  local label="$1"
  local file_a="$2"
  local file_b="$3"
  local json_norm_a="${file_a}.norm.json"
  local json_norm_b="${file_b}.norm.json"
  local text_norm_a="${file_a}.norm.txt"
  local text_norm_b="${file_b}.norm.txt"
  local diff_file="${file_a}.diff"

  if [[ ! -s "$file_a" || ! -s "$file_b" ]]; then
    say "  body: unavailable for comparison"
    return
  fi

  if normalize_json "$file_a" "$json_norm_a" && normalize_json "$file_b" "$json_norm_b"; then
    diff -u "$json_norm_a" "$json_norm_b" > "$diff_file" || true
    if [[ -s "$diff_file" ]]; then
      say "  body: JSON differs"
      sed -n '1,200p' "$diff_file"
    else
      say "  body: JSON identical"
    fi
    return
  fi

  normalize_text "$file_a" "$text_norm_a"
  normalize_text "$file_b" "$text_norm_b"
  diff -u "$text_norm_a" "$text_norm_b" > "$diff_file" || true
  if [[ -s "$diff_file" ]]; then
    say "  body: text differs (normalized)"
    sed -n '1,200p' "$diff_file"
  else
    say "  body: text identical (normalized)"
  fi
}

compare_endpoint() {
  local method="$1"
  local path="$2"
  local id
  id="$(safe_id "${method}_${path}")"
  local prefix_a="${tmp_root}/a_${id}"
  local prefix_b="${tmp_root}/b_${id}"
  local url_a="${base_a}${path}"
  local url_b="${base_b}${path}"

  curl_capture "$method" "$url_a" "$prefix_a"
  curl_capture "$method" "$url_b" "$prefix_b"

  say "== ${method} ${path}"
  say "A ${base_a} -> $(cat "${prefix_a}.status")"
  say "B ${base_b} -> $(cat "${prefix_b}.status")"

  for header in "${headers_to_check[@]}"; do
    local value_a
    local value_b
    value_a="$(get_header_value "${prefix_a}.headers" "$header")"
    value_b="$(get_header_value "${prefix_b}.headers" "$header")"
    if [[ -n "$value_a" || -n "$value_b" ]]; then
      say "  header ${header}: A='${value_a}' B='${value_b}'"
    fi
  done

  if [[ "$method" != "HEAD" ]]; then
    compare_bodies "$path" "${prefix_a}.body" "${prefix_b}.body"
  fi

  say ""
}

pick_asset() {
  local json_file="$1"
  python3 - "$json_file" <<'PY'
import json
import os
import sys
from urllib.parse import urlparse

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    sys.exit(1)

def basename(url):
    return os.path.basename(urlparse(url).path)

download_urls = data.get("download_urls") or {}
preferred = [
    "linux-x64",
    "linux-x64-openssl3",
    "linux-arm64",
    "macos-x64",
    "macos-arm64",
    "windows-x64",
    "linux-musl-x64"
]

if isinstance(download_urls, dict):
    for key in preferred:
        url = download_urls.get(key)
        if url:
            print(basename(url))
            sys.exit(0)
    for url in download_urls.values():
        if url:
            print(basename(url))
            sys.exit(0)

assets = data.get("assets") or []
for asset in assets:
    name = asset.get("name")
    if not name:
        continue
    if name.endswith((".sha256", ".sig", ".asc")):
        continue
    print(name)
    sys.exit(0)
PY
}

pick_version() {
  local json_file="$1"
  python3 - "$json_file" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    sys.exit(1)

version = data.get("version")
if version:
    print(version)
PY
}

say "Comparing install services"
say "A: ${base_a}"
say "B: ${base_b}"
say ""

compare_endpoint "GET" "/"
compare_endpoint "GET" "/health"
compare_endpoint "GET" "/install.sh"
compare_endpoint "GET" "/install.ps1"
compare_endpoint "GET" "/install-macos.sh"
compare_endpoint "GET" "/api/version/latest"
compare_endpoint "GET" "/api/version/check?current=v0.0.0&platform=linux&arch=x64"

latest_id="$(safe_id "GET_/api/version/latest")"
latest_a_body="${tmp_root}/a_${latest_id}.body"
latest_b_body="${tmp_root}/b_${latest_id}.body"

asset_name=""
version_name=""

if [[ -s "$latest_a_body" ]]; then
  asset_name="$(pick_asset "$latest_a_body" 2>/dev/null || true)"
  version_name="$(pick_version "$latest_a_body" 2>/dev/null || true)"
fi

if [[ -z "$asset_name" && -s "$latest_b_body" ]]; then
  asset_name="$(pick_asset "$latest_b_body" 2>/dev/null || true)"
fi

if [[ -z "$version_name" && -s "$latest_b_body" ]]; then
  version_name="$(pick_version "$latest_b_body" 2>/dev/null || true)"
fi

if [[ -n "$asset_name" ]]; then
  say "Using asset: ${asset_name}"
  compare_endpoint "HEAD" "/releases/proxy/latest/${asset_name}"
  if [[ -n "$version_name" ]]; then
    compare_endpoint "HEAD" "/releases/proxy/${version_name}/${asset_name}"
  fi
else
  say "Skipping /releases/proxy checks (no asset name found)."
fi
