#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/test-env" ]]; then
  echo "test-env file not found in ${SCRIPT_DIR}" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/test-env"

: "${CERT_CTRL_TEST_EMAIL:?CERT_CTRL_TEST_EMAIL is not set in test-env}"
: "${CERT_CTRL_TEST_PASSWORD:?CERT_CTRL_TEST_PASSWORD is not set in test-env}"

BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/../build/debug-asan}"
TEST_BIN="${BUILD_DIR}/tests/test_updates_polling_handler"

if [[ ! -x "${TEST_BIN}" ]]; then
  echo "Test binary not found or not executable at ${TEST_BIN}" >&2
  echo "Set BUILD_DIR to the build root containing tests/test_updates_polling_handler" >&2
  exit 1
fi

export CERTCTRL_REAL_SERVER_TESTS=1
ASAN_OPTIONS="detect_leaks=0" "${TEST_BIN}" "$@"
