#!/usr/bin/env bash
# run_all_test.sh - Convenience wrapper to configure, build, and run the full CTest suite.

set -euo pipefail

# export CERTCTRL_REAL_SERVER_TESTS=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
PRESET="debug-asan"
JOBS=""
CONFIGURE_FIRST=true
BUILD_FIRST=true

usage() {
    cat <<'EOF'
Usage: ./run_all_test.sh [options]

Options:
  --preset <name>     CMake configure/build preset to use (default: debug-asan)
  --jobs <n>          Override parallelism passed to CTest (CTEST_PARALLEL_LEVEL)
  --skip-configure    Skip the cmake --preset <name> configure step
  --skip-build        Skip the cmake --build step (requires artifacts already built)
  -h, --help          Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --preset)
            PRESET="$2"
            shift 2
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --skip-configure)
            CONFIGURE_FIRST=false
            shift
            ;;
        --skip-build)
            BUILD_FIRST=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [ ! -f "$PROJECT_ROOT/CMakePresets.json" ]; then
    echo "Error: CMakePresets.json not found in project root ($PROJECT_ROOT)." >&2
    exit 1
fi

if ! command -v cmake >/dev/null 2>&1; then
    echo "Error: cmake is not installed or not in PATH." >&2
    exit 1
fi

if $CONFIGURE_FIRST; then
    echo "[run_all_test] Configuring with preset '$PRESET'..."
    cmake --preset "$PRESET"
fi

if $BUILD_FIRST; then
    echo "[run_all_test] Building with preset '$PRESET'..."
    cmake --build --preset "$PRESET"
fi

export CTEST_OUTPUT_ON_FAILURE=1
if [ -n "$JOBS" ]; then
    export CTEST_PARALLEL_LEVEL="$JOBS"
fi

echo "[run_all_test] Running tests (preset: '$PRESET')..."
cmake --build --preset "$PRESET" --target test

echo "[run_all_test] All tests completed successfully."
