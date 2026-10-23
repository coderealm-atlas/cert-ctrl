set(VCPKG_TARGET_ARCHITECTURE x64)
# Use dynamic CRT (runtime) linkage (for MSVC; has no effect on Linux)
set(VCPKG_CRT_LINKAGE dynamic)
# Use static library linking for all dependencies
set(VCPKG_LIBRARY_LINKAGE static)

# Compiler flags (applied to ALL dependencies)
# set(VCPKG_CXX_FLAGS "-std=c++20 -DBSLS_LIBRARYFEATURES_HAS_CPP20_FEATURES -DBSLS_LIBRARYFEATURES_CPP20_ABI")

set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

set(VCPKG_CMAKE_SYSTEM_NAME Linux)
# Container releases opt in; keep native builds' toolchain choices unchanged.
set(VCPKG_ENV_PASSTHROUGH CERTCTRL_CPU_BASELINE)
if(DEFINED ENV{CERTCTRL_CPU_BASELINE})
    if(NOT "$ENV{CERTCTRL_CPU_BASELINE}" STREQUAL "x86-64")
        message(FATAL_ERROR "Unsupported cert-ctrl container CPU baseline")
    endif()
    set(VCPKG_C_FLAGS "-march=x86-64 -mtune=generic")
    set(VCPKG_CXX_FLAGS "-march=x86-64 -mtune=generic")
endif()
