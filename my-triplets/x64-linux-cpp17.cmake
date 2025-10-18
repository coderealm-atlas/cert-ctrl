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