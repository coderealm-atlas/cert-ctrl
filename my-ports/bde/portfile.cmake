vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

# Acquire Python and add it to PATH
vcpkg_find_acquire_program(PYTHON3)
get_filename_component(PYTHON3_EXE_PATH ${PYTHON3} DIRECTORY)

# Acquire BDE Tools and add them to PATH
set (BDE_TOOLS_VER 4.13.0.0)
vcpkg_from_github(
    OUT_SOURCE_PATH TOOLS_PATH
    REPO "bloomberg/bde-tools"
    REF "${BDE_TOOLS_VER}"
    SHA512 6a0eec25889a33fb0302af735ed2fcce38afa5ad2be9202d2589d76509f9fd85f9ddc0a73147df1b6471543f51df3b5b40e8c08d378ab1335d2703d89b5921e6
    HEAD_REF main
)

message(STATUS "Configure bde-tools-v${BDE_TOOLS_VERSION}")
vcpkg_add_to_path("${PYTHON3_EXE_PATH}")
vcpkg_add_to_path("${TOOLS_PATH}/bin")

# Acquire BDE sources
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO "bloomberg/bde"
    REF "${VERSION}"
    SHA512 d6d7e453cf22f6e28f3513b818ab3f4b597db3e1d109587e0e0a8957338483c475494f55d953dfe86de507a6c292d1492d9cbb3c8be359044ef368fe80595448
    HEAD_REF main
)

set(ENV{CXX} "/usr/bin/clang++")
set(ENV{CC} "/usr/bin/clang")

# string(APPEND CMAKE_CXX_FLAGS " -DBSLS_PLATFORM_CMP_CLANG=1 -UBSLS_PLATFORM_CMP_GNU")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS 
        -DBDE_BUILD_TARGET_CPP20=ON
        -DCMAKE_CXX_STANDARD=20
        -DCMAKE_CXX_STANDARD_REQUIRED=ON
        -DCMAKE_CXX_EXTENSIONS=OFF
        -DBBS_BUILD_SYSTEM=1
        "-DBdeBuildSystem_DIR:PATH=${TOOLS_PATH}/BdeBuildSystem"

        # 🔧 Force Clang-specific implementation for atomics
        # -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
        -DBSLS_PLATFORM_CMP_CLANG=1
        
        # -DBDE_BUILD_TARGET_COMPILER=clang
        # ✅ Add these defines to force symbol inclusion
        # -DBSLS_ASSERT_LEVEL_ASSERT_SAFE=1
        # -DBSLS_REVIEW_REVIEW_LEVEL_ASSERT=1
        # -DBSLS_BUILDTARGET_EXC=1
        # -DBSLS_BUILDTARGET_MT=1
    OPTIONS_RELEASE
        -DBDE_BUILD_TARGET_OPT=1
    OPTIONS_DEBUG
        -DBDE_BUILD_TARGET_DBG=1
)

# Build release
vcpkg_cmake_build()

# Install release
vcpkg_cmake_install()
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
list(APPEND SUBPACKAGES "ryu" "inteldfp" "pcre2" "s_baltst" "bsl" "bdl" "bal")
include(GNUInstallDirs) # needed for CMAKE_INSTALL_LIBDIR
foreach(subpackage IN LISTS SUBPACKAGES)
    vcpkg_cmake_config_fixup(PACKAGE_NAME ${subpackage} CONFIG_PATH /${CMAKE_INSTALL_LIBDIR}/cmake/${subpackage} DO_NOT_DELETE_PARENT_CONFIG_PATH)
endforeach()
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/${CMAKE_INSTALL_LIBDIR}/cmake" "${CURRENT_PACKAGES_DIR}/debug/${CMAKE_INSTALL_LIBDIR}/cmake")

# Handle copyright
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
vcpkg_fixup_pkgconfig()
