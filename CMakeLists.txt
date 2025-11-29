cmake_minimum_required(VERSION 3.16)

cmake_policy(SET CMP0104 NEW)
cmake_policy(SET CMP0146 OLD)
cmake_policy(SET CMP0167 NEW)
cmake_policy(SET CMP0111 NEW)  # Handle imported targets missing location property

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_options(/utf-8)
endif()

if(CMAKE_EXPORT_COMPILE_COMMANDS)
    function(_certctrl_sync_compile_commands)
        set(_src "${CMAKE_BINARY_DIR}/compile_commands.json")
        set(_dst_dir "${CMAKE_SOURCE_DIR}")
        if(EXISTS "${_src}")
            execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_src}" "${_dst_dir}/compile_commands.json")
            message(STATUS "Synced compile_commands.json to ${_dst_dir}")
        else()
            message(WARNING "compile_commands.json not found in ${_src}; skipping sync")
        endif()
    endfunction()
    cmake_language(DEFER CALL _certctrl_sync_compile_commands)
endif()

option(CERTCTRL_FORCE_LEGACY_GLIBCXX_ABI "Use libstdc++ dual ABI in legacy (pre-C++11) mode" OFF)
if(CERTCTRL_FORCE_LEGACY_GLIBCXX_ABI)
    add_compile_definitions(_GLIBCXX_USE_CXX11_ABI=0)
endif()

# Fix RPATH issues with Ninja generator
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

# CRITICAL: Must set runtime library BEFORE project() to apply to vcpkg packages
if(MSVC)
    # Use static runtime for standalone executable (matches x64-windows triplet)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo>:Embedded>")
    foreach(flag_var CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG
                     CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        if(DEFINED ${flag_var})
            string(REPLACE "/Zi" "/Z7" ${flag_var} "${${flag_var}}")
        endif()
    endforeach()
endif()

project(bbserver LANGUAGES CXX)

if(MSVC)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>)
endif()

include(GNUInstallDirs)
include(CheckCXXCompilerFlag)

option(USE_SYSTEM_OPENSSL "Link against the system-provided OpenSSL shared libraries" OFF)

message(STATUS "CMAKE_CXX_STANDARD_LIBRARIES=${CMAKE_CXX_STANDARD_LIBRARIES}")

# Interface target to unify Boost.DI constructor parameter limit across all targets
add_library(di_config INTERFACE)
target_compile_definitions(di_config INTERFACE BOOST_DI_CFG_CTOR_LIMIT_SIZE=16)

# Do not override the chosen compiler in CMake; honor what the user/toolchain sets.

# Add compatibility flags for broader glibc/libstdc++ support
if(UNIX AND NOT APPLE AND NOT WIN32)
    # Target older glibc and libstdc++ for better compatibility
    add_link_options(-static-libgcc -static-libstdc++)  # Static link runtime libraries
    
    # Try to use older symbol versions when possible
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
    
    message(STATUS "Applied Linux compatibility flags for broader glibc/libstdc++ support")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND NOT WIN32)
    set(THREADS_PTHREADS_WEAK_SEARCH FALSE)
    set(CMAKE_THREAD_LIBS_INIT "-pthread")
    add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:-pthread>")
    add_link_options("-pthread")
    # Disable time tracing for faster compilation
    # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftime-trace")
    # add_compile_options(-ftime-trace)
    # message(STATUS "********************Clang time tracing enabled******************************")
endif()

find_package(Threads REQUIRED)

if(USE_SYSTEM_OPENSSL)
    message(STATUS "OpenSSL linkage: using system-provided shared libraries")

    set(_certctrl_openssl_hint_paths)
    if(OPENSSL_ROOT_DIR)
        list(APPEND _certctrl_openssl_hint_paths
            "${OPENSSL_ROOT_DIR}"
            "${OPENSSL_ROOT_DIR}/.."
        )
    endif()
    list(APPEND _certctrl_openssl_hint_paths
        /usr
        /usr/local
        /opt/openssl
    )

    find_path(CERTCTRL_SYSTEM_OPENSSL_INCLUDE_DIR
        NAMES openssl/ssl.h
        PATHS ${_certctrl_openssl_hint_paths}
        PATH_SUFFIXES include include/openssl
    )
    if(NOT CERTCTRL_SYSTEM_OPENSSL_INCLUDE_DIR)
        message(FATAL_ERROR "USE_SYSTEM_OPENSSL=ON but OpenSSL headers were not found. Specify OPENSSL_ROOT_DIR or install the system OpenSSL development package.")
    endif()

    find_library(CERTCTRL_SYSTEM_OPENSSL_SSL_LIBRARY
        NAMES ssl libssl
        PATHS ${_certctrl_openssl_hint_paths}
        PATH_SUFFIXES lib lib64 lib/x86_64-linux-gnu lib64/openssl
    )
    find_library(CERTCTRL_SYSTEM_OPENSSL_CRYPTO_LIBRARY
        NAMES crypto libcrypto
        PATHS ${_certctrl_openssl_hint_paths}
        PATH_SUFFIXES lib lib64 lib/x86_64-linux-gnu lib64/openssl
    )

    if(NOT CERTCTRL_SYSTEM_OPENSSL_SSL_LIBRARY OR NOT CERTCTRL_SYSTEM_OPENSSL_CRYPTO_LIBRARY)
        message(FATAL_ERROR "USE_SYSTEM_OPENSSL=ON but system libssl/libcrypto were not found. Specify OPENSSL_ROOT_DIR or install the distro OpenSSL 3.x packages.")
    endif()

    add_library(OpenSSL::Crypto UNKNOWN IMPORTED)
    set_target_properties(OpenSSL::Crypto PROPERTIES
        IMPORTED_LOCATION "${CERTCTRL_SYSTEM_OPENSSL_CRYPTO_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${CERTCTRL_SYSTEM_OPENSSL_INCLUDE_DIR}"
    )

    add_library(OpenSSL::SSL UNKNOWN IMPORTED)
    set_target_properties(OpenSSL::SSL PROPERTIES
        IMPORTED_LOCATION "${CERTCTRL_SYSTEM_OPENSSL_SSL_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${CERTCTRL_SYSTEM_OPENSSL_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES OpenSSL::Crypto
    )

    set(OpenSSL_FOUND TRUE CACHE BOOL "System OpenSSL located" FORCE)
    set(OPENSSL_FOUND TRUE CACHE BOOL "System OpenSSL located" FORCE)
    set(OPENSSL_INCLUDE_DIR "${CERTCTRL_SYSTEM_OPENSSL_INCLUDE_DIR}" CACHE PATH "System OpenSSL include directory" FORCE)
    set(OPENSSL_LIBRARIES "${CERTCTRL_SYSTEM_OPENSSL_SSL_LIBRARY};${CERTCTRL_SYSTEM_OPENSSL_CRYPTO_LIBRARY}" CACHE STRING "System OpenSSL libraries" FORCE)
else()
    if(NOT DEFINED OPENSSL_USE_STATIC_LIBS)
        set(OPENSSL_USE_STATIC_LIBS ON CACHE BOOL "Link OpenSSL statically" FORCE)
    endif()
    message(STATUS "OpenSSL linkage: using package manager/vcpkg configured OpenSSL (static preferred)")
    find_package(OpenSSL REQUIRED)
endif()

add_library(certctrl_libatomic INTERFACE)
set(CERTCTRL_USING_STATIC_LIBATOMIC FALSE)

function(_certctrl_entry_contains_atomic out entry)
    if("${entry}" STREQUAL "atomic" OR "${entry}" STREQUAL "-latomic")
        set(${out} TRUE PARENT_SCOPE)
        return()
    endif()

    if("${entry}" MATCHES "\\$<LINK_ONLY:-?atomic>")
        set(${out} TRUE PARENT_SCOPE)
        return()
    endif()

    if("${entry}" MATCHES "(^|[^A-Za-z0-9_:])-?l?atomic($|[^A-Za-z0-9_])" AND NOT "${entry}" MATCHES "::")
        set(${out} TRUE PARENT_SCOPE)
        return()
    endif()

    set(${out} FALSE PARENT_SCOPE)
endfunction()

function(certctrl_use_static_atomic target)
    if(NOT CERTCTRL_USING_STATIC_LIBATOMIC)
        return()
    endif()

    if(NOT TARGET ${target})
        message(FATAL_ERROR "certctrl_use_static_atomic: target `${target}` does not exist.")
    endif()

    get_target_property(_certctrl_alias_target ${target} ALIASED_TARGET)
    if(NOT _certctrl_alias_target STREQUAL "_certctrl_alias_target-NOTFOUND" AND _certctrl_alias_target AND NOT _certctrl_alias_target STREQUAL "${target}")
        certctrl_use_static_atomic(${_certctrl_alias_target})
        return()
    endif()

    get_property(_certctrl_processed GLOBAL PROPERTY CERTCTRL_ATOMIC_PROCESSED)
    if(_certctrl_processed STREQUAL "_certctrl_processed-NOTFOUND")
        set(_certctrl_processed "")
    endif()
    list(FIND _certctrl_processed "${target}" _certctrl_processed_index)
    if(NOT _certctrl_processed_index EQUAL -1)
        return()
    endif()
    set_property(GLOBAL APPEND PROPERTY CERTCTRL_ATOMIC_PROCESSED "${target}")

    set(_certctrl_props
        LINK_LIBRARIES
        LINK_OPTIONS
        INTERFACE_LINK_LIBRARIES
        INTERFACE_LINK_OPTIONS
        IMPORTED_LINK_INTERFACE_LIBRARIES
        IMPORTED_LINK_INTERFACE_OPTIONS
    )

    foreach(_certctrl_cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
        list(APPEND _certctrl_props
            LINK_LIBRARIES_${_certctrl_cfg}
            LINK_OPTIONS_${_certctrl_cfg}
            INTERFACE_LINK_LIBRARIES_${_certctrl_cfg}
            INTERFACE_LINK_OPTIONS_${_certctrl_cfg}
            IMPORTED_LINK_INTERFACE_LIBRARIES_${_certctrl_cfg}
            IMPORTED_LINK_INTERFACE_OPTIONS_${_certctrl_cfg}
        )
    endforeach()

    set(_certctrl_child_targets)
    foreach(_certctrl_prop IN LISTS _certctrl_props)
        get_target_property(_certctrl_values ${target} ${_certctrl_prop})
        if(NOT _certctrl_values OR _certctrl_values STREQUAL "NOTFOUND")
            continue()
        endif()

        set(_certctrl_filtered "")
        set(_certctrl_modified FALSE)
        foreach(_certctrl_entry IN LISTS _certctrl_values)
            _certctrl_entry_contains_atomic(_certctrl_has_atomic "${_certctrl_entry}")
            if(_certctrl_has_atomic)
                set(_certctrl_modified TRUE)
                message(STATUS "certctrl: removing `${_certctrl_entry}` from ${target}::${_certctrl_prop}")
            else()
                list(APPEND _certctrl_filtered "${_certctrl_entry}")
                if(NOT _certctrl_entry MATCHES "^\\$" AND TARGET ${_certctrl_entry})
                    list(APPEND _certctrl_child_targets "${_certctrl_entry}")
                endif()
            endif()
        endforeach()

        if(_certctrl_modified)
            if(_certctrl_filtered)
                set_property(TARGET ${target} PROPERTY ${_certctrl_prop} ${_certctrl_filtered})
            else()
                set_property(TARGET ${target} PROPERTY ${_certctrl_prop})
            endif()
        endif()
    endforeach()

    if(_certctrl_child_targets)
        list(REMOVE_DUPLICATES _certctrl_child_targets)
        foreach(_certctrl_child IN LISTS _certctrl_child_targets)
            certctrl_use_static_atomic(${_certctrl_child})
        endforeach()
    endif()
endfunction()

if(NOT APPLE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        check_cxx_compiler_flag("-static-libatomic" CERTCTRL_HAS_STATIC_LIBATOMIC)
        if(CERTCTRL_HAS_STATIC_LIBATOMIC)
            target_link_options(certctrl_libatomic INTERFACE -static-libatomic)
            set(CERTCTRL_USING_STATIC_LIBATOMIC TRUE)
        else()
            execute_process(
                COMMAND ${CMAKE_CXX_COMPILER} -print-file-name=libatomic.a
                OUTPUT_VARIABLE CERTCTRL_LIBATOMIC_STATIC_PATH
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
            )
            if(CERTCTRL_LIBATOMIC_STATIC_PATH AND NOT CERTCTRL_LIBATOMIC_STATIC_PATH STREQUAL "libatomic.a" AND EXISTS "${CERTCTRL_LIBATOMIC_STATIC_PATH}")
                message(STATUS "Linking libatomic statically from ${CERTCTRL_LIBATOMIC_STATIC_PATH}")
                target_link_libraries(certctrl_libatomic INTERFACE ${CERTCTRL_LIBATOMIC_STATIC_PATH})
                set(CERTCTRL_USING_STATIC_LIBATOMIC TRUE)
            else()
                set(_libatomic_candidates)
                foreach(_libatomic_name libatomic.a libatomic.so libatomic.so.1)
                    execute_process(
                        COMMAND ${CMAKE_CXX_COMPILER} -print-file-name=${_libatomic_name}
                        OUTPUT_VARIABLE _libatomic_candidate
                        OUTPUT_STRIP_TRAILING_WHITESPACE
                        ERROR_QUIET
                    )
                    if(_libatomic_candidate AND NOT _libatomic_candidate STREQUAL ${_libatomic_name})
                        if(EXISTS "${_libatomic_candidate}")
                            list(APPEND _libatomic_candidates "${_libatomic_candidate}")
                        endif()
                    endif()
                endforeach()

                list(APPEND _libatomic_candidates
                    /usr/lib/gcc/x86_64-linux-gnu/libatomic.a
                    /usr/lib/gcc/x86_64-linux-gnu/libatomic.so
                    /usr/lib/gcc/x86_64-linux-gnu/13/libatomic.a
                    /usr/lib/gcc/x86_64-linux-gnu/13/libatomic.so
                )

                foreach(_candidate IN LISTS _libatomic_candidates)
                    if(EXISTS "${_candidate}")
                        set(CERTCTRL_LIBATOMIC_LIBRARY "${_candidate}")
                        break()
                    endif()
                endforeach()

                if(NOT CERTCTRL_LIBATOMIC_LIBRARY)
                    find_library(CERTCTRL_LIBATOMIC_LIBRARY atomic)
                endif()

                if(CERTCTRL_LIBATOMIC_LIBRARY)
                    message(WARNING "Compiler does not support -static-libatomic; linking against ${CERTCTRL_LIBATOMIC_LIBRARY}. Consider installing libatomic-static to enable a fully static embed.")
                    target_link_libraries(certctrl_libatomic INTERFACE ${CERTCTRL_LIBATOMIC_LIBRARY})
                    set(CERTCTRL_USING_STATIC_LIBATOMIC FALSE)
                else()
                    message(FATAL_ERROR "libatomic is required but neither -static-libatomic nor an atomic library could be found. Install libatomic-dev or similar.")
                endif()
            endif()
        endif()
    endif()
endif()

if(CERTCTRL_USING_STATIC_LIBATOMIC)
    get_property(_certctrl_all_targets GLOBAL PROPERTY TARGETS)
    foreach(_certctrl_target IN LISTS _certctrl_all_targets)
        foreach(_certctrl_probe_prop
            INTERFACE_LINK_LIBRARIES
            INTERFACE_LINK_OPTIONS
            IMPORTED_LINK_INTERFACE_LIBRARIES
            IMPORTED_LINK_INTERFACE_OPTIONS
            )
            get_target_property(_certctrl_probe_values ${_certctrl_target} ${_certctrl_probe_prop})
            if(_certctrl_probe_values AND NOT _certctrl_probe_values STREQUAL "NOTFOUND")
                foreach(_certctrl_probe_entry IN LISTS _certctrl_probe_values)
                    _certctrl_entry_contains_atomic(_certctrl_probe_has "${_certctrl_probe_entry}")
                    if(_certctrl_probe_has)
                        message(STATUS "certctrl: target `${_certctrl_target}` property ${_certctrl_probe_prop} includes `${_certctrl_probe_entry}`")
                    endif()
                endforeach()
            endif()
        endforeach()
        foreach(_certctrl_cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
            foreach(_certctrl_probe_prop
                INTERFACE_LINK_LIBRARIES_${_certctrl_cfg}
                INTERFACE_LINK_OPTIONS_${_certctrl_cfg}
                IMPORTED_LINK_INTERFACE_LIBRARIES_${_certctrl_cfg}
                )
                get_target_property(_certctrl_cfg_values ${_certctrl_target} ${_certctrl_probe_prop})
                if(_certctrl_cfg_values AND NOT _certctrl_cfg_values STREQUAL "NOTFOUND")
                    foreach(_certctrl_cfg_entry IN LISTS _certctrl_cfg_values)
                        _certctrl_entry_contains_atomic(_certctrl_cfg_has "${_certctrl_cfg_entry}")
                        if(_certctrl_cfg_has)
                            message(STATUS "certctrl: target `${_certctrl_target}` property ${_certctrl_probe_prop} includes `${_certctrl_cfg_entry}`")
                        endif()
                    endforeach()
                endif()
            endforeach()
        endforeach()
    endforeach()
endif()

if(APPLE)
    # Target macOS 13.6 so we can link against the LLVM libc++ runtimes shipped with
    # the Homebrew Clang 18 toolchain without version skew warnings.
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.6" CACHE STRING "Minimum macOS version" FORCE)
    message(STATUS "macOS deployment target: ${CMAKE_OSX_DEPLOYMENT_TARGET}")

    add_library(atomic_stub STATIC cmake/osx/atomic_stub.cpp)
    set_target_properties(atomic_stub PROPERTIES OUTPUT_NAME atomic)
    # Ensure the build tree is searched when downstream dependencies request -latomic
    link_directories(${CMAKE_BINARY_DIR})

    # Prefer matching libc++ runtime from the active Clang toolchain when available
    get_filename_component(_llvm_toolchain_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(_llvm_toolchain_prefix "${_llvm_toolchain_bin}" DIRECTORY)
    set(_llvm_cxx_runtime_dir "${_llvm_toolchain_prefix}/lib/c++")
    if(EXISTS "${_llvm_cxx_runtime_dir}")
        link_directories(${_llvm_cxx_runtime_dir})
    endif()
endif()

set(BUILD_SHARED_LIBS OFF)  # Only build static libraries

if(MSVC)
    # Windows-specific definitions for better compatibility
    add_compile_definitions(
        WIN32_LEAN_AND_MEAN    # Exclude rarely-used stuff from Windows headers
        NOMINMAX               # Prevent Windows.h from defining min/max macros
        _CRT_SECURE_NO_WARNINGS # Disable MSVC security warnings for standard functions
        _WIN32_WINNT=0x0602     # Align Windows API target with Boost binaries
        WINVER=0x0602           # Keep WINVER in sync with _WIN32_WINNT
        BOOST_USE_WINAPI_VERSION=0x0602
    )
    
    # CRITICAL: Set this BEFORE vcpkg toolchain loads packages
    # Use static runtime libraries for standalone executable (MUST match vcpkg triplet)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    
    # Also set the old-style flags for compatibility
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
    
    # Enable multi-processor compilation for faster builds
    add_compile_options(/MP)
    
    # Add /bigobj flag for files with large object sections (many templates)
    add_compile_options(/bigobj)
    
    # Link Windows sockets library for networking
    link_libraries(ws2_32)
endif()

include(cmake/CPM.cmake)

# Enable precompiled headers for faster compilation
set(CMAKE_PCH_ENABLE ON)

find_package(Git)

option(FORCE_CLEAN_GIT_DESCRIBE "Remove '-dirty' suffix from embedded version" OFF)

set(GIT_DESCRIBE "")
set(_GIT_DIFF_RESULT 0)
if(Git_FOUND)
    # Prefer semver-like tags (v*) and include commit metadata when available
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --long --dirty --abbrev=8 --match "v[0-9]*.[0-9]*.[0-9]*" --exclude "*-*"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_DESCRIBE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

    if(GIT_DESCRIBE AND FORCE_CLEAN_GIT_DESCRIBE)
        string(REGEX REPLACE "-dirty$" "" GIT_DESCRIBE "${GIT_DESCRIBE}")
    endif()

    execute_process(
        COMMAND ${GIT_EXECUTABLE} diff --quiet HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE _GIT_DIFF_RESULT
        ERROR_QUIET
    )

    if(NOT GIT_DESCRIBE)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE _GIT_SHA
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-list --count HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE _GIT_COMMIT_COUNT
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(_GIT_SHA AND _GIT_COMMIT_COUNT)
            set(GIT_DESCRIBE "v0.0.${_GIT_COMMIT_COUNT}-${_GIT_SHA}")
            if(NOT FORCE_CLEAN_GIT_DESCRIBE AND NOT _GIT_DIFF_RESULT EQUAL 0 AND NOT _GIT_DIFF_RESULT EQUAL 128)
                set(GIT_DESCRIBE "${GIT_DESCRIBE}-dirty")
            endif()
        endif()
    endif()
endif()

if(GIT_DESCRIBE AND FORCE_CLEAN_GIT_DESCRIBE)
    string(REGEX REPLACE "-dirty$" "" GIT_DESCRIBE "${GIT_DESCRIBE}")
endif()

if(NOT GIT_DESCRIBE)
    set(GIT_DESCRIBE "v0.0.0-unknown")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/version.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

message(STATUS "*******GIT_DESCRIBE: ${GIT_DESCRIBE}")
message(STATUS "*******CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")

# AddressSanitizer: enable only for Clang/GCC by default; skip for MSVC
if(ENABLE_ASAN)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        set(ASAN_FLAGS "-fsanitize=address -fno-omit-frame-pointer -g")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ASAN_FLAGS}")
        set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${ASAN_FLAGS}")
        message(STATUS "AddressSanitizer enabled (Clang/GNU)")
    else()
        message(STATUS "ENABLE_ASAN requested, but MSVC is not configured here; skipping ASAN flags")
    endif()
else()
    message(STATUS "AddressSanitizer disabled")
endif()


# CMAKE_BUILD_TYPE STREQUAL "Debug" and no 'NO_ASAN' environment variable
if (CMAKE_BUILD_TYPE STREQUAL "Debug" AND ENABLE_ASAN)
# Add AddressSanitizer flags
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always -v")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdiagnostics-color=always -v")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdiagnostics-color=always")
    endif()
else()
    message(STATUS "******AddressSanitizer is disabled******")
endif()


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG_BUILD)
    # Fast debug builds - balance speed and functionality
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        set(CMAKE_CXX_FLAGS_DEBUG "-O1 -g1")  # Minimal optimization and debug info
        set(CMAKE_C_FLAGS_DEBUG "-O1 -g1")
    elseif(MSVC)
        # Favor embedded debug info to avoid external PDB lookups
        foreach(_flag_var CMAKE_CXX_FLAGS_DEBUG CMAKE_C_FLAGS_DEBUG)
            if(DEFINED ${_flag_var})
                string(REGEX REPLACE "/Z[0-9I]" "" ${_flag_var} "${${_flag_var}}")
                string(STRIP "${${_flag_var}}" ${_flag_var})
            endif()
        endforeach()
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Z7 /Od")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Z7 /Od")
    endif()
    # option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
    
    # Minimal debug flags for Clang
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(-fno-omit-frame-pointer)
    endif()
    
elseif(CMAKE_BUILD_TYPE STREQUAL "Test")
    add_definitions(-DTEST_ENV)
    set(CMAKE_CXX_FLAGS_TEST "-O2 -g")
    set(CMAKE_C_FLAGS_TEST "-O2 -g")
    
else()
    add_definitions(-DRELEASE_BUILD)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU" AND NOT WIN32)
        if(DISABLE_LTO)
            set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
            set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
        else()
            set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -DNDEBUG")
            set(CMAKE_C_FLAGS_RELEASE "-O3 -flto -DNDEBUG")
        endif()
        set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-fuse-ld=lld")
    elseif(MSVC)
        # Enhanced MSVC optimization flags
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Ob2 /DNDEBUG")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /Ob2 /DNDEBUG")
        # Enable function-level linking for better optimization
        set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /OPT:REF /OPT:ICF")
    endif()
endif()

if(WIN32)
    # add_subdirectory(apps/tray)
endif()

message(STATUS "Current debug flags: ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "-------------------------env CORES value is: $ENV{CORES}-------------------------")
message(STATUS "-------------------------CMAKE_BUILD_PARALLEL_LEVEL: $ENV{CMAKE_BUILD_PARALLEL_LEVEL}-------------------------")


if(FALSE)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Find the IWYU tool
    find_program(IWYU_PATH NAMES include-what-you-use iwyu)

    if(IWYU_PATH)
        message(STATUS "Found Include What You Use (IWYU): ${IWYU_PATH}")
        set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE 
        "${CMAKE_SOURCE_DIR}/iwyu-wrapper.sh;-Xiwyu;--mapping_file=${CMAKE_SOURCE_DIR}/iwyu_mappings.imp;")
        # --mapping_file=${CMAKE_SOURCE_DIR}/iwyu/boost-all.imp
    else()
        message(WARNING "Include What You Use (IWYU) not found. Skipping IWYU checks.")
    endif()
endif()
endif()


enable_testing()
add_definitions(-DEIGEN_NO_DEBUG)

add_definitions(-DBOOST_PROCESS_VERSION=2)

# Auto-regenerate when new source files are added under src/
# Note: CONFIGURE_DEPENDS makes CMake re-run when the glob results change
# (supported since CMake 3.12+). Keep the pattern shallow to avoid pulling
# unintended files; add more patterns if you later add nested src directories.
# file(GLOB_RECURSE APP_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
file(GLOB APP_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

# Prefer submodule http_client sources over local duplicates
set(_LOCAL_DUP_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/base64.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/json_util.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/misc_util.cpp
)
foreach(_f IN LISTS _LOCAL_DUP_SRC)
    list(REMOVE_ITEM APP_SOURCES "${_f}")
endforeach()

set(HTTP_CLIENT_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/external/http_client/src/base64.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/external/http_client/src/client_ssl_ctx.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/external/http_client/src/json_util.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/external/http_client/src/misc_util.cpp
)

list(APPEND APP_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_config_manager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_actions/copy_action.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_actions/exec_action.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_actions/import_ca_action.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/browser_trust_sync.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_actions/install_resource_materializer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_actions/materialize_password_manager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/session_refresher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_workflow/install_workflow_runner.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_config_handler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/info_handler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/certificates_handler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/update_handler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_config_apply_handler.cpp
)

# Always use a stable target name; vary only the output file name per config
set(CERT_CTRL_APP_NAME cert_ctrl)

find_package(Protobuf CONFIG REQUIRED)
set(PROTO_FILES
    proto/messages/dicmeta.proto
    proto/messages/models.proto
)
set(Protobuf_USE_STATIC_LIBS ON)
message(STATUS "************* Protobuf_INCLUDE_DIRS: ${Protobuf_INCLUDE_DIRS}")
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})

# print PROTO_SRCS and PROTO_HDRS
message(STATUS "************* PROTO_SRCS: ${PROTO_SRCS}")
message(STATUS "************* PROTO_HDRS: ${PROTO_HDRS}")

add_compile_definitions(BUFFERSIZE=2048)

find_package(Boost REQUIRED COMPONENTS program_options)
find_package(minizip-ng CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS json)
find_package(Boost REQUIRED COMPONENTS uuid)
find_package(Boost REQUIRED COMPONENTS url)
find_package(Boost REQUIRED COMPONENTS asio)
find_package(Boost REQUIRED COMPONENTS process)
find_package(Boost REQUIRED COMPONENTS program_options)
find_package(Boost REQUIRED COMPONENTS iostreams)
find_package(Boost REQUIRED COMPONENTS log)
find_package(Boost REQUIRED COMPONENTS log_setup)
find_package(minizip-ng CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)

if(ENABLE_ASAN)
    if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU"))
        message(FATAL_ERROR "ENABLE_ASAN requires Clang or GCC toolchains")
    endif()

    add_compile_options(
        "$<$<COMPILE_LANGUAGE:CXX>:-fsanitize=address>"
        "$<$<COMPILE_LANGUAGE:CXX>:-fno-omit-frame-pointer>"
        "$<$<COMPILE_LANGUAGE:C>:-fsanitize=address>"
        "$<$<COMPILE_LANGUAGE:C>:-fno-omit-frame-pointer>"
    )

    add_link_options(-fsanitize=address -fno-omit-frame-pointer)

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(
            "$<$<COMPILE_LANGUAGE:CXX>:-fdiagnostics-color=always>"
            "$<$<COMPILE_LANGUAGE:C>:-fdiagnostics-color=always>"
        )
    endif()

    message(STATUS "AddressSanitizer enabled (ENABLE_ASAN=ON)")
else()
    message(STATUS "AddressSanitizer disabled (ENABLE_ASAN=OFF)")
endif()


add_executable(${CERT_CTRL_APP_NAME} 
    ${APP_SOURCES}
    ${HTTP_CLIENT_SRCS}
    ${PROTO_SRCS}
    )

if(APPLE)
    add_dependencies(${CERT_CTRL_APP_NAME} atomic_stub)
endif()

# Name the produced binary by configuration to keep Release/Debug outputs distinct
set_target_properties(${CERT_CTRL_APP_NAME} PROPERTIES
    OUTPUT_NAME_DEBUG "cert_ctrl_debug"
    OUTPUT_NAME_RELWITHDEBINFO "cert_ctrl"
    OUTPUT_NAME_MINSIZEREL "cert_ctrl"
    OUTPUT_NAME_RELEASE "cert_ctrl"
)

target_include_directories(${CERT_CTRL_APP_NAME} 
    PRIVATE include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/external/http_client/include
    )

target_link_libraries(${CERT_CTRL_APP_NAME} 
    PRIVATE Boost::program_options
    PRIVATE Boost::json
    PRIVATE Boost::uuid
    PRIVATE Boost::asio
    PRIVATE Boost::url
    PRIVATE protobuf::libprotoc
    PRIVATE protobuf::libprotobuf
    PRIVATE Boost::program_options
    PRIVATE Boost::process
    PRIVATE Boost::iostreams
    PRIVATE Boost::log
    PRIVATE Boost::log_setup
    PRIVATE MINIZIP::minizip-ng
    PRIVATE jwt-cpp::jwt-cpp
    PRIVATE unofficial-sodium::sodium
    PRIVATE fmt::fmt
    PRIVATE certctrl_libatomic
    PRIVATE di_config
    )

if(WIN32)
    target_link_libraries(${CERT_CTRL_APP_NAME} PRIVATE crypt32)
endif()

if(APPLE)
    target_link_libraries(${CERT_CTRL_APP_NAME} PRIVATE c++abi "-framework Security" "-framework CoreFoundation")
endif()

if(OpenMP_CXX_FOUND)
    target_link_libraries(${CERT_CTRL_APP_NAME} PRIVATE OpenMP::OpenMP_CXX)
    message(STATUS "OpenMP enabled: using OpenMP::OpenMP_CXX")
else()
    message(STATUS "OpenMP not found or disabled; proceeding without OpenMP")
endif()

certctrl_use_static_atomic(${CERT_CTRL_APP_NAME})

install(TARGETS ${CERT_CTRL_APP_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    BUNDLE DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Add tests subdirectory
add_subdirectory(tests)
