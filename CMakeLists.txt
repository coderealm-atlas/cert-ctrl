cmake_minimum_required(VERSION 3.16)

cmake_policy(SET CMP0104 NEW)
cmake_policy(SET CMP0146 OLD)
cmake_policy(SET CMP0167 NEW)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# CRITICAL: Must set runtime library BEFORE project() to apply to vcpkg packages
if(MSVC)
    # Use static runtime for standalone executable (matches x64-windows triplet)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

project(bbserver LANGUAGES CXX)

# Interface target to unify Boost.DI constructor parameter limit across all targets
add_library(di_config INTERFACE)
target_compile_definitions(di_config INTERFACE BOOST_DI_CFG_CTOR_LIMIT_SIZE=16)

# Do not override the chosen compiler in CMake; honor what the user/toolchain sets.

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

option(ENABLE_OPENMP "Enable OpenMP (link if available)" ON)
# Use imported OpenMP targets when present; don’t hard-fail if missing
if(ENABLE_OPENMP)
    find_package(OpenMP QUIET)
else()
    set(OpenMP_CXX_FOUND OFF)
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

set(GIT_DESCRIBE "")
set(_GIT_DIFF_RESULT 0)
if(Git_FOUND)
    # Prefer semver-like tags (v*) and include commit metadata when available
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --long --dirty --match "v*"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_DESCRIBE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

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
            if(NOT _GIT_DIFF_RESULT EQUAL 0 AND NOT _GIT_DIFF_RESULT EQUAL 128)
                set(GIT_DESCRIBE "${GIT_DESCRIBE}-dirty")
            endif()
        endif()
    endif()
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
        # Use MSVC defaults or set /Od /Zi if needed
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi /Od")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Zi /Od")
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
        set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto=thin -DNDEBUG")
        set(CMAKE_C_FLAGS_RELEASE "-O3 -flto=thin -DNDEBUG")
        set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-fuse-ld=lld")
    elseif(MSVC)
        # Enhanced MSVC optimization flags
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Ob2 /DNDEBUG")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /Ob2 /DNDEBUG")
        # Enable function-level linking for better optimization
        set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /OPT:REF /OPT:ICF")
    endif()
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
    ${CMAKE_CURRENT_SOURCE_DIR}/external/http_client/src/json_util.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/external/http_client/src/misc_util.cpp
)

list(APPEND APP_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/install_config_manager.cpp
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
    )

if(OpenMP_CXX_FOUND)
    target_link_libraries(${CERT_CTRL_APP_NAME} PRIVATE OpenMP::OpenMP_CXX)
    message(STATUS "OpenMP enabled: using OpenMP::OpenMP_CXX")
else()
    message(STATUS "OpenMP not found or disabled; proceeding without OpenMP")
endif()

# Add tests subdirectory
add_subdirectory(tests)
