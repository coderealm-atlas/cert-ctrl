cmake_minimum_required(VERSION 3.16)

cmake_policy(SET CMP0104 NEW)
cmake_policy(SET CMP0146 OLD)
cmake_policy(SET CMP0167 NEW)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(bbserver LANGUAGES CXX)

# Interface target to unify Boost.DI constructor parameter limit across all targets
add_library(di_config INTERFACE)
target_compile_definitions(di_config INTERFACE BOOST_DI_CFG_CTOR_LIMIT_SIZE=16)

# Set Clang and LLD as default compilers
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CMAKE_C_COMPILER "clang")
    set(CMAKE_CXX_COMPILER "clang++")
    set(CMAKE_EXE_LINKER_FLAGS "-fuse-ld=lld")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
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

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(OpenMP_CXX_FLAGS "-fopenmp")
    set(OpenMP_CXX_LIB_NAMES "omp")
    set(OpenMP_omp_LIBRARY omp)
endif()

find_package(OpenMP REQUIRED)

set(BUILD_SHARED_LIBS OFF)  # Only build static libraries

if(MSVC)
    # Use dynamic runtime libraries
    # set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MD")
    # set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MDd")
    # Uncomment the following lines to use static runtime libraries instead
    # set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    # set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
endif()

include(cmake/CPM.cmake)

# Enable precompiled headers for faster compilation
set(CMAKE_PCH_ENABLE ON)

find_package(Git REQUIRED)

execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --tags
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_DESCRIBE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/version.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

message(STATUS "*******GIT_DESCRIBE: ${GIT_DESCRIBE}")
message(STATUS "*******CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")

# Check if ENABLE_ASAN is ON
if(ENABLE_ASAN)
    set(ASAN_FLAGS "-fsanitize=address -fno-omit-frame-pointer -g")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ASAN_FLAGS}")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${ASAN_FLAGS}")
    message(STATUS "AddressSanitizer enabled")
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
    set(CMAKE_CXX_FLAGS_DEBUG "-O1 -g1")  # Minimal optimization and debug info
    set(CMAKE_C_FLAGS_DEBUG "-O1 -g1")
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
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto=thin -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -flto=thin -DNDEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-fuse-ld=lld")
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

# file(GLOB_RECURSE APP_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
file(GLOB APP_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

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

if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
  set(CERT_CTRL_APP_NAME cert_ctrl_debug)
else()
  set(CERT_CTRL_APP_NAME cert_ctrl)
endif()

# Try to find Protobuf using CONFIG mode first (vcpkg), then fallback to MODULE mode (system packages)
find_package(Protobuf CONFIG QUIET)
if(NOT Protobuf_FOUND)
    find_package(Protobuf REQUIRED)
endif()
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



option(ENABLE_ASAN "Enable AddressSanitizer" ON)
# Check if ENABLE_ASAN is ON
if(ENABLE_ASAN)
    set(ASAN_FLAGS "-fsanitize=address -fno-omit-frame-pointer -g")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ASAN_FLAGS}")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${ASAN_FLAGS}")
    message(STATUS "AddressSanitizer enabled")
else()
    message(STATUS "AddressSanitizer disabled")
endif()

add_executable(${CERT_CTRL_APP_NAME} 
    ${APP_SOURCES}
    ${HTTP_CLIENT_SRCS}
    ${PROTO_SRCS}
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
    # Use CONFIG mode targets if available, otherwise use MODULE mode targets
    PRIVATE $<IF:$<TARGET_EXISTS:protobuf::libprotoc>,protobuf::libprotoc,${Protobuf_PROTOC_LIBRARIES}>
    PRIVATE $<IF:$<TARGET_EXISTS:protobuf::libprotobuf>,protobuf::libprotobuf,${Protobuf_LIBRARIES}>
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
