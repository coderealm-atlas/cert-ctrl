cmake_minimum_required(VERSION 3.16)

# Enable testing if not already
include(CTest)

# Only add tests when testing is enabled
if(NOT BUILD_TESTING)
  return()
endif()

find_package(GTest CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options json asio url uuid process iostreams log log_setup system filesystem thread chrono date_time container)
find_package(fmt CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(test_program_options test_program_options.cpp)
target_compile_features(test_program_options PRIVATE cxx_std_20)
target_include_directories(test_program_options PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
)
target_link_libraries(test_program_options PRIVATE
  GTest::gtest_main
  Boost::program_options
  fmt::fmt
  protobuf::libprotobuf
)
if(APPLE)
  target_link_libraries(test_program_options PRIVATE c++abi)
endif()

# Ensure Boost.JSON actually links (vcpkg/Boost provides Boost::json;
# some environments expose boost_json or require an explicit find_library)
if(TARGET Boost::json)
  target_link_libraries(test_program_options PRIVATE Boost::json)
elseif(TARGET boost_json)
  target_link_libraries(test_program_options PRIVATE boost_json)
else()
  find_library(BOOST_JSON_LIB NAMES boost_json)
  if(BOOST_JSON_LIB)
    target_link_libraries(test_program_options PRIVATE ${BOOST_JSON_LIB})
  endif()
endif()

if(APPLE)
  add_dependencies(test_program_options atomic_stub)
endif()

include(GoogleTest)
gtest_discover_tests(test_program_options DISCOVERY_TIMEOUT 30)

add_executable(test_login_handler_workflow
  test_login_handler_workflow.cpp
  ${CMAKE_SOURCE_DIR}/src/login_handler.cpp
  ${CMAKE_SOURCE_DIR}/src/device_fingerprint.cpp
  ${CMAKE_SOURCE_DIR}/src/openssl_raii.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_login_handler_workflow PRIVATE cxx_std_20)
target_include_directories(test_login_handler_workflow PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
  ${CMAKE_SOURCE_DIR}/external/http_client
)
target_link_libraries(test_login_handler_workflow PRIVATE
  GTest::gtest_main
  Boost::program_options
  Boost::json
  Boost::asio
  Boost::system
  Boost::url
  Boost::uuid
  Boost::process
  Boost::iostreams
  Boost::log
  Boost::log_setup
  MINIZIP::minizip-ng
  jwt-cpp::jwt-cpp
  unofficial-sodium::sodium
  fmt::fmt
  protobuf::libprotobuf
  OpenSSL::SSL
  OpenSSL::Crypto
)
if(APPLE)
  target_link_libraries(test_login_handler_workflow PRIVATE c++abi)
endif()

if(APPLE)
  add_dependencies(test_login_handler_workflow atomic_stub)
endif()

gtest_discover_tests(test_login_handler_workflow)

# Real server integration login test (requires running external server)
add_executable(test_login_real_server
  test_login_real_server.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_login_real_server PRIVATE cxx_std_20)
target_include_directories(test_login_real_server PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include/util
  ${CMAKE_SOURCE_DIR}/external/http_client/include
  ${CMAKE_SOURCE_DIR}/external/http_client
  ${CMAKE_SOURCE_DIR}/tests/include
)
target_link_libraries(test_login_real_server PRIVATE
  GTest::gtest_main
  Boost::program_options
  Boost::json
  Boost::asio
  Boost::system
  Boost::url
  Boost::uuid
  Boost::process
  Boost::iostreams
  fmt::fmt
  OpenSSL::SSL
  OpenSSL::Crypto
  Boost::log
  Boost::log_setup
  unofficial-sodium::sodium
)
if(APPLE)
  target_link_libraries(test_login_real_server PRIVATE c++abi)
endif()

if(APPLE)
  add_dependencies(test_login_real_server atomic_stub)
endif()

gtest_discover_tests(test_login_real_server DISCOVERY_TIMEOUT 60)

# Monadic device registration/login integration test using HttpClientManager + IO monad
add_executable(test_device_registration
  test_device_registration.cpp
  ${CMAKE_SOURCE_DIR}/src/login_handler.cpp
  ${CMAKE_SOURCE_DIR}/src/device_fingerprint.cpp
  ${CMAKE_SOURCE_DIR}/src/openssl_raii.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_device_registration PRIVATE cxx_std_20)
target_include_directories(test_device_registration PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
  ${CMAKE_SOURCE_DIR}/external/http_client
  ${CMAKE_SOURCE_DIR}/tests/include
)
target_link_libraries(test_device_registration PRIVATE
  GTest::gtest_main
  Boost::program_options
  Boost::json
  Boost::asio
  Boost::system
  Boost::url
  Boost::uuid
  Boost::process
  Boost::iostreams
  Boost::log
  Boost::log_setup
  fmt::fmt
  OpenSSL::SSL
  OpenSSL::Crypto
  unofficial-sodium::sodium
)
if(APPLE)
  target_link_libraries(test_device_registration PRIVATE c++abi)
endif()

if(APPLE)
  add_dependencies(test_device_registration atomic_stub)
endif()

gtest_discover_tests(test_device_registration DISCOVERY_TIMEOUT 60)

# Updates polling handler test
add_executable(test_install_config_manager
  test_install_config_manager.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_config_manager.cpp
  ${CMAKE_SOURCE_DIR}/src/secret_util.cpp
  ${CMAKE_SOURCE_DIR}/src/openssl_raii.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_install_config_manager PRIVATE cxx_std_20)
target_include_directories(test_install_config_manager PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
  ${CMAKE_SOURCE_DIR}/external/http_client
)
target_link_libraries(test_install_config_manager PRIVATE
  GTest::gtest_main
  Boost::program_options
  Boost::json
  Boost::asio
  Boost::system
  Boost::url
  Boost::container
  Boost::uuid
  Boost::process
  Boost::iostreams
  Boost::log
  Boost::log_setup
  Boost::filesystem
  Boost::thread
  Boost::chrono
  Boost::date_time
  fmt::fmt
  OpenSSL::SSL
  OpenSSL::Crypto
  unofficial-sodium::sodium
)
if(APPLE)
  target_link_libraries(test_install_config_manager PRIVATE c++abi)
endif()

if(APPLE)
  add_dependencies(test_install_config_manager atomic_stub)
endif()

gtest_discover_tests(test_install_config_manager DISCOVERY_TIMEOUT 30)

add_executable(test_updates_polling_handler
  test_updates_polling_handler.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_config_manager.cpp
  ${CMAKE_SOURCE_DIR}/src/secret_util.cpp
  ${CMAKE_SOURCE_DIR}/src/openssl_raii.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_updates_polling_handler PRIVATE cxx_std_20)
target_include_directories(test_updates_polling_handler PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
  ${CMAKE_SOURCE_DIR}/external/http_client
  ${CMAKE_SOURCE_DIR}/tests/include
)
target_link_libraries(test_updates_polling_handler PRIVATE
  GTest::gtest_main
  Boost::program_options
  Boost::json
  Boost::asio
  Boost::system
  Boost::url
  Boost::container
  Boost::uuid
  Boost::process
  Boost::iostreams
  Boost::log
  Boost::log_setup
  Boost::filesystem
  Boost::thread
  Boost::chrono
  Boost::date_time
  fmt::fmt
  OpenSSL::SSL
  OpenSSL::Crypto
  unofficial-sodium::sodium
)
if(APPLE)
  target_link_libraries(test_updates_polling_handler PRIVATE c++abi)
endif()
if(APPLE)
  add_dependencies(test_updates_polling_handler atomic_stub)
endif()
gtest_discover_tests(test_updates_polling_handler DISCOVERY_TIMEOUT 30)
