cmake_minimum_required(VERSION 3.16)

# Enable testing if not already
include(CTest)

# Only add tests when testing is enabled
if(NOT BUILD_TESTING)
  return()
endif()

if(MSVC)
  add_compile_options(/utf-8)

  add_executable(msvc_lambda_capture_probe
    msvc_lambda_capture_probe.cpp
  )
  target_compile_features(msvc_lambda_capture_probe PRIVATE cxx_std_17)

  add_executable(msvc_lambda_capture_error EXCLUDE_FROM_ALL
    msvc_lambda_capture_probe.cpp
  )
  target_compile_features(msvc_lambda_capture_error PRIVATE cxx_std_17)
  target_compile_definitions(msvc_lambda_capture_error PRIVATE PROVOKE_CAPTURE_ERROR)
endif()

find_package(GTest CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options json asio url uuid process iostreams log log_setup system filesystem thread chrono date_time container)
find_package(fmt CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(test_program_options test_program_options.cpp)
target_compile_features(test_program_options PRIVATE cxx_std_17)
target_include_directories(test_program_options PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
)
target_link_libraries(test_program_options PRIVATE
  GTest::gtest_main
  Boost::program_options
  fmt::fmt
  protobuf::libprotobuf
  certctrl_libatomic
  di_config
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

certctrl_use_static_atomic(test_program_options)

include(GoogleTest)

set(TEST_DISCOVERY_TIMEOUT_MEDIUM 120)
set(TEST_DISCOVERY_TIMEOUT_LONG 240)

add_executable(test_boost_di_lifetimes
  test_boost_di_lifetimes.cpp
)
target_compile_features(test_boost_di_lifetimes PRIVATE cxx_std_17)
target_include_directories(test_boost_di_lifetimes PRIVATE
  ${CMAKE_SOURCE_DIR}/external/http_client/include
)
target_link_libraries(test_boost_di_lifetimes PRIVATE
  GTest::gtest_main
  di_config
)

gtest_discover_tests(test_boost_di_lifetimes DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_MEDIUM})

gtest_discover_tests(test_program_options DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_MEDIUM})

add_executable(test_device_fingerprint
  test_device_fingerprint.cpp
  ${CMAKE_SOURCE_DIR}/src/device_fingerprint.cpp
  ${CMAKE_SOURCE_DIR}/src/openssl_raii.cpp
  ${CMAKE_SOURCE_DIR}/src/crypt_util.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_device_fingerprint PRIVATE cxx_std_17)
target_include_directories(test_device_fingerprint PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
  ${CMAKE_SOURCE_DIR}/external/http_client
)
target_link_libraries(test_device_fingerprint PRIVATE
  GTest::gtest_main
  Boost::json
  fmt::fmt
  OpenSSL::SSL
  OpenSSL::Crypto
  certctrl_libatomic
)

certctrl_use_static_atomic(test_device_fingerprint)

gtest_discover_tests(test_device_fingerprint DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_MEDIUM})

add_executable(test_login_handler_workflow
  test_login_handler_workflow.cpp
  ${CMAKE_SOURCE_DIR}/src/login_handler.cpp
  ${CMAKE_SOURCE_DIR}/src/device_fingerprint.cpp
  ${CMAKE_SOURCE_DIR}/src/openssl_raii.cpp
  ${CMAKE_SOURCE_DIR}/src/crypt_util.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_login_handler_workflow PRIVATE cxx_std_17)
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
  certctrl_libatomic
  di_config
)
if(APPLE)
  target_link_libraries(test_login_handler_workflow PRIVATE c++abi)
endif()

if(APPLE)
  add_dependencies(test_login_handler_workflow atomic_stub)
endif()

certctrl_use_static_atomic(test_login_handler_workflow)

gtest_discover_tests(test_login_handler_workflow DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_LONG})

# Real server integration login test (requires running external server)
add_executable(test_login_real_server
  test_login_real_server.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_login_real_server PRIVATE cxx_std_17)
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
  certctrl_libatomic
  di_config
)
if(APPLE)
  target_link_libraries(test_login_real_server PRIVATE c++abi)
endif()

if(APPLE)
  add_dependencies(test_login_real_server atomic_stub)
endif()

certctrl_use_static_atomic(test_login_real_server)

gtest_discover_tests(test_login_real_server DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_LONG})

# Monadic device registration/login integration test using HttpClientManager + IO monad
add_executable(test_device_registration
  test_device_registration.cpp
  ${CMAKE_SOURCE_DIR}/src/login_handler.cpp
  ${CMAKE_SOURCE_DIR}/src/device_fingerprint.cpp
  ${CMAKE_SOURCE_DIR}/src/openssl_raii.cpp
  ${CMAKE_SOURCE_DIR}/src/crypt_util.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_device_registration PRIVATE cxx_std_17)
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
  certctrl_libatomic
  di_config
)
if(APPLE)
  target_link_libraries(test_device_registration PRIVATE c++abi)
endif()

if(APPLE)
  add_dependencies(test_device_registration atomic_stub)
endif()

certctrl_use_static_atomic(test_device_registration)

gtest_discover_tests(test_device_registration DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_LONG})

# Updates polling handler test
add_executable(test_install_config_manager
  test_install_config_manager.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_config_manager.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/copy_action.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/exec_action.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/import_ca_action.cpp
  ${CMAKE_SOURCE_DIR}/src/browser_trust_sync.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/install_resource_materializer.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/materialize_password_manager.cpp
  ${CMAKE_SOURCE_DIR}/src/secret_util.cpp
  ${CMAKE_SOURCE_DIR}/src/openssl_raii.cpp
  ${CMAKE_SOURCE_DIR}/src/crypt_util.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_install_config_manager PRIVATE cxx_std_17)
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
  certctrl_libatomic
  di_config
)
if(WIN32)
  target_link_libraries(test_install_config_manager PRIVATE crypt32)
endif()
if(APPLE)
  target_link_libraries(test_install_config_manager PRIVATE c++abi "-framework Security" "-framework CoreFoundation")
endif()

if(APPLE)
  add_dependencies(test_install_config_manager atomic_stub)
endif()

certctrl_use_static_atomic(test_install_config_manager)

gtest_discover_tests(test_install_config_manager DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_LONG})

add_executable(test_exec_action
  test_exec_action.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/exec_action.cpp
)
target_compile_features(test_exec_action PRIVATE cxx_std_17)
target_include_directories(test_exec_action PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
)
target_link_libraries(test_exec_action PRIVATE
  GTest::gtest_main
  Boost::program_options
  Boost::json
  Boost::log
  Boost::log_setup
  Boost::filesystem
  Boost::thread
  Boost::chrono
  Boost::date_time
  fmt::fmt
  certctrl_libatomic
  di_config
)

certctrl_use_static_atomic(test_exec_action)

gtest_discover_tests(test_exec_action DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_MEDIUM})

add_executable(test_import_ca_action
  test_import_ca_action.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/import_ca_action.cpp
  ${CMAKE_SOURCE_DIR}/src/browser_trust_sync.cpp
  ${CMAKE_SOURCE_DIR}/external/http_client/src/base64.cpp
)
target_compile_features(test_import_ca_action PRIVATE cxx_std_17)
target_include_directories(test_import_ca_action PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
)
target_link_libraries(test_import_ca_action PRIVATE
  GTest::gtest_main
  Boost::log
  Boost::log_setup
  Boost::json
  fmt::fmt
  certctrl_libatomic
  di_config
)
if(WIN32)
  target_link_libraries(test_import_ca_action PRIVATE crypt32)
endif()
if(APPLE)
  target_link_libraries(test_import_ca_action PRIVATE c++abi "-framework Security" "-framework CoreFoundation")
  add_dependencies(test_import_ca_action atomic_stub)
endif()
certctrl_use_static_atomic(test_import_ca_action)

gtest_discover_tests(test_import_ca_action DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_MEDIUM})

add_executable(test_updates_polling_handler
  test_updates_polling_handler.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_config_manager.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/copy_action.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/exec_action.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/import_ca_action.cpp
  ${CMAKE_SOURCE_DIR}/src/browser_trust_sync.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/install_resource_materializer.cpp
  ${CMAKE_SOURCE_DIR}/src/handlers/install_actions/materialize_password_manager.cpp
  ${CMAKE_SOURCE_DIR}/src/secret_util.cpp
  ${CMAKE_SOURCE_DIR}/src/openssl_raii.cpp
  ${CMAKE_SOURCE_DIR}/src/crypt_util.cpp
  ${HTTP_CLIENT_SRCS}
)
target_compile_features(test_updates_polling_handler PRIVATE cxx_std_17)
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
  certctrl_libatomic
  di_config
)
if(WIN32)
  target_link_libraries(test_updates_polling_handler PRIVATE crypt32)
endif()
if(APPLE)
  target_link_libraries(test_updates_polling_handler PRIVATE c++abi "-framework Security" "-framework CoreFoundation")
endif()
if(APPLE)
  add_dependencies(test_updates_polling_handler atomic_stub)
endif()
certctrl_use_static_atomic(test_updates_polling_handler)

gtest_discover_tests(
  test_updates_polling_handler
  DISCOVERY_TIMEOUT ${TEST_DISCOVERY_TIMEOUT_LONG}
  DISCOVERY_PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
