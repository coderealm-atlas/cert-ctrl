cmake_minimum_required(VERSION 3.16)

# Enable testing if not already
include(CTest)

# Only add tests when testing is enabled
if(NOT BUILD_TESTING)
  return()
endif()

find_package(GTest CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options json)
find_package(fmt CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)

add_executable(test_program_options test_program_options.cpp)
target_compile_features(test_program_options PRIVATE cxx_std_20)
target_include_directories(test_program_options PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/http_client/include
)
target_link_libraries(test_program_options PRIVATE
  GTest::gtest_main
  Boost::program_options
  Boost::json
  fmt::fmt
  protobuf::libprotobuf
)

include(GoogleTest)
gtest_discover_tests(test_program_options)
