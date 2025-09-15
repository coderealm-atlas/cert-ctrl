# Find OpenMP

find_package(OpenMP REQUIRED)
if(OpenMP_CXX_FOUND)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    message(STATUS "OpenMP found and enabled")
    add_definitions(-DUSE_OPENMP)
endif()

if(OpenMP_CXX_FOUND)
    target_link_libraries(${APPNAME} PUBLIC OpenMP::OpenMP_CXX)
endif()