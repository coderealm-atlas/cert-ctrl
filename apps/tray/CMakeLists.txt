if(NOT WIN32)
    return()
endif()

project(certctrl_tray LANGUAGES CXX)

add_executable(certctrl-tray WIN32
    src/tray_app.cpp
)

target_compile_features(certctrl-tray PRIVATE cxx_std_20)

target_include_directories(certctrl-tray PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(certctrl-tray PRIVATE
    user32
    shell32
    gdi32
    advapi32
)

set_target_properties(certctrl-tray PROPERTIES
    OUTPUT_NAME certctrl-tray
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
