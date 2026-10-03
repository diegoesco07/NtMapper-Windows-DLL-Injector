cmake_minimum_required(VERSION 3.20)
project(NtMapperPortfolio LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "NtMapper requires a 64-bit Windows toolchain")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(NtMapper main.cpp)
target_include_directories(NtMapper PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(NtMapper PRIVATE comdlg32)

add_executable(NtMapperDemoTarget demo/demo_target.cpp)
add_library(NtMapperDemoPayload SHARED demo/demo_payload.cpp)
set_target_properties(NtMapperDemoTarget NtMapperDemoPayload PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

enable_testing()
add_executable(PeInspectorTests tests/pe_inspector_tests.cpp)
target_include_directories(PeInspectorTests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
add_test(NAME PeInspectorTests COMMAND PeInspectorTests)
