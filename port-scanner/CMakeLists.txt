cmake_minimum_required(VERSION 3.15)
project(port-scanner VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /EHsc /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O2)
endif()

# Core static library
add_library(scanner_core STATIC
    src/scanner.cpp
)

target_include_directories(scanner_core PUBLIC
    include
)

find_package(Threads REQUIRED)
target_link_libraries(scanner_core PUBLIC
    Threads::Threads
)

if(WIN32)
    target_link_libraries(scanner_core PUBLIC ws2_32)
endif()

# CLI Executable
add_executable(port_scanner
    src/main.cpp
)

target_link_libraries(port_scanner PRIVATE
    scanner_core
)

# Test Executable
enable_testing()

add_executable(port_scanner_tests
    tests/test_scanner.cpp
)

target_link_libraries(port_scanner_tests PRIVATE
    scanner_core
)

add_test(NAME PortScannerUnitTests COMMAND port_scanner_tests)
