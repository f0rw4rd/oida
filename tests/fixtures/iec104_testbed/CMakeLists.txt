cmake_minimum_required(VERSION 3.10)
project(iec104_test_server C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2")

# ============================================================================
# Find lib60870
# ============================================================================

# Option 1: System-installed lib60870
find_library(LIB60870_LIBRARY
    NAMES lib60870 60870
    PATHS /usr/local/lib /usr/lib
)

find_path(LIB60870_INCLUDE_DIR
    NAMES cs104_slave.h
    PATHS /usr/local/include /usr/include
    PATH_SUFFIXES lib60870
)

# Option 2: Local lib60870 build (submodule or downloaded)
if(NOT LIB60870_LIBRARY)
    if(EXISTS "${CMAKE_SOURCE_DIR}/lib60870")
        message(STATUS "Using local lib60870 source")
        set(LIB60870_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib60870/lib60870-C")

        # Add lib60870 as subdirectory
        add_subdirectory(${LIB60870_SOURCE_DIR} lib60870-build EXCLUDE_FROM_ALL)

        set(LIB60870_LIBRARY lib60870)
        set(LIB60870_INCLUDE_DIR
            ${LIB60870_SOURCE_DIR}/src/inc/api
            ${LIB60870_SOURCE_DIR}/src/inc/internal
            ${LIB60870_SOURCE_DIR}/src/common/inc
            ${LIB60870_SOURCE_DIR}/src/hal/inc
        )
    endif()
endif()

if(NOT LIB60870_LIBRARY)
    message(FATAL_ERROR "lib60870 not found! Please install it or clone into lib60870/ directory.

To install lib60870:
    git clone https://github.com/mz-automation/lib60870.git
    cd lib60870/lib60870-C
    mkdir build && cd build
    cmake ..
    make
    sudo make install

Or to use as submodule:
    git clone https://github.com/mz-automation/lib60870.git
    ")
endif()

message(STATUS "lib60870 library: ${LIB60870_LIBRARY}")
message(STATUS "lib60870 include: ${LIB60870_INCLUDE_DIR}")

# ============================================================================
# Test Server Executable
# ============================================================================

add_executable(iec104_test_server
    src/iec104_test_server.c
)

target_include_directories(iec104_test_server PRIVATE
    ${LIB60870_INCLUDE_DIR}
)

target_link_libraries(iec104_test_server
    ${LIB60870_LIBRARY}
    pthread
)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS iec104_test_server
    RUNTIME DESTINATION bin
)

install(DIRECTORY data/
    DESTINATION share/iec104_testbed/data
)

# ============================================================================
# Custom targets
# ============================================================================

# Run target
add_custom_target(run
    COMMAND iec104_test_server
    DEPENDS iec104_test_server
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running IEC 104 test server on default port 2404"
)

# Run verbose target
add_custom_target(run-verbose
    COMMAND iec104_test_server --verbose
    DEPENDS iec104_test_server
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running IEC 104 test server with verbose output"
)

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "=== IEC 104 Test Server Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
