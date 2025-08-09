# Minimum required version of CMake
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(Tsudump VERSION 1.0)

# Specify the C standard (C90 for compatibility)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED True)

# Set build type to Debug by default
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (default Debug)" FORCE)
endif()

# Add compile options for debugging and UTF-8 support
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Zi /utf-8")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /utf-8")

# Add the executable or library
add_executable(tsudump main.c)
# If tsudump is a library, you might want to use add_library instead
# add_library(tsudump src1.c src2.c ...)
