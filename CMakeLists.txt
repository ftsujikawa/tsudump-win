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

# Add compile options (MSVC: Shift-JIS)
if(MSVC)
    # Use Shift-JIS (CP932) for source/execution charset
    set(CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG} /Zi /source-charset:shift_jis /execution-charset:shift_jis")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /source-charset:shift_jis /execution-charset:shift_jis")
else()
    # Non-MSVC compilers: no-op (adjust as needed)
endif()

# Find Capstone package
find_package(Capstone REQUIRED)

set(CAPSTONE_INCLUDE_DIRS "C:/Program Files/capstone/include")
set(CAPSTONE_LIBRARIES "C:/Program Files/capstone/lib/capstone.lib")

# Include Capstone directories
include_directories(${CAPSTONE_INCLUDE_DIRS})

# Add the executable or library
add_executable(tsudump main.c)
# If tsudump is a library, you might want to use add_library instead
# add_library(tsudump src1.c src2.c ...)

# Link Capstone library
target_link_libraries(tsudump ${CAPSTONE_LIBRARIES})

message(STATUS "Capstone include directories: ${CAPSTONE_INCLUDE_DIRS}")
message(STATUS "Capstone libraries: ${CAPSTONE_LIBRARIES}")