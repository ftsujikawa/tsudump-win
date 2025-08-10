# Minimum required version of CMake
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(Tsudump VERSION 1.0)

# Specify the C standard (use C99 for mixed declarations)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Set build type to Debug by default
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (default Debug)" FORCE)
endif()

# Add compile options (MSVC: Shift-JIS)
if(MSVC)
    # Use Shift-JIS for source/execution charset
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

# --- PDB generation settings (MSVC) ---
if(MSVC)
    # Ensure compiler emits debug info for Debug and RelWithDebInfo
    target_compile_options(tsudump PRIVATE
        /FS
        $<$<CONFIG:Debug>:/Zi>
        $<$<CONFIG:RelWithDebInfo>:/Zi>
        $<$<CONFIG:Debug>:/Fd${CMAKE_BINARY_DIR}/$<CONFIG>/tsudump_cl.pdb>
        $<$<CONFIG:RelWithDebInfo>:/Fd${CMAKE_BINARY_DIR}/$<CONFIG>/tsudump_cl.pdb>
    )

    # Instruct linker to produce PDB
    target_link_options(tsudump PRIVATE
        $<$<CONFIG:Debug>:/DEBUG:FULL>
        $<$<CONFIG:RelWithDebInfo>:/DEBUG:FULL>
    )

    # Place PDB next to the built binary under the configuration folder
    set_target_properties(tsudump PROPERTIES
        PDB_NAME "tsudump"
        PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
        OUTPUT_NAME "tsudump"
    )
endif()