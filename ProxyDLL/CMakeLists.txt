# Set the minimum required version for CMake
cmake_minimum_required(VERSION 3.10)

# Define the project name and type
project(ProxyDLL)

# Set the output directory for the build
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/libs")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/libs")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Include the header file directory
include_directories(${CMAKE_SOURCE_DIR})

# Find all .cpp files in the directory
file(GLOB SOURCES "*.cpp")

# Define the DLL output name
add_library(ProxyDLL SHARED ${SOURCES})

# If there are any other required flags (e.g., for Windows, Linux, etc.), they can be added here
if(MSVC)
    target_compile_definitions(ProxyDLL PRIVATE -D_USRDLL -D_AFXDLL)
    target_compile_options(ProxyDLL PRIVATE /EHsc)
endif()

# For additional external libraries, link them here
# example: target_link_libraries(ProxyDLL PRIVATE external_library)

# Specify the required C++ standard
set_target_properties(ProxyDLL PROPERTIES CXX_STANDARD 17)
