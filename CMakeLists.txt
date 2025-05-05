# Set the minimum required version for CMake
cmake_minimum_required(VERSION 3.10)

# Define the overall project name
project(BlackoutAC)

# Specify the output directories for all build outputs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/libs")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/libs")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Include subdirectories
add_subdirectory(AntiCheatDLL)
add_subdirectory(ProxyDLL)
add_subdirectory(GUIInstaller)
add_subdirectory(GameLoader)
