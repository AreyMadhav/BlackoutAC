# GUIInstaller/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(GUIInstaller)

set(CMAKE_CXX_STANDARD 17)

# Add source files
set(SOURCES
    src/MainInstaller.cpp
    src/MainInstaller.h
)

# Include directories (if needed)
include_directories(src)

# Add the executable
add_executable(GUIInstaller ${SOURCES})

# Link any libraries needed
target_link_libraries(GUIInstaller <list_of_libraries>)
