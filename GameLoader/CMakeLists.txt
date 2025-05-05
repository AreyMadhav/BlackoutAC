# GameLoader/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(GameLoader)

set(CMAKE_CXX_STANDARD 17)

# Add source files
set(SOURCES
    GameLoader.cpp
)

# Add the executable
add_executable(GameLoader ${SOURCES})

# Link any libraries needed
target_link_libraries(GameLoader <list_of_libraries>)
