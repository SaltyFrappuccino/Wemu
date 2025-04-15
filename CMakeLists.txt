cmake_minimum_required(VERSION 3.10)

project(Wemu VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(EXECUTABLE_NAME wemu)

include_directories(include)

file(GLOB SOURCES "src/*.cpp")

add_executable(${EXECUTABLE_NAME} ${SOURCES})

# set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

message(STATUS "Project Name: ${PROJECT_NAME}")
message(STATUS "Executable Name: ${EXECUTABLE_NAME}")
message(STATUS "Sources: ${SOURCES}") 