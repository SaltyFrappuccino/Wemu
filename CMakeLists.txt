cmake_minimum_required(VERSION 3.10)

project(Wemu VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(EXECUTABLE_NAME wemu)

# Добавляем директорию с заголовочными файлами
include_directories(include)

# Находим все исходные файлы в директории src
file(GLOB SOURCES "src/*.cpp")

# Создаем исполняемый файл
add_executable(${EXECUTABLE_NAME} ${SOURCES})

# TODO: Можно добавить опции сборки для Debug/Release.
# set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

message(STATUS "Project Name: ${PROJECT_NAME}")
message(STATUS "Executable Name: ${EXECUTABLE_NAME}")
message(STATUS "Sources: ${SOURCES}") 