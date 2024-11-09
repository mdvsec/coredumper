cmake_minimum_required(VERSION 3.10)

project(memdumper C)

include_directories(${PROJECT_SOURCE_DIR}/include)

file(GLOB_RECURSE SOURCES "${PROJECT_SOURCE_DIR}/src/*.c")

add_executable(memdumper ${SOURCES})

# TBD: Add tests
