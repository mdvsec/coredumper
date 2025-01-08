cmake_minimum_required(VERSION 3.10)

if (NOT UNIX)
    message(FATAL_ERROR "This project only supports Linux aarch64 platform.\n")
endif()

execute_process(
    COMMAND uname -s
    OUTPUT_VARIABLE OS_TYPE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE ARCH_TYPE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if (NOT OS_TYPE MATCHES "Linux" OR NOT ARCH_TYPE MATCHES "aarch64")
    message(FATAL_ERROR "This project only supports Linux aarch64 platform.\n"
            "Current OS: ${OS_TYPE}\n"
            "Current architecture: ${ARCH_TYPE}\n")
endif()

project(memdumper C CXX)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${PROJECT_SOURCE_DIR}/include)

file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/src/*.c")

add_executable(memdumper ${SOURCES})

# Set default build type to Release if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type (Debug, Release)" FORCE)
endif()

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    add_compile_definitions(DEBUG_MODE)
    target_compile_options(memdumper PRIVATE -Wall -Wextra -pedantic -g -O0)
else()
    target_compile_options(memdumper PRIVATE -Wall -Wextra -pedantic -O3)
endif()

# Use GoogleTest framework for testing 
enable_testing()

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG main
)
FetchContent_MakeAvailable(googletest)

file(GLOB TEST_SOURCES "${PROJECT_SOURCE_DIR}/tests/*.cc")
if (TEST_SOURCES)
    add_executable(memdumper_tests ${TEST_SOURCES})

    target_link_libraries(memdumper_tests GTest::gtest_main)

    include(GoogleTest)
    gtest_discover_tests(memdumper_tests)
endif()
