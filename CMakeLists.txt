cmake_minimum_required(VERSION 3.10)
project(memdumper C CXX)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${PROJECT_SOURCE_DIR}/include)

file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/src/*.c")

add_executable(memdumper ${SOURCES})

target_compile_options(memdumper PRIVATE -Wall -g)

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
