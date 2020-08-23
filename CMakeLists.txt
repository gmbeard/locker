cmake_minimum_required(VERSION 3.17)

project(locker
    LANGUAGES CXX
    VERSION 0.1.0
)

option(
    LOCKER_ENABLE_TESTS
    "Enable tests for ${PROJECT_NAME}"
    OFF
)

add_library(
    locker-obj
    OBJECT
    src/crypt.cpp
    src/fs.cpp
    src/keys
    src/io.cpp
    src/init.cpp
    src/locker.cpp
)

target_include_directories(
    locker-obj
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_compile_features(
    locker-obj
    PUBLIC
    cxx_std_20
)

target_compile_options(
    locker-obj
    PUBLIC
    -fconcepts
)

target_compile_options(
    locker-obj
    PUBLIC
    -Wall -Werror -Wextra -Wconversion -pedantic
    $<$<STREQUAL:${CMAKE_BUILD_TYPE},Debug>:-g -O0>
)

target_link_libraries(
    locker-obj
    PRIVATE
    stdc++fs
    crypto
)

add_executable(
    locker
    src/main.cpp
)

target_link_libraries(
    locker
    PRIVATE
    locker-obj
)

if(LOCKER_ENABLE_TESTS)
    list(
        APPEND 
        CMAKE_MODULE_PATH 
        ${PROJECT_SOURCE_DIR}/dependencies/testy-mctest-face/cmake
    )
    enable_testing()
    include(Testy)
    add_subdirectory(tests)
endif()
