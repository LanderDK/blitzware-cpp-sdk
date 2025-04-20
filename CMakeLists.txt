cmake_minimum_required(VERSION 3.15)
project(MySDK VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optionally allow building examples/tests
option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TESTS    "Build unit tests"    ON)

# Define library target
add_library(blitzware-cpp-sdk
    BlitzWareAuthManager.cpp
    # add other source files here
)

target_include_directories(blitzware-cpp-sdk
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Installation rules
install(TARGETS blitzware-cpp-sdk
    EXPORT blitzware-cpp-sdkTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include)

install(EXPORT blitzware-cpp-sdkTargets
    FILE MySDKConfig.cmake
    NAMESPACE blitzware-cpp-sdk::
    DESTINATION lib/cmake/blitzware-cpp-sdk
)

# Examples
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
