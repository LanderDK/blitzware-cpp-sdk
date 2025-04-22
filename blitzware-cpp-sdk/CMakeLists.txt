cmake_minimum_required(VERSION 3.10)
project(BlitzWareAuthSDK)

set(CMAKE_CXX_STANDARD 17)

# Add the source files
add_library(BlitzWareAuthSDK STATIC
    BlitzWareAuthManager.cpp
)

# Include header files
target_include_directories(BlitzWareAuthSDK PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
