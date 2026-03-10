cmake_minimum_required(VERSION 3.18.1)
project("cyber_guard_security" LANGUAGES CXX)

# Compile with maximum optimization and hide all symbols by default.
# -fvisibility=hidden: Only explicitly exported functions are visible.
# This prevents reverse engineers from seeing internal function names.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -fvisibility=hidden -fvisibility-inlines-hidden")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(
    security_core
    SHARED
    security_core.cpp
    anti_hook.cpp
)

# Android NDK libraries we need:
# - log: __android_log_print for debug logging
# - android: ANativeWindow, AConfiguration, etc.
find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(
    security_core
    ${log-lib}
    ${android-lib}
)
