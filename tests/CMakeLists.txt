cmake_minimum_required(VERSION 3.13.1)
project(cose_test)

get_filename_component(PARENT_DIR ${CMAKE_SOURCE_DIR} DIRECTORY)
set(ZEPHYR_EXTRA_MODULES ${PARENT_DIR})
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})

