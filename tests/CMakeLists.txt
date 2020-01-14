cmake_minimum_required(VERSION 3.13.1)
set(ZEPHYR_EXTRA_MODULES $ENV{ZEPHYR_BASE}/../cozy)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(cose_test)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})

