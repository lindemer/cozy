zephyr_interface_library_named(cozy)
set(WITH_ZEPHYR 1)
set(WITH_ZEPHYR_LIB 1)
target_include_directories(cozy INTERFACE include)

zephyr_library()
zephyr_library_sources(
    src/sign.c
    src/encrypt.c
    src/mac.c
    src/shared.c
    )
zephyr_library_link_libraries(cozy)
zephyr_include_directories(include)

target_link_libraries(cozy INTERFACE 
    zephyr_interface
    TINYCBOR
    mbedTLS
    )
