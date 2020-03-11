zephyr_interface_library_named(cozy)
set(WITH_ZEPHYR 1)
set(WITH_ZEPHYR_LIB 1)
target_include_directories(cozy INTERFACE include)

add_definitions( 
    -DNANOCBOR_BYTEORDER_HEADER=<sys/byteorder.h>
    -DNANOCBOR_BE64TOH_FUNC=sys_be64_to_cpu
    -DNANOCBOR_HTOBE64_FUNC=sys_cpu_to_be64
    -DNANOCBOR_HTOBE32_FUNC=sys_cpu_to_be32 
    )

zephyr_library()
zephyr_library_sources(
    src/sign.c
    src/encrypt.c
    src/mac.c
    src/common.c
    NanoCBOR/src/decoder.c
    NanoCBOR/src/encoder.c
    )
zephyr_library_link_libraries(cozy)
zephyr_include_directories(include NanoCBOR/include)

target_link_libraries(cozy INTERFACE 
    zephyr_interface
    mbedTLS
    )
