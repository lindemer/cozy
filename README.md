# cozy
This is very much a work in progress. See unit tests in `src/unit_tests.c` for examples. This library is built on [mbedTLS](https://github.com/zephyrproject-rtos/mbedtls) and [TinyCBOR](https://github.com/zephyrproject-rtos/tinycbor). Run tests from the app directory using `west build -t run -b native_posix`.

## Project Roadmap
* Support for COSE signing with ECDSA keys.
* Support for COSE encryption and MAC with AES-GCM.
* Full coverage of [RFC 8152](https://tools.ietf.org/html/rfc8152)
* Optimize for memory footprint.
* Integrate with the Zephyr project as an external module.

Contributions welcome!
