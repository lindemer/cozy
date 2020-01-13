# cozy
This is very much a work in progress. See unit tests in `src/tests.c` for examples. This library is built on [mbedTLS](https://github.com/zephyrproject-rtos/mbedtls) and [TinyCBOR](https://github.com/zephyrproject-rtos/tinycbor). Run tests from the app directory using `west build -t run -b native_posix`.

## Project Roadmap
* Support for NSA Suite B algorithms listed in [RFC 6460](https://tools.ietf.org/html/rfc6460)
* Full coverage of COSE specfication described in [RFC 8152](https://tools.ietf.org/html/rfc8152)
* Integration with the Zephyr project as an external module

**Contributions welcome!**
