# cozy
See unit tests in `src/tests.c` for examples. This library is built on [mbedTLS](https://github.com/zephyrproject-rtos/mbedtls) and [TinyCBOR](https://github.com/zephyrproject-rtos/tinycbor). Run tests from the app directory using `west build -t run -b native_posix`.

## Current Coverage of RFC 8152
* Encode/decode COSE Sign objects with single signer
* Encode/decode COSE Encrypt0 objects
* EC signature algorithms: NIST P-256, NIST P-384
* AEAD algorithms: AES-GCM 128, AES-GCM 192, AES-GCM 256

## Project Roadmap
* Support for ECDH key agreement algorithms
* Support for countersignatures
* Support for NSA Suite B algorithms listed in [RFC 6460](https://tools.ietf.org/html/rfc6460)
* Full coverage of COSE specfication described in [RFC 8152](https://tools.ietf.org/html/rfc8152)
* Integration with the Zephyr project as an external module

**Contributions welcome!**
