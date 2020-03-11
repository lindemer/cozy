# Cozy
**Cozy** can be linked as an external module to any Zephyr app. This library is built on [mbedTLS](https://github.com/zephyrproject-rtos/mbedtls) and [NanoCBOR](https://github.com/bergzand/NanoCBOR).

## Current coverage of RFC 8152
* Encode/decode COSE Sign objects with single signer
* Encode/decode COSE Encrypt0 objects
* EC signature algorithms: NIST P-256, NIST P-384
* AEAD algorithms: AES-GCM 128, AES-GCM 192, AES-GCM 256

## Usage
Add the following line to your app's `CMakeLists.txt`:

    set(ZEPHYR_EXTRA_MODULES <absolute_path_to>/cozy)

Add the following line to your app's `prj.conf`:

    CONFIG_COZY=y

Access the **Cozy** API from your source files with `#include <cozy/cose.h>`.

## Tests and examples
Run `west build -t run -b native_posix` from the `tests` directory. See `tests/src/tests.c` for examples.
 
## Project roadmap
* Support for ECDH key agreement algorithms
* Support for countersignatures
* Support for NSA Suite B algorithms listed in [RFC 6460](https://tools.ietf.org/html/rfc6460)
* Full coverage of COSE specfication described in [RFC 8152](https://tools.ietf.org/html/rfc8152)
