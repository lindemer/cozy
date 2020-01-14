# cozy
**cozy** can be linked as an external module to any Zephyr app. This library is built on [mbedTLS](https://github.com/zephyrproject-rtos/mbedtls) and [TinyCBOR](https://github.com/zephyrproject-rtos/tinycbor).

## Current Coverage of RFC 8152
* Encode/decode COSE Sign objects with single signer
* Encode/decode COSE Encrypt0 objects
* EC signature algorithms: NIST P-256, NIST P-384
* AEAD algorithms: AES-GCM 128, AES-GCM 192, AES-GCM 256

## Usage
Add the following line to your app's `CMakeLists.txt`:

    set(ZEPHYR_EXTRA_MODULES <absolute_path_to>/cozy)

Add the following line to your app's `prj.conf` to compile the required mbedTLS sources:

    CONFIG_MBEDTLS_CFG_FILE="config-suite-b.h"

Access the **cozy** API from your source files with `#include <cozy/cose.h>`.

## Tests and Examples
Run tests from the `tests` directory with `west build -t run -b native_posix`. See unit tests in `tests/src/tests.c` for examples. The `tests/CMakeLists.txt` assumes that this repository has been cloned to `$ZEPHYR_BASE/..` (i.e., the directory containing your `.west` file).

## Project Roadmap
* Support for ECDH key agreement algorithms
* Support for countersignatures
* Support for NSA Suite B algorithms listed in [RFC 6460](https://tools.ietf.org/html/rfc6460)
* Full coverage of COSE specfication described in [RFC 8152](https://tools.ietf.org/html/rfc8152)
