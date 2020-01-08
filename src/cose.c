#include <zephyr.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/pk.h>
#include <tinycbor/cbor.h>

#if !defined(CONFIG_MBEDTLS_CFG_FILE)
#include "mbedtls/config.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif

#define COSE_SELF_TEST

/*
 *
 * library methods go here ...
 *
 */

#ifdef COSE_SELF_TEST

/*
 *
 * unit tests go here ...
 *
 */  

#include <ztest.h>
#include <mbedtls/debug.h>

#define COSE_TEST_EC_PRIV                                                       \
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                        \
    "MHcCAQEEIKw78CnaOuvcRE7dcngmKcbM6FbB3Ue3wkPYQbu+hNHeoAoGCCqGSM49\r\n"      \
    "AwEHoUQDQgAEAWScYjUwMrXA0gAc/LD6EDmJu7Ob7LzngEVn9HJrj4zGUjELTUYf\r\n"      \
    "Mq2CXK9SpGLX33eRmv9itRcWjWWmqZuh2w==\r\n"                                  \
    "-----END EC PRIVATE KEY-----\r\n"

#define COSE_TEST_EC_PUB                                                        \
    "-----BEGIN PUBLIC KEY-----\r\n"                                            \
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAWScYjUwMrXA0gAc/LD6EDmJu7Ob\r\n"      \
    "7LzngEVn9HJrj4zGUjELTUYfMq2CXK9SpGLX33eRmv9itRcWjWWmqZuh2w==\r\n"          \
    "-----END PUBLIC KEY-----\r\n"

unsigned char * priv = COSE_TEST_EC_PRIV;
unsigned char * pub = COSE_TEST_EC_PUB;
mbedtls_pk_context ctx_pub, ctx_priv;

void cose_test_mbedtls_sanity_check(void) {

    mbedtls_pk_init(&ctx_pub);
    mbedtls_pk_init(&ctx_priv);
    int ret = mbedtls_pk_parse_public_key(&ctx_pub, pub, strlen(pub) + 1);
    if (!ret) ret = mbedtls_pk_parse_key(&ctx_priv, priv, strlen(priv) + 1, NULL, 0);
    zassert_false(ret, "Failed to parse an EC key pair with mbedTLS.\n");

}

void cose_test_tinycbor_sanity_check(void) { 

    uint8_t buf[16];
    CborEncoder encoder, mapEncoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    cbor_encoder_create_map(&encoder, &mapEncoder, 1);
    cbor_encode_text_stringz(&mapEncoder, "foo");
    cbor_encode_boolean(&mapEncoder, 0);
    cbor_encoder_close_container(&encoder, &mapEncoder);
    size_t len = cbor_encoder_get_buffer_size(&encoder, buf);
    zassert_true(len == 6, "Failed to encode a CBOR object with TinyCBOR.\n"); 

}

void cose_test_sign1(void) { zassert_true(1, "Failed to encode COSE Sign1 object.\n"); }

#endif
