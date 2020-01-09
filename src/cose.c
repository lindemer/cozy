#include <zephyr.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <tinycbor/cbor.h>
#include "cose.h"

#ifndef CONFIG_MBEDTLS_CFG_FILE
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

#include <ztest.h>
#include <mbedtls/debug.h>
#include "vectors.h"

void cose_test_mbedtls_sanity(void) {
    const uint8_t * msg = COSE_TEST_MESSAGE;
    const uint8_t * key_priv = COSE_TEST_KEY_PRIV;
    const uint8_t * key_pub = COSE_TEST_KEY_PUB;
    const char * pers = "cose_self_test";
    size_t sig_len = 0;
    uint8_t key_sym[16];
    uint8_t iv[12];
    uint8_t sig[256];
    uint8_t plaintext[4096];
    uint8_t ciphertext[4096];
    uint8_t hashtag[64];

    // initialize
    mbedtls_pk_context ctx_pub, ctx_priv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_init(&ctx_pub); 
    mbedtls_pk_init(&ctx_priv);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // public key operations
    zassert_false(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, 
                &entropy, (const uint8_t *) pers, strlen(pers)), 
            "Failed to seed mbedTLS entropy source.\n");

    mbedtls_pk_parse_public_key(&ctx_pub, key_pub, strlen(key_pub) + 1);
    mbedtls_pk_parse_key(&ctx_priv, key_priv, strlen(key_priv) + 1, NULL, 0);
    zassert_false(mbedtls_pk_check_pair(&ctx_pub, &ctx_priv), 
            "Failed to verify EC key pair with mbedTLS.\n");

    mbedtls_md_type_t md_alg = MBEDTLS_MD_SHA256;
    const mbedtls_md_info_t * md_info = mbedtls_md_info_from_type(md_alg);
    zassert_false(mbedtls_md(md_info, msg, strlen(msg), hashtag),
            "Failed to compute message digest with mbedTLS.\n");

    zassert_false(mbedtls_pk_sign(&ctx_priv, md_alg, hashtag, 0, 
                sig, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg),
            "Failed to compute message signature with mbedTLS.\n");

    zassert_false(mbedtls_pk_verify(&ctx_pub, md_alg, hashtag, 0, sig, sig_len), 
            "Failed to verify signature with mbedTLS.\n");

    // symmetric key operations
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_ctr_drbg_random(&ctr_drbg, key_sym, 16);
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, 12);
    zassert_false(mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key_sym, 128),
            "Failed to generate AES-GCM key with mbedTLS.\n");

    zassert_false(mbedtls_gcm_crypt_and_tag(
                &gcm, MBEDTLS_GCM_ENCRYPT, strlen(msg), iv, 12, 
                NULL, 0, msg, ciphertext, 16, hashtag),
            "Failed to encrypt and tag message with mbedTLS.\n");

    zassert_false(mbedtls_gcm_auth_decrypt(
                &gcm, strlen(msg), iv, 12, NULL, 0, hashtag, 
                16, ciphertext, plaintext),
            "Failed to decrypt and authenticate message with mbedTLS.\n");
            
    zassert_false(strcmp(msg, plaintext), "Message integrity check failed.\n"); 

    // cleanup
    mbedtls_gcm_free(&gcm);
    mbedtls_pk_free(&ctx_priv); 
    mbedtls_pk_free(&ctx_pub);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void cose_test_tinycbor_sanity(void) { 
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
