#define COSE_SELF_TEST
#ifdef COSE_SELF_TEST

#include <ztest.h>
#include "cose.h"
#include "test_vectors.h"

const uint8_t * pld = COSE_TEST_PLD;
const uint8_t * aad = COSE_TEST_AAD;
const uint8_t kid[] = {0xC0, 0x53};
uint8_t obj[4096];
uint8_t out[4096];
size_t len_obj;
size_t len_out;

void cose_test_sign1_write(void) {
    const uint8_t * key = COSE_TEST_KEY_384_PRIV;

    size_t len_pld = strlen(pld);
    size_t len_aad = strlen(aad);
    len_obj = sizeof(obj);

    cose_sign_context ctx;
    zassert_false(cose_sign_init(&ctx, key, strlen(key), kid, sizeof(kid)), 
            "Failed to initialize COSE signing context.\n");

    zassert_false(cose_sign1_write(&ctx, 
                pld, len_pld, aad, len_aad, obj, &len_obj), 
            "Failed to sign COSE object.\n"); 

    cose_sign_free(&ctx);
}

void cose_test_sign1_read(void) {
    const uint8_t * key = COSE_TEST_KEY_384_PUB;
    
    size_t len_aad = strlen(aad);
    size_t len_out = sizeof(out);
    
    cose_verify_context ctx;
    zassert_false(cose_verify_init(&ctx, key, strlen(key), kid, sizeof(kid)), 
            "Failed to initialize COSE verification context.\n");

    zassert_false(cose_sign1_read(&ctx, 
                obj, len_obj, aad, len_aad, out, &len_out), 
            "Failed to authenticate signature.\n"); 

    zassert_false(strcmp(out, pld),
            "Failed to decode payload.\n");

    cose_verify_free(&ctx);
}

void cose_test_encrypt0_write(void) {
    const uint8_t key[32] = COSE_TEST_KEY_256_SYM;
    const uint8_t iv[12] = COSE_TEST_KEY_IV;

    size_t len_pld = strlen(pld);
    size_t len_aad = strlen(aad);
    len_obj = sizeof(obj);

    cose_crypt_context ctx;
    zassert_false(cose_crypt_init(&ctx, key, sizeof(key), kid, sizeof(kid)),
            "Failed to initialize COSE encryption context.\n");

    zassert_false(cose_encrypt0_write(&ctx, 
                pld, len_pld, aad, len_aad, iv, sizeof(iv), obj, &len_obj), 
            "Failed to encrypt COSE object.\n"); 

    cose_crypt_free(&ctx);
}

void cose_test_encrypt0_read(void) {
    const uint8_t key[32] = COSE_TEST_KEY_256_SYM;
    const uint8_t iv[12] = COSE_TEST_KEY_IV;

    size_t len_aad = strlen(aad);
    size_t len_out = sizeof(out);

    cose_crypt_context ctx;
    zassert_false(cose_crypt_init(&ctx, key, sizeof(key), kid, sizeof(kid)),
            "Failed to initialize COSE encryption context.\n");

    zassert_false(cose_encrypt0_read(&ctx, 
                obj, len_obj, aad, len_aad, iv, sizeof(iv), out, &len_out), 
            "Failed to decrypt payload.\n"); 

    zassert_false(strcmp(out, pld),
            "Failed to decode payload.\n");

    zassert_false(0, ""); 
}

#endif
