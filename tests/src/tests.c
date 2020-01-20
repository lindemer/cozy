#include <ztest.h>
#include <cozy/cose.h>
#include "vectors.h"

const uint8_t * pld = COSE_TEST_PLD;
const uint8_t * aad = COSE_TEST_AAD;
const uint8_t kid[] = {0xC0, 0x53};
uint8_t obj[4096];
uint8_t out[4096];
size_t len_obj;
size_t len_out;

void test_cose_sign_write(void) {
    const uint8_t * key = COSE_TEST_KEY_384_PRIV;

    size_t len_pld = strlen(pld);
    size_t len_aad = strlen(aad);
    len_obj = sizeof(obj);

    cose_sign_context ctx;
    zassert_false(cose_sign_init(&ctx, key, strlen(key), kid, sizeof(kid)), 
            "Failed to initialize COSE signing context.\n");

    zassert_false(cose_sign_write(&ctx, 
                pld, len_pld, aad, len_aad, obj, &len_obj), 
            "Failed to encode COSE object.\n"); 

    cose_sign_free(&ctx);
}

void test_cose_sign_read(void) {
    const uint8_t * key = COSE_TEST_KEY_384_PUB;
    
    size_t len_aad = strlen(aad);
    size_t len_out = sizeof(out);
    
    cose_verify_context ctx;
    zassert_false(cose_verify_init(&ctx, key, strlen(key), kid, sizeof(kid)), 
            "Failed to initialize COSE verification context.\n");

    zassert_false(cose_sign_read(&ctx, 
                obj, len_obj, aad, len_aad, out, &len_out), 
            "Failed to authenticate signature.\n"); 

    zassert_false(memcmp(out, pld, strlen(pld)),
            "Failed to decode payload.\n");

    cose_verify_free(&ctx);
}

void test_cose_encrypt0_write(void) {
    const uint8_t key[16] = COSE_TEST_KEY_128_SYM;
    const uint8_t iv[12] = COSE_TEST_IV;
    cose_alg alg = cose_alg_aes_gcm_128;

    size_t len_pld = strlen(pld);
    size_t len_aad = strlen(aad);
    len_obj = sizeof(obj);

    cose_crypt_context ctx;
    zassert_false(cose_crypt_init(&ctx, key, alg, NULL, 0),
            "Failed to initialize COSE encryption context.\n");

    zassert_false(cose_encrypt0_write(&ctx, 
                pld, len_pld, aad, len_aad, iv, sizeof(iv), obj, &len_obj), 
            "Failed to encode COSE object.\n"); 

    cose_crypt_free(&ctx);
}

void test_cose_encrypt0_read(void) {
    const uint8_t key[16] = COSE_TEST_KEY_128_SYM;
    cose_alg alg = cose_alg_aes_gcm_128;

    size_t len_aad = strlen(aad);
    size_t len_out = sizeof(out);

    cose_crypt_context ctx;
    zassert_false(cose_crypt_init(&ctx, key, alg, NULL, 0),
            "Failed to initialize COSE encryption context.\n");

    zassert_false(cose_encrypt0_read(&ctx, 
                obj, len_obj, aad, len_aad, out, &len_out), 
            "Failed to decrypt COSE payload.\n"); 

    zassert_false(memcmp(out, pld, strlen(pld)),
            "Failed to decode COSE payload.\n");

    cose_crypt_free(&ctx);
}

void test_cose_mac0_write(void) {
    printk("WARNING - This test has not been implemented.\n");
    zassert_false(0, "");
}

void test_cose_mac0_read(void) {
    printk("WARNING - This test has not been implemented.\n");
    zassert_false(0, ""); 
}
