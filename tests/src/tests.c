/*
 * Copyright 2020 RISE Research Institutes of Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <ztest.h>
#include <cozy/cose.h>
#include "vectors.h"

const uint8_t * pld = COSE_TEST_PLD;
const uint8_t * aad = COSE_TEST_AAD;
const uint8_t kid[] = {0xC0, 0x53};
uint8_t obj[3072];
uint8_t out[3072];
size_t len_obj;
size_t len_out;

void test_cose_sign_write(void) {
    const uint8_t * pem = COSE_TEST_KEY_384_PRV;
    size_t len_pld = strlen(pld);
    len_obj = sizeof(obj);

    cose_sign_context_t ctx;
    zassert_false(cose_sign_init(&ctx, cose_mode_w, pem),
            "Failed to initialize COSE signing context.\n");

    cose_set_kid(&ctx.key, kid, sizeof(kid));
    cose_set_aad(&ctx.key, aad, strlen(aad));

    zassert_false(cose_sign_write(&ctx, 
                pld, len_pld, obj, &len_obj), 
            "Failed to encode COSE object.\n"); 

    cose_sign_free(&ctx);
}

void test_cose_sign_read(void) {
    const uint8_t * pem = COSE_TEST_KEY_384_PUB;
    uint8_t * dec;
    size_t len_dec;

    cose_sign_context_t ctx;
    zassert_false(cose_sign_init(&ctx, cose_mode_r, pem), 
            "Failed to initialize COSE signing context.\n");

    cose_set_kid(&ctx.key, kid, sizeof(kid));
    cose_set_aad(&ctx.key, aad, strlen(aad));

    zassert_false(cose_sign_read(&ctx, obj, len_obj,  
                (const uint8_t **) &dec, &len_dec), 
            "Failed to authenticate signature.\n"); 

    zassert_false(memcmp(dec, pld, len_dec),
            "Failed to decode payload.\n");

    cose_sign_free(&ctx);
}

void test_cose_encrypt0_write(void) {
    const uint8_t key[16] = COSE_TEST_KEY_128_SYM;
    uint8_t iv[12] = COSE_TEST_IV;
    cose_alg_t alg = cose_alg_aes_gcm_128;

    size_t len_pld = strlen(pld);
    len_obj = sizeof(obj);

    cose_crypt_context_t ctx;
    zassert_false(cose_crypt_init(&ctx, key, alg, iv, sizeof(iv)),
            "Failed to initialize COSE encryption context.\n");

    cose_set_kid(&ctx.key, kid, sizeof(kid));
    cose_set_aad(&ctx.key, aad, strlen(aad));

    zassert_false(cose_encrypt0_write(&ctx, 
                pld, len_pld, obj, &len_obj), 
            "Failed to encode COSE object.\n"); 

    cose_crypt_free(&ctx);
}

void test_cose_encrypt0_read(void) {
    const uint8_t key[16] = COSE_TEST_KEY_128_SYM;
    cose_alg_t alg = cose_alg_aes_gcm_128;
    size_t len_out = sizeof(out);

    cose_crypt_context_t ctx;
    zassert_false(cose_crypt_init(&ctx, key, alg, NULL, 0),
            "Failed to initialize COSE encryption context.\n");
    
    cose_set_kid(&ctx.key, kid, sizeof(kid));
    cose_set_aad(&ctx.key, aad, strlen(aad));

    zassert_false(cose_encrypt0_read(&ctx, 
                obj, len_obj, out, &len_out), 
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
