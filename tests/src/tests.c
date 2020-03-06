/*
 * Copyright (c) 2020, RISE Research Institutes of Sweden
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Samuel Tanner Lindemer
 * <samuel.lindemer@ri.se>
 */

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
    cose_entropy_context ent;

    zassert_false(cose_sign_init(&ctx, &ent, key, strlen(key), kid, sizeof(kid)),
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
    
    cose_sign_context ctx;

    zassert_false(cose_sign_init(&ctx, NULL, key, strlen(key), kid, sizeof(kid)), 
            "Failed to initialize COSE signing context.\n");

    zassert_false(cose_sign_read(&ctx, 
                obj, len_obj, aad, len_aad, out, &len_out), 
            "Failed to authenticate signature.\n"); 

    zassert_false(memcmp(out, pld, strlen(pld)),
            "Failed to decode payload.\n");

    cose_sign_free(&ctx);
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
