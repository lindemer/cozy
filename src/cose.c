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

#define COSE_SELF_TEST

#ifndef CONFIG_MBEDTLS_CFG_FILE
#include "mbedtls/config.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif

int cose_sign_get_alg(cose_sign_context * ctx) {
    mbedtls_pk_type_t pk_type = mbedtls_pk_get_type(&ctx->pk);
    if (pk_type == MBEDTLS_PK_ECKEY) { 
        size_t bitlen = mbedtls_pk_get_bitlen(&ctx->pk);
        if (bitlen == 256) {
            ctx->alg = cose_alg_ecdsa_sha_256;
            ctx->md_alg = MBEDTLS_MD_SHA256;
        } else if (bitlen == 384) {
            ctx->alg = cose_alg_ecdsa_sha_384;
            ctx->md_alg = MBEDTLS_MD_SHA384;
        } else if (bitlen == 512) {
            ctx->alg = cose_alg_ecdsa_sha_512;
            ctx->md_alg = MBEDTLS_MD_SHA512;
        } else return COSE_ERROR;
        return 0;
    } else return COSE_ERROR;
}

int cose_sign_init(cose_sign_context * ctx) {
    mbedtls_pk_init(&ctx->pk);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    if (mbedtls_ctr_drbg_seed(
                &ctx->ctr_drbg, mbedtls_entropy_func, 
                &ctx->entropy, COSE_ENTROPY_SEED, 
                strlen(COSE_ENTROPY_SEED)))
        return COSE_ERROR;
    return 0;
}

int cose_sign_free(cose_sign_context * ctx) {
    mbedtls_pk_free(&ctx->pk);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    return 0;
}

int cose_sign1_encode(cose_sign_context * ctx, 
        const uint8_t * msg, size_t ilen, 
        uint8_t * buf, size_t * olen) {    

    uint8_t hash[64];
    uint8_t sig[128];
    size_t temp;

    // get the signing algorithm
    if (cose_sign_get_alg(ctx)) return COSE_ERROR;

    // data to be signed is written to buf as an intermediate step
    CborEncoder encoder, array_encoder, map_encoder;
    cbor_encoder_init(&encoder, buf, *olen, 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 4);
    cbor_encode_text_string(&array_encoder, COSE_CONTEXT_SIGN1, strlen(COSE_CONTEXT_SIGN1));
    cbor_encoder_create_map(&array_encoder, &map_encoder, 0);
    cbor_encoder_close_container(&array_encoder, &map_encoder);
    cbor_encode_byte_string(&encoder, NULL, 0);
    cbor_encode_byte_string(&encoder, msg, ilen);
    cbor_encoder_close_container(&encoder, &array_encoder);
    temp = cbor_encoder_get_buffer_size(&encoder, buf);

    // compute message digest
    if (mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), buf, temp, hash)) 
        return COSE_ERROR;

    // compute signature
    if (mbedtls_pk_sign(&ctx->pk, ctx->md_alg, sig, 0, hash, &temp, 
                mbedtls_ctr_drbg_random, &ctx->ctr_drbg)) 
        return COSE_ERROR;

    cbor_encoder_init(&encoder, buf, *olen, 0);
    // TODO: package signature into final COSE object

    return 0;
}

// The remainder of this file contains unit tests.
#ifdef COSE_SELF_TEST

#include <ztest.h>
#include <mbedtls/debug.h>
#include "vectors.h"

void cose_test_mbedtls_sanity(void) {
    const uint8_t * msg = COSE_TEST_MESSAGE;
    const uint8_t * key_priv = COSE_TEST_KEY_PRIV;
    const uint8_t * key_pub = COSE_TEST_KEY_PUB;
    size_t sig_len = 0;
    uint8_t key_sym[16];
    uint8_t iv[12];
    uint8_t sig[256];
    uint8_t plaintext[4096];
    uint8_t ciphertext[4096];
    uint8_t hashtag[64];

    // initialization
    mbedtls_pk_context ctx_pub, ctx_priv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_init(&ctx_pub); 
    mbedtls_pk_init(&ctx_priv);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // public key operations
    zassert_false(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, 
                &entropy, (const uint8_t *) COSE_ENTROPY_SEED, strlen(COSE_ENTROPY_SEED)), 
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

void cose_test_sign1(void) { 
    const uint8_t * msg = COSE_TEST_MESSAGE;
    size_t ilen = strlen(msg);
    uint8_t buffer[256];
    size_t olen;

    cose_sign_context ctx;
    zassert_false(cose_sign_init(&ctx), 
            "Failed to initialize COSE signing context.\n");

    const uint8_t * key = COSE_TEST_KEY_PRIV;
    zassert_false(mbedtls_pk_parse_key(&ctx.pk, key, strlen(key) + 1, NULL, 0),
            "Failed to parse key with mbedTLS.\n");

    zassert_false(cose_sign1_encode(&ctx, msg, ilen, buffer, &olen), 
            "Failed to encode COSE Sign1 object.\n"); 

    cose_sign_free(&ctx);
}

#endif
