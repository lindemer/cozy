#include "cose.h"
#include "encode.h"

int cose_sign_init(cose_sign_context * ctx,
        const uint8_t * key, size_t len_key,
        const uint8_t * kid, size_t len_kid) 
{
    mbedtls_pk_init(&ctx->key.pk);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    if (mbedtls_ctr_drbg_seed(
                &ctx->ctr_drbg, mbedtls_entropy_func, 
                &ctx->entropy, COSE_ENTROPY_SEED, 
                strlen(COSE_ENTROPY_SEED)))
        return COSE_ERROR;
    if (mbedtls_pk_parse_key(&ctx->key.pk, key, len_key + 1, NULL, 0)) 
        return COSE_ERROR;
    ctx->key.len_id = len_kid;
    memcpy(ctx->key.id, kid, len_kid);
    return 0;
}

int cose_verify_init(cose_verify_context * ctx,
        const uint8_t * key, size_t len_key,
        const uint8_t * kid, size_t len_kid) 
{
    mbedtls_pk_init(&ctx->key.pk);
    if (mbedtls_pk_parse_public_key(&ctx->key.pk, key, len_key + 1))
        return COSE_ERROR;
    ctx->key.len_id = len_kid;
    memcpy(ctx->key.id, kid, len_kid);
    return 0;
}

int cose_crypt_init(cose_crypt_context * ctx,
        const uint8_t * key, size_t len_key,
        const uint8_t * kid, size_t len_kid) 
{
    mbedtls_gcm_init(&ctx->key.gcm);
    mbedtls_gcm_setkey(&ctx->key.gcm, MBEDTLS_CIPHER_ID_AES, key, len_key * 8);
    ctx->key.len_id = len_kid;
    memcpy(ctx->key.id, kid, len_kid);
    return 0;
}

int cose_sign_free(cose_sign_context * ctx) 
{
    mbedtls_pk_free(&ctx->key.pk);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    return 0;
}

int cose_verify_free(cose_verify_context * ctx) 
{
    mbedtls_pk_free(&ctx->key.pk);
    return 0;
}

int cose_crypt_free(cose_crypt_context * ctx) 
{
    mbedtls_gcm_free(&ctx->key.gcm);
    return 0;
}

int cose_sign1_write(cose_sign_context * ctx, 
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        uint8_t * obj, size_t * len_obj) 
{

    size_t len_temp = *len_obj;
    uint8_t hash[128];
    uint8_t sig[384];

    if (cose_sign_get_alg(&ctx->key)) 
        return COSE_ERROR;

    if (cose_sign_encode_tbs(pld, len_pld, aad, len_aad, obj, &len_temp)) 
        return COSE_ERROR;

    if (mbedtls_md(mbedtls_md_info_from_type(ctx->key.md_alg), obj, len_temp, hash)) 
        return COSE_ERROR;

    if (mbedtls_pk_sign(&ctx->key.pk, ctx->key.md_alg, hash, 0, sig, &len_temp, 
                mbedtls_ctr_drbg_random, &ctx->ctr_drbg)) 
        return COSE_ERROR;

    if (cose_sign_encode_final(&ctx->key, pld, len_pld, aad, len_aad, 
                sig, len_temp, obj, len_obj))
        return COSE_ERROR;

    return 0;
}

int cose_sign1_read(cose_verify_context * ctx, 
        const uint8_t * obj, size_t len_obj, 
        const uint8_t * aad, size_t len_aad,
        uint8_t * pld, size_t * len_pld) 
{

    size_t len_temp = *len_pld;
    size_t len_sig;
    uint8_t sig[384];
    uint8_t hash[128];

    if (cose_sign_get_alg(&ctx->key)) 
        return COSE_ERROR;

    if (cose_sign_decode_obj(obj, len_obj, aad, len_aad, pld, &len_temp, sig, &len_sig))
        return COSE_ERROR;

    if (mbedtls_md(mbedtls_md_info_from_type(ctx->key.md_alg), pld, len_temp, hash)) 
        return COSE_ERROR;

    if (mbedtls_pk_verify(&ctx->key.pk, ctx->key.md_alg, hash, 0, sig, len_sig))
        return COSE_ERROR;

    if (cose_sign_decode_pld(obj, len_obj, pld, len_pld)) 
        return COSE_ERROR;

    return 0;
}

int cose_encrypt0_write(cose_crypt_context *ctx,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        const uint8_t * iv, size_t len_iv,
        uint8_t * obj, size_t * len_obj) 
{

    return 0;
}

int cose_encrypt0_read(cose_crypt_context * ctx,
        const uint8_t * obj, size_t len_obj, 
        const uint8_t * aad, size_t len_aad,
        const uint8_t * iv, size_t len_iv,
        uint8_t * pld, size_t * len_pld) 
{

    return 0;
}

