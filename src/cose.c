#include "cose.h"
#include "encode.h"

int cose_sign_init(cose_sign_context * ctx,
        const uint8_t * key, size_t len_key,
        const uint8_t * kid, size_t len_kid) 
{
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    if (mbedtls_ctr_drbg_seed(
                &ctx->ctr_drbg, mbedtls_entropy_func, 
                &ctx->entropy, COSE_ENTROPY_SEED, 
                strlen(COSE_ENTROPY_SEED)))
        return COSE_ERROR;
    ctx->key.len_kid = len_kid;
    memcpy(ctx->key.kid, kid, len_kid);

    mbedtls_pk_init(&ctx->pk);
    if (mbedtls_pk_parse_key(&ctx->pk, key, len_key + 1, NULL, 0)) 
        return COSE_ERROR;
    if (mbedtls_pk_get_type(&ctx->pk) == MBEDTLS_PK_ECKEY) { 
        if (mbedtls_pk_get_bitlen(&ctx->pk) == 256) {
            ctx->key.alg = cose_alg_ecdsa_sha_256;
            ctx->md_alg = MBEDTLS_MD_SHA256;
        } else if (mbedtls_pk_get_bitlen(&ctx->pk) == 384) {
            ctx->key.alg = cose_alg_ecdsa_sha_384;
            ctx->md_alg = MBEDTLS_MD_SHA384;
        } else if (mbedtls_pk_get_bitlen(&ctx->pk) == 512) {
            ctx->key.alg = cose_alg_ecdsa_sha_512;
            ctx->md_alg = MBEDTLS_MD_SHA512;
        } else return COSE_ERROR;
    } else return COSE_ERROR;
    return 0;
}

int cose_verify_init(cose_verify_context * ctx,
        const uint8_t * key, size_t len_key,
        const uint8_t * kid, size_t len_kid) 
{
    ctx->key.len_kid = len_kid;
    memcpy(ctx->key.kid, kid, len_kid);
    
    mbedtls_pk_init(&ctx->pk);
    if (mbedtls_pk_parse_public_key(&ctx->pk, key, len_key + 1)) 
        return COSE_ERROR;
    if (mbedtls_pk_get_type(&ctx->pk) == MBEDTLS_PK_ECKEY) { 
        if (mbedtls_pk_get_bitlen(&ctx->pk) == 256) {
            ctx->key.alg = cose_alg_ecdsa_sha_256;
            ctx->md_alg = MBEDTLS_MD_SHA256;
        } else if (mbedtls_pk_get_bitlen(&ctx->pk) == 384) {
            ctx->key.alg = cose_alg_ecdsa_sha_384;
            ctx->md_alg = MBEDTLS_MD_SHA384;
        } else if (mbedtls_pk_get_bitlen(&ctx->pk) == 512) {
            ctx->key.alg = cose_alg_ecdsa_sha_512;
            ctx->md_alg = MBEDTLS_MD_SHA512;
        } else return COSE_ERROR;
    } else return COSE_ERROR;
    return 0;
}

int cose_crypt_init(cose_crypt_context * ctx,
        const uint8_t * key, cose_alg alg,
        const uint8_t * kid, size_t len_kid) 
{
    ctx->key.alg = alg;
    ctx->cipher = MBEDTLS_CIPHER_ID_AES;
    ctx->key.len_kid = len_kid;
    memcpy(ctx->key.kid, kid, len_kid);

    if (ctx->key.alg == cose_alg_aes_gcm_128)
        ctx->key.len_key = 16;
    else if (ctx->key.alg == cose_alg_aes_gcm_192) 
        ctx->key.len_key = 24;
    else if (ctx->key.alg == cose_alg_aes_gcm_256)
        ctx->key.len_key = 32;
    else return COSE_ERROR;

    if (ctx->key.alg == cose_alg_aes_gcm_128 ||
            ctx->key.alg == cose_alg_aes_gcm_192 ||
            ctx->key.alg == cose_alg_aes_gcm_256) {
        ctx->len_tag = 16;
        mbedtls_gcm_init(&ctx->gcm);
        mbedtls_gcm_setkey(&ctx->gcm, ctx->cipher, key, ctx->key.len_key * 8);
    } else return COSE_ERROR;

    return 0;
}

int cose_sign_free(cose_sign_context * ctx) 
{
    mbedtls_pk_free(&ctx->pk);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    return 0;
}

int cose_verify_free(cose_verify_context * ctx) 
{
    mbedtls_pk_free(&ctx->pk);
    return 0;
}

int cose_crypt_free(cose_crypt_context * ctx) 
{
    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
            ctx->key.alg == cose_alg_aes_gcm_192 ||
            ctx->key.alg == cose_alg_aes_gcm_256) {
        mbedtls_gcm_free(&ctx->gcm);
    } return COSE_ERROR;
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

    if (cose_sign_encode_tbs(pld, len_pld, aad, len_aad, obj, &len_temp)) 
        return COSE_ERROR;

    if (mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), obj, len_temp, hash)) 
        return COSE_ERROR;

    if (mbedtls_pk_sign(&ctx->pk, ctx->md_alg, hash, 0, sig, &len_temp, 
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

    if (cose_sign_decode_obj(obj, len_obj, aad, len_aad, pld, &len_temp, sig, &len_sig))
        return COSE_ERROR;

    if (mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), pld, len_temp, hash)) 
        return COSE_ERROR;

    if (mbedtls_pk_verify(&ctx->pk, ctx->md_alg, hash, 0, sig, len_sig))
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
    size_t len_tbe = *len_obj;
    uint8_t tbe[2048];
    uint8_t tag[ctx->len_tag];
    uint8_t enc[len_pld];

    if (cose_crypt_encode_tbe(ctx, aad, len_aad, tbe, &len_tbe)) 
        return COSE_ERROR;

    if (cose_crypt_encipher(ctx, pld, len_pld, tbe, len_tbe, iv, len_iv, enc, tag))
        return COSE_ERROR;

    if (cose_crypt_encode_final(ctx, enc, len_pld, tag, ctx->len_tag, obj, len_obj)) 
        return COSE_ERROR;

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

