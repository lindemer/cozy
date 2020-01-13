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
        return COSE_ERROR_MBEDTLS;
    ctx->key.len_kid = len_kid;
    memcpy(ctx->key.kid, kid, len_kid);

    mbedtls_pk_init(&ctx->pk);
    if (mbedtls_pk_parse_key(&ctx->pk, key, len_key + 1, NULL, 0)) 
        return COSE_ERROR_MBEDTLS;
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
        } else return COSE_ERROR_UNSUPPORTED;
    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

int cose_verify_init(cose_verify_context * ctx,
        const uint8_t * key, size_t len_key,
        const uint8_t * kid, size_t len_kid) 
{
    ctx->key.len_kid = len_kid;
    memcpy(ctx->key.kid, kid, len_kid);
    
    mbedtls_pk_init(&ctx->pk);
    if (mbedtls_pk_parse_public_key(&ctx->pk, key, len_key + 1)) 
        return COSE_ERROR_MBEDTLS;
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
        } else return COSE_ERROR_UNSUPPORTED;
    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
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
    else return COSE_ERROR_UNSUPPORTED;

    if (ctx->key.alg == cose_alg_aes_gcm_128 ||
            ctx->key.alg == cose_alg_aes_gcm_192 ||
            ctx->key.alg == cose_alg_aes_gcm_256) {
        ctx->len_mac = 16;
        mbedtls_gcm_init(&ctx->gcm);
        mbedtls_gcm_setkey(&ctx->gcm, ctx->cipher, key, ctx->key.len_key * 8);
    } else return COSE_ERROR_UNSUPPORTED;

    return COSE_ERROR_NONE;
}

int cose_sign_free(cose_sign_context * ctx) 
{
    mbedtls_pk_free(&ctx->pk);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    return COSE_ERROR_NONE;
}

int cose_verify_free(cose_verify_context * ctx) 
{
    mbedtls_pk_free(&ctx->pk);
    return COSE_ERROR_NONE;
}

int cose_crypt_free(cose_crypt_context * ctx) 
{
    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
            ctx->key.alg == cose_alg_aes_gcm_192 ||
            ctx->key.alg == cose_alg_aes_gcm_256) {
        mbedtls_gcm_free(&ctx->gcm);
    } return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

int cose_sign1_write(cose_sign_context * ctx, 
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        uint8_t * obj, size_t * len_obj) 
{

    size_t len_temp = *len_obj;
    uint8_t hash[128];
    uint8_t sig[384];

    if (cose_encode_sign_tbs(&ctx->key, pld, len_pld, aad, len_aad, obj, &len_temp)) 
        return COSE_ERROR_ENCODE;

    if (mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), obj, len_temp, hash)) 
        return COSE_ERROR_HASH;

    if (mbedtls_pk_sign(&ctx->pk, ctx->md_alg, hash, 0, sig, &len_temp, 
                mbedtls_ctr_drbg_random, &ctx->ctr_drbg)) 
        return COSE_ERROR_SIGN;

    if (cose_encode_sign_obj(&ctx->key, pld, len_pld, aad, len_aad, 
                sig, len_temp, obj, len_obj))
        return COSE_ERROR_ENCODE;

    return COSE_ERROR_NONE;
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

    if (cose_decode_sign_obj(&ctx->key, obj, len_obj, aad, len_aad, pld, &len_temp, sig, &len_sig))
        return COSE_ERROR_DECODE;

    if (mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), pld, len_temp, hash)) 
        return COSE_ERROR_HASH;

    if (mbedtls_pk_verify(&ctx->pk, ctx->md_alg, hash, 0, sig, len_sig))
        return COSE_ERROR_AUTHENTICATE;

    if (cose_decode_sign_pld(obj, len_obj, pld, len_pld)) 
        return COSE_ERROR_DECODE;

    return COSE_ERROR_NONE;
}

int cose_crypt_encipher(
        cose_crypt_context * ctx,
        const uint8_t * pld, size_t len_pld,
        const uint8_t * tbe, size_t len_tbe,
        const uint8_t * iv, size_t len_iv,
        uint8_t * enc) 
{
    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
        ctx->key.alg == cose_alg_aes_gcm_192 ||
        ctx->key.alg == cose_alg_aes_gcm_256) {

            if (mbedtls_gcm_crypt_and_tag(&ctx->gcm, MBEDTLS_GCM_ENCRYPT, len_pld, 
                        iv, len_iv, tbe, len_tbe, pld, enc, ctx->len_mac, enc + len_pld))
                return COSE_ERROR_ENCRYPT;
            
    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

int cose_encrypt0_write(cose_crypt_context *ctx,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        const uint8_t * iv, size_t len_iv,
        uint8_t * obj, size_t * len_obj) 
{
    size_t len_enc = len_pld + ctx->len_mac;
    uint8_t enc[len_enc];

    size_t len_tbe = len_aad + 32;
    uint8_t tbe[len_tbe];

    if (cose_encode_encrypt0_tbe(&ctx->key, aad, len_aad, tbe, &len_tbe)) 
        return COSE_ERROR_ENCODE;

    if (cose_crypt_encipher(ctx, pld, len_pld, tbe, len_tbe, iv, len_iv, enc))
        return COSE_ERROR_ENCRYPT;

    if (cose_encode_encrypt0_obj(&ctx->key, enc, len_enc, iv, len_iv, obj, len_obj)) 
        return COSE_ERROR_ENCODE;

    return COSE_ERROR_NONE;
}

int cose_encrypt0_read(cose_crypt_context * ctx,
        const uint8_t * obj, size_t len_obj, 
        const uint8_t * aad, size_t len_aad,
        uint8_t * pld, size_t * len_pld) 
{
    size_t len_enc = len_obj;
    uint8_t enc[len_enc];

    size_t len_tbe = len_aad + 32;
    uint8_t tbe[len_tbe];

    size_t len_iv = 12;
    uint8_t iv[len_iv];

    if (cose_encode_encrypt0_tbe(&ctx->key, aad, len_aad, tbe, &len_tbe)) 
        return COSE_ERROR_ENCODE;

    if (cose_decode_encrypt0_obj(obj, len_obj, enc, &len_enc, iv, &len_iv))
        return COSE_ERROR_DECODE; 

    return COSE_ERROR_NONE;
}

