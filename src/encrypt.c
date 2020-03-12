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

#ifdef CONFIG_COZY_ENCRYPT

#include <cozy/cose.h>
#include <cozy/common.h>

int cose_crypt_init(cose_crypt_context_t * ctx,
        const uint8_t * key, cose_alg_t alg,
        uint8_t * iv, const size_t len_iv) 
{
    ctx->key.alg = alg;
    ctx->cipher = MBEDTLS_CIPHER_ID_AES;
    ctx->iv = iv;
    ctx->len_iv = len_iv;
    ctx->key.kid = NULL;
    ctx->key.len_kid = 0;
    ctx->key.aad = NULL;
    ctx->key.len_aad = 0;

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
        mbedtls_gcm_setkey(&ctx->gcm, ctx->cipher, 
                key, ctx->key.len_key * 8);
    } else return COSE_ERROR_UNSUPPORTED;

    return COSE_ERROR_NONE;
}

int cose_crypt_encrypt(
        cose_crypt_context_t * ctx,
        const uint8_t * pld, const size_t len_pld,
        const uint8_t * tbe, const size_t len_tbe,
        uint8_t * enc) 
{
    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
        ctx->key.alg == cose_alg_aes_gcm_192 ||
        ctx->key.alg == cose_alg_aes_gcm_256) {

        if (mbedtls_gcm_crypt_and_tag(
                    &ctx->gcm, MBEDTLS_GCM_ENCRYPT, 
                    len_pld, ctx->iv, ctx->len_iv, tbe, len_tbe, 
                    pld, enc, ctx->len_mac, enc + len_pld))
            return COSE_ERROR_ENCRYPT;

    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

int cose_crypt_decrypt(
        cose_crypt_context_t * ctx,
        const uint8_t * enc, const size_t len_enc,
        const uint8_t * tbe, const size_t len_tbe,
        uint8_t * pld, size_t * len_pld) 
{
    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
        ctx->key.alg == cose_alg_aes_gcm_192 ||
        ctx->key.alg == cose_alg_aes_gcm_256) {

        *len_pld = len_enc - ctx->len_mac;
        if (mbedtls_gcm_auth_decrypt(
                    &ctx->gcm, *len_pld, 
                    ctx->iv, ctx->len_iv, 
                    tbe, len_tbe, enc + *len_pld, 
                    ctx->len_mac, enc, pld))
            return COSE_ERROR_DECRYPT;
            
    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

int cose_crypt_encode_tbe0(
        cose_key_t * key,
        uint8_t * tbe, size_t * len_tbe)
{
    /* serialize protected */
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = cose_encode_prot(key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    cose_encode_prot(key, &nc);
   
    /* get size of Enc_structure */
    nanocbor_encoder_init(&nc, NULL, 0);
    nanocbor_fmt_array(&nc, 3);
    nanocbor_put_tstr(&nc, COSE_CONTEXT_ENCRYPT0);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_put_bstr(&nc, key->aad, key->len_aad);
    size_t len_struct = nanocbor_encoded_len(&nc);

    /* serialize to byte stream */
    nanocbor_encoder_init(&nc, tbe, *len_tbe);
    nanocbor_fmt_bstr(&nc, len_struct);
    nanocbor_fmt_array(&nc, 3);
    nanocbor_put_tstr(&nc, COSE_CONTEXT_ENCRYPT0);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_put_bstr(&nc, key->aad, key->len_aad);
    *len_tbe = nanocbor_encoded_len(&nc);

    return COSE_ERROR_NONE;
}

int cose_crypt_encode_encrypt0(
        cose_crypt_context_t * ctx,
        const uint8_t * enc, const size_t len_enc, 
        uint8_t * obj, size_t * len_obj) 
{
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = cose_encode_prot(&ctx->key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    cose_encode_prot(&ctx->key, &nc);

    nanocbor_encoder_init(&nc, obj, *len_obj);
    nanocbor_fmt_tag(&nc, cose_tag_encrypt0);
    nanocbor_fmt_array(&nc, 3);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_fmt_map(&nc, 2);
    nanocbor_fmt_int(&nc, cose_header_kid);
    nanocbor_put_bstr(&nc, ctx->key.kid, ctx->key.len_kid);
    nanocbor_fmt_int(&nc, cose_header_iv);
    nanocbor_put_bstr(&nc, ctx->iv, ctx->len_iv);
    nanocbor_put_bstr(&nc, enc, len_enc);

    *len_obj = nanocbor_encoded_len(&nc);
    return COSE_ERROR_NONE;
} 

int cose_crypt_decode_encrypt0(
        cose_crypt_context_t * ctx,
        const uint8_t * obj, const size_t len_obj,
        const uint8_t ** enc, size_t * len_enc)
{
    nanocbor_value_t nc, arr, map;
    nanocbor_decoder_init(&nc, obj, len_obj);
    nanocbor_skip(&nc);
    if (nanocbor_enter_array(&nc, &arr) < 0) 
        return COSE_ERROR_DECODE;
    nanocbor_skip(&arr); 
    if (nanocbor_enter_map(&arr, &map) < 0) 
        return COSE_ERROR_DECODE;

    while (!nanocbor_at_end(&map)) {
        int32_t map_key;
        if (nanocbor_get_int32(&map, &map_key) < 0) 
            return COSE_ERROR_DECODE;
        if (map_key == cose_header_iv) {
            if (nanocbor_get_bstr(
                        &map, (const uint8_t **) &ctx->iv, 
                        &ctx->len_iv) < 0)
                return COSE_ERROR_DECODE;
            else break;
        }
        nanocbor_skip(&map); 
    }

    nanocbor_skip(&arr); 
    if (nanocbor_get_bstr(&arr, enc, len_enc) < 0)
        return COSE_ERROR_DECODE;

    return COSE_ERROR_NONE;
}

int cose_encrypt0_write(cose_crypt_context_t *ctx,
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * obj, size_t * len_obj) 
{
    size_t len_enc = len_pld + ctx->len_mac;
    uint8_t enc[len_enc];

    size_t len_tbe = len_pld + ctx->key.len_aad;
    uint8_t tbe[len_tbe];

    if (cose_crypt_encode_tbe0(
                &ctx->key,
                tbe, &len_tbe)) 
        return COSE_ERROR_ENCODE;

    if (cose_crypt_encrypt(
                ctx, 
                pld, len_pld, 
                tbe, len_tbe, 
                enc))
        return COSE_ERROR_ENCRYPT;

    if (cose_crypt_encode_encrypt0(
                ctx,
                enc, len_enc, 
                obj, len_obj)) 
        return COSE_ERROR_ENCODE;

    return COSE_ERROR_NONE;
}

int cose_encrypt0_read(cose_crypt_context_t * ctx,
        const uint8_t * obj, const size_t len_obj, 
        uint8_t * pld, size_t * len_pld) 
{
    size_t len_tbe = len_obj + ctx->key.len_aad;
    uint8_t tbe[len_tbe];

    uint8_t * enc; size_t len_enc;

    if (cose_crypt_encode_tbe0(
                &ctx->key, 
                tbe, &len_tbe)) 
        return COSE_ERROR_ENCODE;

    if (cose_crypt_decode_encrypt0(
                ctx, obj, len_obj, 
                (const uint8_t **) &enc, &len_enc))
        return COSE_ERROR_DECODE;

    if (cose_crypt_decrypt(ctx,
                enc, len_enc, 
                tbe, len_tbe, 
                pld, len_pld))
        return COSE_ERROR_DECRYPT;

    return COSE_ERROR_NONE;
}

void cose_crypt_free(cose_crypt_context_t * ctx) 
{
     mbedtls_gcm_free(&ctx->gcm);
}
#endif /* CONFIG_COZY_ENCRYPT */

