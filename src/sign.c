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

#ifdef CONFIG_COZY_SIGN

#include <cozy/cose.h>
#include <cozy/common.h>

int cose_sign_init(
        cose_sign_context_t * ctx, 
        cose_mode_t mode,
        const uint8_t * pem) 
{
    mbedtls_pk_init(&ctx->pk);
    if (mode == cose_mode_r) {
        ctx->key.op = cose_key_op_verify;
        if (mbedtls_pk_parse_public_key(
                    &ctx->pk, pem, strlen(pem) + 1)) 
            return COSE_ERROR_MBEDTLS;
    } else if (mode == cose_mode_w) {
        ctx->key.op = cose_key_op_sign;
        if (mbedtls_pk_parse_key(
                    &ctx->pk, pem, strlen(pem) + 1, NULL, 0)) 
            return COSE_ERROR_MBEDTLS;
    } else return COSE_ERROR_UNSUPPORTED;
    ctx->key.kty = cose_kty_ec2;
    mbedtls_ecp_group_id grp_id = mbedtls_pk_ec(ctx->pk)->grp.id;
    if (grp_id == MBEDTLS_ECP_DP_SECP256R1) {
        ctx->len_hash = 32;
        ctx->key.crv = cose_curve_p256;
        ctx->key.alg = cose_alg_ecdsa_sha_256;
        ctx->md_alg = MBEDTLS_MD_SHA256;
        ctx->len_sig = 72;
    } else if (grp_id == MBEDTLS_ECP_DP_SECP384R1) {
        ctx->len_hash = 48;
        ctx->key.crv = cose_curve_p384;
        ctx->key.alg = cose_alg_ecdsa_sha_384;
        ctx->md_alg = MBEDTLS_MD_SHA384;
        ctx->len_sig = 104;
    } else return COSE_ERROR_UNSUPPORTED;

    ctx->key.kid = NULL;
    ctx->key.len_kid = 0;
    ctx->key.aad = NULL;
    ctx->key.len_aad = 0;
    return COSE_ERROR_NONE;
}

int cose_sign_write(cose_sign_context_t * ctx, 
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * obj, size_t * len_obj) 
{
    size_t len_buff = *len_obj;
    uint8_t hash[ctx->len_hash];
    uint8_t sig[ctx->len_sig];

    if (cose_encode_tbs1(
                &ctx->key, 
                pld, len_pld, 
                obj, &len_buff)) 
        return COSE_ERROR_ENCODE;

    if (mbedtls_md(
                mbedtls_md_info_from_type(ctx->md_alg), 
                obj, len_buff, hash)) 
        return COSE_ERROR_HASH;

    if (mbedtls_ecdsa_write_signature(
                ctx->pk.pk_ctx, ctx->md_alg, 
                hash, ctx->len_hash, 
                sig, &len_buff, 
                NULL, NULL)) 
        return COSE_ERROR_SIGN;

    if (cose_encode_sign_object(
                &ctx->key, 
                pld, len_pld, 
                sig, len_buff,
                obj, len_obj))
        return COSE_ERROR_ENCODE;

    return COSE_ERROR_NONE;
}

int cose_sign_read(cose_sign_context_t * ctx, 
        const uint8_t * obj, const size_t len_obj, 
        const uint8_t ** pld, size_t * len_pld) 
{
    size_t len_tbs = len_obj + ctx->key.len_aad;
    uint8_t tbs[len_tbs];
    uint8_t hash[ctx->len_hash];
    uint8_t * sig;
    size_t len_sig;

    if (cose_decode_sign_object(
                &ctx->key, 
                obj, len_obj,
                tbs, &len_tbs, 
                pld, len_pld,
                (const uint8_t **) &sig, &len_sig))
        return COSE_ERROR_DECODE;

    if (mbedtls_md(
                mbedtls_md_info_from_type(ctx->md_alg), 
                tbs, len_tbs, hash)) 
        return COSE_ERROR_HASH;

   if (mbedtls_pk_verify(
                &ctx->pk, ctx->md_alg, 
                hash, 0, sig, len_sig))
        return COSE_ERROR_AUTHENTICATE;

    return COSE_ERROR_NONE;
}

void cose_sign_free(cose_sign_context_t * ctx) 
{
    mbedtls_pk_free(&ctx->pk);
}

int cose_encode_tbs1(
        cose_key_t * key,
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * tbs, size_t * len_tbs) 
{
    /* serialize body_protected */
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = cose_encode_prot(key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    cose_encode_prot(key, &nc);

    /* get size of Sig_structure */
    nanocbor_encoder_init(&nc, NULL, 0);
    nanocbor_fmt_array(&nc, 4);
    nanocbor_put_tstr(&nc, COSE_CONTEXT_SIGN1);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_put_bstr(&nc, key->aad, key->len_aad);
    nanocbor_put_bstr(&nc, pld, len_pld);
    size_t len_struct = nanocbor_encoded_len(&nc);
    
    /* serialize ToBeSigned  */
    nanocbor_encoder_init(&nc, tbs, *len_tbs);
    nanocbor_fmt_bstr(&nc, len_struct);
    nanocbor_fmt_array(&nc, 4);
    nanocbor_put_tstr(&nc, COSE_CONTEXT_SIGN1);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_put_bstr(&nc, key->aad, key->len_aad);
    nanocbor_put_bstr(&nc, pld, len_pld);
    *len_tbs = nanocbor_encoded_len(&nc);

    return COSE_ERROR_NONE;
}

int cose_encode_sign_object(
        cose_key_t * key,
        const uint8_t * pld, const size_t len_pld, 
        const uint8_t * sig, const size_t len_sig,
        uint8_t * obj, size_t * len_obj) 
{
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = cose_encode_prot(key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    cose_encode_prot(key, &nc);

    nanocbor_encoder_init(&nc, obj, *len_obj);
    nanocbor_fmt_tag(&nc, cose_tag_sign1);
    nanocbor_fmt_array(&nc, 4);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_fmt_map(&nc, 0);
    nanocbor_put_bstr(&nc, pld, len_pld);
    nanocbor_put_bstr(&nc, sig, len_sig);
    *len_obj = nanocbor_encoded_len(&nc);

    return COSE_ERROR_NONE;
}

int cose_decode_sign_object(
        cose_key_t * key,
        const uint8_t * obj, const size_t len_obj,
        uint8_t * tbs, size_t * len_tbs,
        const uint8_t ** pld, size_t * len_pld,
        const uint8_t ** sig, size_t * len_sig) 
{
    nanocbor_value_t nc, arr;
    nanocbor_decoder_init(&nc, obj, len_obj);
    nanocbor_skip(&nc);
    if (nanocbor_enter_array(&nc, &arr) < 0) 
        return COSE_ERROR_DECODE;
    nanocbor_skip(&arr);
    nanocbor_skip(&arr);
    nanocbor_get_bstr(&arr, pld, len_pld); 

    if (cose_encode_tbs1(key, *pld, *len_pld, tbs, len_tbs)) 
        return COSE_ERROR_ENCODE;
    nanocbor_get_bstr(&arr, sig, len_sig); 

    return COSE_ERROR_NONE;
}

#endif /* CONFIG_COZY_SIGN */
