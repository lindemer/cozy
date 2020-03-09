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
#include <cozy/shared.h>

int cose_sign_init(
        cose_sign_context * ctx,
        cose_entropy_context * ent,
        const uint8_t * key, const size_t len_key,
        const uint8_t * kid, const size_t len_kid) 
{
    ctx->key.len_kid = len_kid;
    memcpy(ctx->key.kid, kid, len_kid);
    mbedtls_pk_init(&ctx->pk);
    if (ent == NULL) {
        ctx->key.op = cose_key_op_verify;
        if (mbedtls_pk_parse_public_key(&ctx->pk, key, len_key + 1)) 
            return COSE_ERROR_MBEDTLS;
    } else {
        ctx->key.op = cose_key_op_sign;
        ctx->ent = ent;
        mbedtls_entropy_init(&ent->entropy);
        mbedtls_ctr_drbg_init(&ent->ctr_drbg);
        if (mbedtls_ctr_drbg_seed(
                    &ent->ctr_drbg, mbedtls_entropy_func, 
                    &ent->entropy, COSE_ENTROPY_SEED, 
                    strlen(COSE_ENTROPY_SEED)))
            return COSE_ERROR_MBEDTLS;
        if (mbedtls_pk_parse_key(&ctx->pk, key, len_key + 1, NULL, 0)) 
            return COSE_ERROR_MBEDTLS;
    }
    ctx->key.kty = cose_kty_ec2;
    ctx->len_hash = mbedtls_pk_get_len(&ctx->pk);
    if (ctx->len_hash == 32) {
        ctx->key.crv = cose_curve_p256;
        ctx->key.alg = cose_alg_ecdsa_sha_256;
        ctx->md_alg = MBEDTLS_MD_SHA256;
        ctx->len_sig = 72;
    } else if (ctx->len_hash == 48) {
        ctx->key.crv = cose_curve_p384;
        ctx->key.alg = cose_alg_ecdsa_sha_384;
        ctx->md_alg = MBEDTLS_MD_SHA384;
        ctx->len_sig = 104;
    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

void cose_sign_free(cose_sign_context * ctx) 
{
    mbedtls_pk_free(&ctx->pk);
    if (ctx->ent != NULL) {
        mbedtls_entropy_free(&ctx->ent->entropy);
        mbedtls_ctr_drbg_free(&ctx->ent->ctr_drbg);
    }
}

int cose_sign_write(cose_sign_context * ctx, 
        const uint8_t * pld, const size_t len_pld, 
        const uint8_t * aad, const size_t len_aad,
        uint8_t * obj, size_t * len_obj) 
{
    size_t len_temp = *len_obj;
    uint8_t hash[ctx->len_hash];
    uint8_t sig[ctx->len_sig];

    if (cose_encode_sign_tbs(&ctx->key, pld, len_pld, aad, len_aad, obj, &len_temp)) 
        return COSE_ERROR_ENCODE;

    if (mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), obj, len_temp, hash)) 
        return COSE_ERROR_HASH;

    if (mbedtls_pk_sign(&ctx->pk, ctx->md_alg, hash, 0, sig, &len_temp, 
                mbedtls_ctr_drbg_random, &ctx->ent->ctr_drbg)) 
        return COSE_ERROR_SIGN;

    if (cose_encode_sign_object(&ctx->key, pld, len_pld, aad, len_aad, 
                sig, len_temp, obj, len_obj))
        return COSE_ERROR_ENCODE;

    return COSE_ERROR_NONE;
}

int cose_sign_read(cose_sign_context * ctx, 
        const uint8_t * obj, const size_t len_obj, 
        const uint8_t * aad, const size_t len_aad,
        uint8_t * pld, size_t * len_pld) 
{
    size_t len_temp = *len_pld;
    uint8_t sig[ctx->len_sig];
    uint8_t hash[ctx->len_hash];

    if (cose_decode_sign_object(&ctx->key, obj, len_obj, aad, len_aad, 
                pld, &len_temp, sig, &ctx->len_sig))
        return COSE_ERROR_DECODE;

    if (mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), pld, len_temp, hash)) 
        return COSE_ERROR_HASH;

    if (mbedtls_pk_verify(&ctx->pk, ctx->md_alg, hash, 0, sig, ctx->len_sig))
        return COSE_ERROR_AUTHENTICATE;

    if (cose_decode_sign_payload(obj, len_obj, pld, len_pld)) 
        return COSE_ERROR_DECODE;

    return COSE_ERROR_NONE;
}

int cose_encode_sign_tbs(
        cose_key * key,
        const uint8_t * pld, const size_t len_pld, 
        const uint8_t * aad, const size_t len_aad,
        uint8_t * tbs, size_t * len_tbs) 
{
    size_t len_pro = 8;
    uint8_t pro[len_pro];

    CborEncoder encoder_obj0, encoder_arr0;

    cbor_encoder_init(&encoder_obj0, tbs, *len_tbs, 0);
    cbor_encoder_create_array(&encoder_obj0, &encoder_arr0, 5);                 // Sig_Structure
    cbor_encode_text_string(&encoder_arr0, COSE_CONTEXT_SIGN,                   // context
            strlen(COSE_CONTEXT_SIGN));
    cbor_encode_byte_string(&encoder_arr0, NULL, 0);                            // body_protected
    cose_encode_protected(key, pro, &len_pro);                                  // sign_protected
    cbor_encode_byte_string(&encoder_arr0, pro, len_pro);
    cbor_encode_byte_string(&encoder_arr0, aad, len_aad);                       // external_aad
    cbor_encode_byte_string(&encoder_arr0, pld, len_pld);                       // payload
    cbor_encoder_close_container(&encoder_obj0, &encoder_arr0);

    return cose_encode_final(&encoder_obj0, tbs, len_tbs);
}

int cose_encode_sign_object(
        cose_key * key,
        const uint8_t * pld, const size_t len_pld, 
        const uint8_t * aad, const size_t len_aad,
        const uint8_t * sig, const size_t len_sig,
        uint8_t * obj, size_t * len_obj) 
{
    size_t len_pro = 8;
    uint8_t pro[len_pro];

    CborEncoder encoder_obj0, encoder_arr0, 
                encoder_arr1, encoder_arr2,
                encoder_map0;

    cbor_encoder_init(&encoder_obj0, obj, *len_obj, 0);
    cbor_encode_tag(&encoder_obj0, cose_tag_sign);                              // tag
    cbor_encoder_create_array(&encoder_obj0, &encoder_arr0, 4);
    cbor_encode_byte_string(&encoder_arr0, NULL, 0);                            // protected
    cbor_encoder_create_map(&encoder_arr0, &encoder_map0, 0);                   // unprotected
    cbor_encoder_close_container(&encoder_arr0, &encoder_map0);
    cbor_encode_byte_string(&encoder_arr0, pld, len_pld);                       // payload
    cbor_encoder_create_array(&encoder_arr0, &encoder_arr1, 1);                 // signatures
    cbor_encoder_create_array(&encoder_arr1, &encoder_arr2, 3);
    cose_encode_protected(key, pro, &len_pro);                                  // sign_protected
    cbor_encode_byte_string(&encoder_arr0, pro, len_pro);
    cbor_encoder_create_map(&encoder_arr2, &encoder_map0, 1);                   // unprotected
    CBOR_MAP_BYTES(&encoder_map0, cose_header_kid, key->kid, key->len_kid)
    cbor_encoder_close_container(&encoder_arr2, &encoder_map0);
    cbor_encode_byte_string(&encoder_arr1, sig, len_sig);                       // signature
    cbor_encoder_close_container(&encoder_arr1, &encoder_arr2);
    cbor_encoder_close_container(&encoder_arr0, &encoder_arr1);
    cbor_encoder_close_container(&encoder_obj0, &encoder_arr0);

    return cose_encode_final(&encoder_obj0, obj, len_obj);
}

int cose_decode_sign_payload(
        const uint8_t * obj, const size_t len_obj,
        uint8_t * pld, size_t * len_pld) 
{
    CborParser parser;
    CborValue par0, par1;
    if (cbor_parser_init(obj, len_obj, 0, &parser, &par0) != CborNoError)
        return COSE_ERROR_TINYCBOR;
    cbor_value_skip_tag(&par0);                                      
    cbor_value_enter_container(&par0, &par1);                                   // protected
    cbor_value_advance(&par1);                                                  // unprotected 
    cbor_value_advance(&par1);                                                  // payload
    
    return cose_decode_final(&par1, pld, len_pld);
}

int cose_decode_sign_object(
        cose_key * key,
        const uint8_t * obj, const size_t len_obj,
        const uint8_t * aad, const size_t len_aad,
        uint8_t * tbs, size_t * len_tbs,
        uint8_t * sig, size_t * len_sig) 
{
    CborParser parser;
    CborValue par0, par1, par2, par3;
    if (cbor_parser_init(obj, len_obj, 0, &parser, &par0) != CborNoError)
        return COSE_ERROR_TINYCBOR;
    cbor_value_skip_tag(&par0);                                      
    cbor_value_enter_container(&par0, &par1);                                   // protected
    cbor_value_advance(&par1);                                                  // unprotected 
    cbor_value_advance(&par1);                                                  // payload

    size_t len_pld;
    cbor_value_get_string_length(&par1, &len_pld);
    uint8_t pld[len_pld];

    if (cbor_value_copy_byte_string(&par1, pld, &len_pld, &par1) != CborNoError) 
        return COSE_ERROR_TINYCBOR;

    if (cose_encode_sign_tbs(key, pld, len_pld, aad, len_aad, tbs, len_tbs)) 
        return COSE_ERROR_ENCODE;

    cbor_value_enter_container(&par1, &par2);
    cbor_value_enter_container(&par2, &par3);                                   // protected
    cbor_value_advance(&par3);                                                  // unprotected
    cbor_value_advance(&par3);                                                  // signature

    return cose_decode_final(&par3, sig, len_sig);
}

#endif /* CONFIG_COZY_SIGN */
