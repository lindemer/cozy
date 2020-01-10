#include "cose.h"
#include "encode.h"

int cose_sign_get_alg(cose_asym_key * key) 
{
    mbedtls_pk_type_t pk_type = mbedtls_pk_get_type(&key->pk);
    if (pk_type == MBEDTLS_PK_ECKEY) { 
        size_t bitlen = mbedtls_pk_get_bitlen(&key->pk);
        if (bitlen == 256) {
            key->alg = cose_alg_ecdsa_sha_256;
            key->md_alg = MBEDTLS_MD_SHA256;
        } else if (bitlen == 384) {
            key->alg = cose_alg_ecdsa_sha_384;
            key->md_alg = MBEDTLS_MD_SHA384;
        } else if (bitlen == 512) {
            key->alg = cose_alg_ecdsa_sha_512;
            key->md_alg = MBEDTLS_MD_SHA512;
        } else return COSE_ERROR;
        return 0;
    } else return COSE_ERROR;
}

int cose_sign_encode_tbs(
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs) 
{

    size_t len_buf = 64;
    size_t use_buf;
    uint8_t buf[len_buf];

    CborEncoder encoder_obj, encoder_arr, 
                encoder_map, encoder_buf;

    cbor_encoder_init(&encoder_obj, tbs, *len_tbs, 0);
    cbor_encoder_create_array(&encoder_obj, &encoder_arr, 5);               // Sig_Structure
    cbor_encode_text_string(&encoder_arr, COSE_CONTEXT_SIGN1,               // context
            strlen(COSE_CONTEXT_SIGN1));
    
    cbor_encoder_init(&encoder_buf, buf, len_buf, 0);
    cbor_encoder_create_map(&encoder_buf, &encoder_map, 0);                 // body_protected
    cbor_encoder_close_container(&encoder_buf, &encoder_map);
    if (cbor_encoder_get_extra_bytes_needed(&encoder_buf)) return COSE_ERROR;
    use_buf = cbor_encoder_get_buffer_size(&encoder_buf, buf);
    cbor_encode_byte_string(&encoder_arr, buf, use_buf);

    // TODO: populate this field
    cbor_encoder_init(&encoder_buf, buf, len_buf, 0);
    cbor_encoder_create_map(&encoder_buf, &encoder_map, 0);                 // sign_protected
    cbor_encoder_close_container(&encoder_buf, &encoder_map);
    if (cbor_encoder_get_extra_bytes_needed(&encoder_buf)) return COSE_ERROR;
    use_buf = cbor_encoder_get_buffer_size(&encoder_buf, buf);
    cbor_encode_byte_string(&encoder_arr, buf, use_buf);

    cbor_encode_byte_string(&encoder_arr, aad, len_aad);                    // external_aad
    cbor_encode_byte_string(&encoder_arr, pld, len_pld);                    // payload
    cbor_encoder_close_container(&encoder_obj, &encoder_arr);
    if (cbor_encoder_get_extra_bytes_needed(&encoder_obj)) return COSE_ERROR;
    *len_tbs = cbor_encoder_get_buffer_size(&encoder_obj, tbs);
    return 0;
}

int cose_sign_encode_final(cose_asym_key * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        const uint8_t * sig, size_t len_sig,
        uint8_t * out, size_t * len_out) 
{
    
    size_t len_buf = 64;
    size_t use_buf;
    uint8_t buf[len_buf];

    CborEncoder encoder_obj, encoder_arr_0, 
                encoder_arr_1, encoder_arr_2, 
                encoder_map, encoder_buf;

    cbor_encoder_init(&encoder_obj, out, *len_out, 0);
    cbor_encode_tag(&encoder_obj, cose_tag_sign1);                      // tag
    cbor_encoder_create_array(&encoder_obj, &encoder_arr_0, 4);
    cbor_encode_byte_string(&encoder_arr_0, NULL, 0);                   // protected
    cbor_encoder_create_map(&encoder_arr_0, &encoder_map, 0);           // unprotected
    cbor_encoder_close_container(&encoder_arr_0, &encoder_map);
    cbor_encode_byte_string(&encoder_arr_0, pld, len_pld);              // payload
    cbor_encoder_create_array(&encoder_arr_0, &encoder_arr_1, 1);       // signatures
    cbor_encoder_create_array(&encoder_arr_1, &encoder_arr_2, 3);

    cbor_encoder_init(&encoder_buf, buf, len_buf, 0);
    cbor_encoder_create_map(&encoder_buf, &encoder_map, 1);             // protected
    cbor_encode_int(&encoder_map, cose_header_algorithm);               // alg
    cbor_encode_int(&encoder_map, key->alg);
    cbor_encoder_close_container(&encoder_buf, &encoder_map);
    if (cbor_encoder_get_extra_bytes_needed(&encoder_buf)) return COSE_ERROR;
    use_buf = cbor_encoder_get_buffer_size(&encoder_buf, buf);
    cbor_encode_byte_string(&encoder_arr_1, buf, use_buf);

    cbor_encoder_create_map(&encoder_arr_2, &encoder_map, 1);           // unprotected
    cbor_encode_int(&encoder_map, cose_header_kid);                     // kid
    cbor_encode_byte_string(&encoder_map, key->id, key->len_id);
    cbor_encoder_close_container(&encoder_arr_2, &encoder_map);
    cbor_encode_byte_string(&encoder_arr_1, sig, len_sig);              // signature
    cbor_encoder_close_container(&encoder_arr_1, &encoder_arr_2);
    cbor_encoder_close_container(&encoder_arr_0, &encoder_arr_1);
    cbor_encoder_close_container(&encoder_obj, &encoder_arr_0);
    if (cbor_encoder_get_extra_bytes_needed(&encoder_obj)) return COSE_ERROR;
    *len_out = cbor_encoder_get_buffer_size(&encoder_obj, out);
    return 0;
}

int cose_sign_decode_pld(
        const uint8_t * obj, size_t len_obj,
        uint8_t * pld, size_t * len_pld) 
{

    CborParser parser;
    CborValue par_0, par_1;
    if (cbor_parser_init(obj, len_obj, 0, &parser, &par_0) != CborNoError)
        return COSE_ERROR;
    cbor_value_skip_tag(&par_0);                                      
    cbor_value_enter_container(&par_0, &par_1);                         // protected
    cbor_value_advance(&par_1);                                         // unprotected 
    cbor_value_advance(&par_1);                                         // payload

    if (cbor_value_copy_byte_string(&par_1, pld, len_pld, &par_1) != CborNoError) 
        return COSE_ERROR;

    return 0;
}

int cose_sign_decode_obj(
        const uint8_t * obj, size_t len_obj,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs,
        uint8_t * sig, size_t * len_sig) 
{

    CborParser parser;
    CborValue par_0, par_1, par_2, par_3;
    if (cbor_parser_init(obj, len_obj, 0, &parser, &par_0) != CborNoError)
        return COSE_ERROR;
    cbor_value_skip_tag(&par_0);                                      
    cbor_value_enter_container(&par_0, &par_1);                         // protected
    cbor_value_advance(&par_1);                                         // unprotected 
    cbor_value_advance(&par_1);                                         // payload

    size_t len_pld;
    cbor_value_get_string_length(&par_1, &len_pld);
    uint8_t pld[len_pld];

    if (cbor_value_copy_byte_string(&par_1, pld, &len_pld, &par_1) != CborNoError) 
        return COSE_ERROR;

    if (cose_sign_encode_tbs(pld, len_pld, aad, len_aad, tbs, len_tbs)) 
        return COSE_ERROR;

    cbor_value_enter_container(&par_1, &par_2);
    cbor_value_enter_container(&par_2, &par_3);                         // protected
    cbor_value_advance(&par_3);                                         // unprotected
    cbor_value_advance(&par_3);                                         // signature

    cbor_value_get_string_length(&par_3, len_sig);
    if (cbor_value_copy_byte_string(&par_3, sig, len_sig, &par_3) != CborNoError) 
        return COSE_ERROR;
    
    return 0;
}


