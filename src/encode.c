#include "cose.h"
#include "encode.h"

int cose_encode_protected(
        cose_key * key,
        uint8_t * pro, size_t * len_pro) 
{
    CborEncoder encoder_pro0, encoder_map0;

    cbor_encoder_init(&encoder_pro0, pro, *len_pro, 0);
    cbor_encoder_create_map(&encoder_pro0, &encoder_map0, 1);
    cbor_encode_int(&encoder_map0, cose_header_algorithm); 
    cbor_encode_int(&encoder_map0, key->alg);
    cbor_encoder_close_container(&encoder_pro0, &encoder_map0);

    if (cbor_encoder_get_extra_bytes_needed(&encoder_pro0)) 
        return COSE_ERROR_OVERFLOW;
    *len_pro = cbor_encoder_get_buffer_size(&encoder_pro0, pro);

    return COSE_ERROR_NONE;
}

int cose_encode_sign_tbs(
        cose_key * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
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

    if (cbor_encoder_get_extra_bytes_needed(&encoder_obj0)) 
        return COSE_ERROR_TINYCBOR;
    *len_tbs = cbor_encoder_get_buffer_size(&encoder_obj0, tbs);

     return COSE_ERROR_NONE;
}

int cose_encode_sign_obj(
        cose_key * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        const uint8_t * sig, size_t len_sig,
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
    cose_encode_protected(key, pro, &len_pro);                              // sign_protected
    cbor_encode_byte_string(&encoder_arr0, pro, len_pro);
    cbor_encoder_create_map(&encoder_arr2, &encoder_map0, 1);                   // unprotected
    cbor_encode_int(&encoder_map0, cose_header_kid);                            // kid
    cbor_encode_byte_string(&encoder_map0, key->kid, key->len_kid);
    cbor_encoder_close_container(&encoder_arr2, &encoder_map0);
    cbor_encode_byte_string(&encoder_arr1, sig, len_sig);                       // signature
    cbor_encoder_close_container(&encoder_arr1, &encoder_arr2);
    cbor_encoder_close_container(&encoder_arr0, &encoder_arr1);
    cbor_encoder_close_container(&encoder_obj0, &encoder_arr0);

    if (cbor_encoder_get_extra_bytes_needed(&encoder_obj0)) 
        return COSE_ERROR_TINYCBOR;
    *len_obj = cbor_encoder_get_buffer_size(&encoder_obj0, obj);

     return COSE_ERROR_NONE;
}

int cose_decode_sign_pld(
        const uint8_t * obj, size_t len_obj,
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

    if (cbor_value_copy_byte_string(&par1, pld, len_pld, &par1) != CborNoError) 
        return COSE_ERROR_TINYCBOR;

     return COSE_ERROR_NONE;
}

int cose_decode_sign_obj(
        cose_key * key,
        const uint8_t * obj, size_t len_obj,
        const uint8_t * aad, size_t len_aad,
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

    cbor_value_get_string_length(&par3, len_sig);
    if (cbor_value_copy_byte_string(&par3, sig, len_sig, &par3) != CborNoError) 
        return COSE_ERROR_TINYCBOR;
    
     return COSE_ERROR_NONE;
}

int cose_encode_encrypt0_tbe(
        cose_key * key,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbe, size_t * len_tbe)
{
    size_t len_pro = 8;
    uint8_t pro[len_pro];

    CborEncoder encoder_obj0, encoder_arr0;

    cbor_encoder_init(&encoder_obj0, tbe, *len_tbe, 0);
    cbor_encoder_create_array(&encoder_obj0, &encoder_arr0, 3);                 // Enc_structure
    cbor_encode_text_string(&encoder_arr0, COSE_CONTEXT_ENCRYPT0,               // context
            strlen(COSE_CONTEXT_ENCRYPT0));
    cose_encode_protected(key, pro, &len_pro);                                  // protected
    cbor_encode_byte_string(&encoder_arr0, pro, len_pro);
    cbor_encode_byte_string(&encoder_arr0, aad, len_aad);                       // external_aad
    cbor_encoder_close_container(&encoder_obj0, &encoder_arr0);

    if (cbor_encoder_get_extra_bytes_needed(&encoder_obj0)) 
        return COSE_ERROR_TINYCBOR;
    *len_tbe = cbor_encoder_get_buffer_size(&encoder_obj0, tbe);

     return COSE_ERROR_NONE;
}

int cose_encode_encrypt0_obj(
        cose_key * key,
        const uint8_t * enc, size_t len_enc, 
        const uint8_t * iv, size_t len_iv,
        uint8_t * obj, size_t * len_obj) 
{
    size_t len_pro = 8;
    uint8_t pro[len_pro];

    CborEncoder encoder_obj0, encoder_arr0, 
                encoder_map0;

    cbor_encoder_init(&encoder_obj0, obj, *len_obj, 0);
    cbor_encode_tag(&encoder_obj0, cose_tag_encrypt0);                          // tag
    cbor_encoder_create_array(&encoder_obj0, &encoder_arr0, 4);
    cbor_encode_byte_string(&encoder_arr0, NULL, 0);                            // protected
    cbor_encoder_create_map(&encoder_arr0, &encoder_map0, 1);                   // unprotected
    cbor_encode_int(&encoder_map0, cose_header_iv);
    cbor_encode_byte_string(&encoder_map0, iv, len_iv);                         // iv 
    cbor_encoder_close_container(&encoder_arr0, &encoder_map0);
    cbor_encode_byte_string(&encoder_arr0, enc, len_enc);                       // ciphertext
    cbor_encoder_close_container(&encoder_obj0, &encoder_arr0);

    if (cbor_encoder_get_extra_bytes_needed(&encoder_obj0)) 
        return COSE_ERROR_TINYCBOR;
    *len_obj = cbor_encoder_get_buffer_size(&encoder_obj0, obj);

     return COSE_ERROR_NONE;
} 

int cose_decode_encrypt0_obj(
        const uint8_t * obj, size_t len_obj,
        uint8_t * enc, size_t * len_enc,
        uint8_t * iv, size_t * len_iv)
{
    CborParser parser;
    CborValue par0, par1, par2;
    if (cbor_parser_init(obj, len_obj, 0, &parser, &par0) != CborNoError)
        return COSE_ERROR_TINYCBOR;
    cbor_value_skip_tag(&par0);                                      
    cbor_value_enter_container(&par0, &par1);                                   // protected
    cbor_value_advance(&par1);                                                  // unprotected 
    cbor_value_enter_container(&par1, &par2);                                   // iv
    if (!cbor_value_is_integer(&par2)) return COSE_ERROR_DECODE;
    cbor_value_advance(&par2);
    if (cbor_value_copy_byte_string(&par2, iv, len_iv, &par2) != CborNoError)
        return COSE_ERROR_TINYCBOR;
    cbor_value_leave_container(&par1, &par2);
    if (cbor_value_copy_byte_string(&par1, enc, len_enc, &par1) != CborNoError)
        printk("Fails here with unknown TinyCBOR error... why?\n");
        return COSE_ERROR_TINYCBOR;
    
     return COSE_ERROR_NONE;
}

