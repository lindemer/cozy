#ifndef SHARED_H
#define SHARED_H

#include <cozy/cose.h>

#define CBOR_MAP_INT(encoder, key, val)                                 \
    cbor_encode_int(encoder, key);                                      \
    cbor_encode_int(encoder, val);

#define CBOR_MAP_BYTES(encoder, key, val, len)                          \
    cbor_encode_int(encoder, key);                                      \
    cbor_encode_byte_string(encoder, val, len);

#define CBOR_WRITE_RETURN(encoder, out, len_out)                        \
    if (cbor_encoder_get_extra_bytes_needed(encoder))                   \
        return COSE_ERROR_OVERFLOW;                                     \
    len_out = cbor_encoder_get_buffer_size(encoder, out);               \
    return COSE_ERROR_NONE;

#define CBOR_READ_RETURN(val, out, len_out)                             \
    cbor_value_get_string_length(val, len_out);                         \
    if (cbor_value_copy_byte_string(val, out, len_out, val)             \
            != CborNoError)                                             \
        return COSE_ERROR_DECODE;                                       \
     return COSE_ERROR_NONE;

int cose_encode_protected(
        cose_key * key,
        uint8_t * pro, size_t * len_pro);

int cose_encode_sign_tbs(
        cose_key * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs);

int cose_encode_sign_object(
        cose_key * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        const uint8_t * sig, size_t len_sig,
        uint8_t * obj, size_t * len_obj);
    
int cose_decode_sign_payload(
        const uint8_t * obj, size_t len_obj,
        uint8_t * pld, size_t * len_pld);

int cose_decode_sign_object(
        cose_key * key,
        const uint8_t * obj, size_t len_obj,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs,
        uint8_t * sig, size_t * len_sig); 

int cose_encode_encrypt0_tbe(
        cose_key * key,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbe, size_t * len_tbe);

int cose_encode_encrypt0_object(
        cose_key * key,
        const uint8_t * enc, size_t len_enc, 
        const uint8_t * iv, size_t len_iv,
        uint8_t * obj, size_t * len_obj);

int cose_decode_encrypt0_object(
        const uint8_t * obj, size_t len_obj,
        uint8_t * enc, size_t * len_enc,
        uint8_t * iv, size_t * len_iv);

#endif /* SHARED_H */
