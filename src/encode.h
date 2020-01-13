#ifndef ENCODE_H
#define ENCODE_H

#include "cose.h"

int cose_sign_encode_tbs(
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs);

int cose_sign_encode_final(
        cose_key * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        const uint8_t * sig, size_t len_sig,
        uint8_t * obj, size_t * len_obj);
    
int cose_sign_decode_pld(
        const uint8_t * obj, size_t len_obj,
        uint8_t * pld, size_t * len_pld);

int cose_sign_decode_obj(
        const uint8_t * obj, size_t len_obj,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs,
        uint8_t * sig, size_t * len_sig); 

int cose_crypt_encode_tbe(
        cose_crypt_context * ctx,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbe, size_t * len_tbe);

int cose_crypt_encipher(
        cose_crypt_context * ctx,
        const uint8_t * pld, size_t len_pld,
        const uint8_t * tbe, size_t len_tbe,
        const uint8_t * iv, size_t len_iv,
        uint8_t * enc, uint8_t * tag);

int cose_crypt_encode_final(
        cose_crypt_context * ctx,
        const uint8_t * enc, size_t len_enc, 
        const uint8_t * tag, size_t len_tag,
        uint8_t * out, size_t * len_out);

#endif /* ENCODE_H */
