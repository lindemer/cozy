#ifndef ENCODE_H
#define ENCODE_H

#include "cose.h"

int cose_encode_protected(
        cose_key * key,
        uint8_t * pro, size_t * len_pro);

int cose_encode_sign_tbs(
        cose_key * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs);

int cose_encode_sign_obj(
        cose_key * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        const uint8_t * sig, size_t len_sig,
        uint8_t * obj, size_t * len_obj);
    
int cose_decode_sign_pld(
        const uint8_t * obj, size_t len_obj,
        uint8_t * pld, size_t * len_pld);

int cose_decode_sign_obj(
        cose_key * key,
        const uint8_t * obj, size_t len_obj,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs,
        uint8_t * sig, size_t * len_sig); 

int cose_encode_encrypt0_tbe(
        cose_key * key,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbe, size_t * len_tbe);

int cose_encode_encrypt0_obj(
        cose_key * key,
        const uint8_t * enc, size_t len_enc, 
        const uint8_t * iv, size_t len_iv,
        uint8_t * obj, size_t * len_obj);

int cose_decode_encrypt0_obj(
        const uint8_t * obj, size_t len_obj,
        uint8_t * enc, size_t * len_enc,
        uint8_t * iv, size_t * len_iv);

#endif /* ENCODE_H */
