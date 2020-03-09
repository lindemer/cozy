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

#ifndef SHARED_H
#define SHARED_H

#include <cozy/cose.h>

#define CBOR_MAP_INT(encoder, key, val)                                 \
    cbor_encode_int(encoder, key);                                      \
    cbor_encode_int(encoder, val);

#define CBOR_MAP_BYTES(encoder, key, val, len)                          \
    cbor_encode_int(encoder, key);                                      \
    cbor_encode_byte_string(encoder, val, len);

int cose_encode_final(
        CborEncoder * encoder, 
        uint8_t * out, size_t * len_out);

int cose_decode_final(
        CborValue * decoder, 
        uint8_t * out, size_t * len_out);

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
