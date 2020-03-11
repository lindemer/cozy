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

int cose_encode_prot(cose_key_t * key, nanocbor_encoder_t * nc);
void xxd(const uint8_t * data, size_t len, int w); 

int cose_encode_sign_tbs(
        cose_key_t * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs);

int cose_encode_sign_object(
        cose_key_t * key,
        const uint8_t * pld, size_t len_pld, 
        const uint8_t * aad, size_t len_aad,
        const uint8_t * sig, size_t len_sig,
        uint8_t * obj, size_t * len_obj);

int cose_decode_sign_object(
        cose_key_t * key,
        const uint8_t * obj, size_t len_obj,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbs, size_t * len_tbs,
        const uint8_t ** pld, size_t * len_pld,
        const uint8_t ** sig, size_t * len_sig); 

int cose_encode_encrypt0_tbe(
        cose_key_t * key,
        const uint8_t * aad, size_t len_aad,
        uint8_t * tbe, size_t * len_tbe);

int cose_encode_encrypt0_object(
        cose_key_t * key,
        const uint8_t * enc, size_t len_enc, 
        const uint8_t * iv, size_t len_iv,
        uint8_t * obj, size_t * len_obj);

int cose_decode_encrypt0_object(
        const uint8_t * obj, size_t len_obj,
        const uint8_t ** enc, size_t * len_enc,
        const uint8_t ** iv, size_t * len_iv);

#endif /* SHARED_H */
