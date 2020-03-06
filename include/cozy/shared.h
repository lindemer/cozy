/*
 * Copyright (c) 2020, RISE Research Institutes of Sweden
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Samuel Tanner Lindemer
 * <samuel.lindemer@ri.se>
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
