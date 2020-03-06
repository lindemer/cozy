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

#include <cozy/cose.h>
#include <cozy/shared.h>

int cose_encode_final(
        CborEncoder * encoder, 
        uint8_t * out, size_t * len_out)
{
    if (cbor_encoder_get_extra_bytes_needed(encoder))
        return COSE_ERROR_OVERFLOW;
    *len_out = cbor_encoder_get_buffer_size(encoder, out);
    return COSE_ERROR_NONE;
}

int cose_decode_final(
        CborValue * decoder, 
        uint8_t * out, size_t * len_out)
{
    int len_tmp = 0;
    cbor_value_get_string_length(decoder, &len_tmp);
    if (*len_out < len_tmp) return COSE_ERROR_OVERFLOW;
    *len_out = len_tmp;
    if (cbor_value_copy_byte_string(decoder, out, len_out, decoder) != CborNoError)
        return COSE_ERROR_DECODE;
     return COSE_ERROR_NONE;
}

int cose_encode_protected(
        cose_key * key,
        uint8_t * pro, size_t * len_pro) 
{
    CborEncoder encoder_pro0, encoder_map0;

    cbor_encoder_init(&encoder_pro0, pro, *len_pro, 0);
    cbor_encoder_create_map(&encoder_pro0, &encoder_map0, 1);
    CBOR_MAP_INT(&encoder_map0, cose_header_algorithm, key->alg);
    cbor_encoder_close_container(&encoder_pro0, &encoder_map0);

    if (cbor_encoder_get_extra_bytes_needed(&encoder_pro0)) 
        return COSE_ERROR_OVERFLOW;
    *len_pro = cbor_encoder_get_buffer_size(&encoder_pro0, pro);

    return COSE_ERROR_NONE;
}
