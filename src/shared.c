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

#include <cozy/cose.h>
#include <cozy/common.h>

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
