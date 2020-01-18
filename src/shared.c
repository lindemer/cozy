#include <cozy/cose.h>
#include <cozy/shared.h>

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
