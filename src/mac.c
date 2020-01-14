#ifdef CONFIG_COZY_MAC

#include <cozy/cose.h>
#include <cozy/shared.h>

int cose_mac0_write(cose_crypt_context *ctx,
        const uint8_t * pld, const size_t len_pld, 
        const uint8_t * aad, const size_t len_aad,
        const uint8_t * iv, const size_t len_iv,
        uint8_t * obj, size_t * len_obj) 
{

    return COSE_ERROR_NONE;
}

int cose_mac0_read(cose_crypt_context * ctx,
        const uint8_t * obj, const size_t len_obj, 
        const uint8_t * aad, const size_t len_aad,
        uint8_t * pld, size_t * len_pld)
{

    return COSE_ERROR_NONE;
}

#endif /* CONFIG_COZY_MAC */
