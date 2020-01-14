#ifndef COSE_H
#define COSE_H

#include <zephyr.h>
#include <tinycbor/cbor.h>

#ifndef CONFIG_MBEDTLS_CFG_FILE
#include "mbedtls/config-suite-b.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#define COSE_CONTEXT_SIGN "Signature"
#define COSE_CONTEXT_SIGN1 "Signature1"
#define COSE_CONTEXT_COUNTERSIGN "CounterSignature"
#define COSE_CONTEXT_MAC "MAC"
#define COSE_CONTEXT_MAC0 "MAC0"
#define COSE_CONTEXT_ENCRYPT "Encrypt"
#define COSE_CONTEXT_ENCRYPT0 "Encrypt0"
#define COSE_CONTEXT_ENC_RECIPIENT "Enc_Recipient"
#define COSE_CONTEXT_MAC_RECIPIENT "Mac_Recipient"
#define COSE_CONTEXT_REC_RECIPIENT "Rec_Recipient"

#define COSE_ENTROPY_SEED "This should be unique for every device."

#define COSE_ERROR_NONE                 0x00
#define COSE_ERROR_MBEDTLS              0x01
#define COSE_ERROR_TINYCBOR             0x02
#define COSE_ERROR_UNSUPPORTED          0x03
#define COSE_ERROR_ENCODE               0x04
#define COSE_ERROR_DECODE               0x05
#define COSE_ERROR_AUTHENTICATE         0x06
#define COSE_ERROR_MISMATCH             0x07
#define COSE_ERROR_HASH                 0x08
#define COSE_ERROR_ENCRYPT              0x09
#define COSE_ERROR_DECRYPT              0x0a
#define COSE_ERROR_SIGN                 0x0b
#define COSE_ERROR_OVERFLOW             0x0c

typedef enum {
    cose_tag_sign = 98,
    cose_tag_sign1 = 18,
    cose_tag_encrypt = 96,
    cose_tag_encrypt0 = 16,
    cose_tag_mac = 97,
    cose_tag_mac0 = 17,
} cose_tag;

typedef enum {
    cose_alg_aes_gcm_128 = 1,
    cose_alg_aes_gcm_192 = 2,
    cose_alg_aes_gcm_256 = 3,
    cose_alg_hmac_256_64 = 4,
    cose_alg_hmac_256_256 = 5,
    cose_alg_hmac_384_384 = 6,
    cose_alg_hmac_512_512 = 7,
    cose_alg_cbc_mac_128_64 = 14,
    cose_alg_cbc_mac_256_64 = 15,
    cose_alg_cbc_mac_128_128 = 25,
    cose_alg_cbc_mac_256_128 = 26,
    cose_alg_aes_ccm_16_64_128 = 10,
    cose_alg_aes_ccm_16_64_256 = 11,
    cose_alg_aes_ccm_64_64_128 = 12,
    cose_alg_aes_ccm_64_64_256 = 13,
    cose_alg_aes_ccm_16_128_128 = 30,
    cose_alg_aes_ccm_16_128_256 = 31,
    cose_alg_aes_ccm_64_128_128 = 32,
    cose_alg_aes_ccm_64_128_256 = 33,
    cose_alg_ecdh_es_hkdf_256 = -25,
    cose_alg_ecdh_es_hkdf_512 = -26,
    cose_alg_ecdh_ss_hkdf_256 = -27,
    cose_alg_ecdh_ss_hkdf_512 = -28,
    cose_alg_ecdh_es_a128kw = -29,
    cose_alg_ecdh_es_a192kw = -30,
    cose_alg_ecdh_es_a256kw = -31,
    cose_alg_ecdh_ss_a128kw = -32,
    cose_alg_ecdh_ss_a192kw = -33,
    cose_alg_ecdh_ss_a256kw = -34,
    cose_alg_aes_kw_128 = -3,
    cose_alg_aes_kw_192 = -4,
    cose_alg_aes_kw_256 = -5,
    cose_alg_direct = -6,
    cose_alg_direct_hkdf_hmac_sha_256 = -10,
    cose_alg_direct_hkdf_hmac_sha_512 = -11,
    cose_alg_direct_hkdf_aes_128 = -12,
    cose_alg_direct_hkdf_aes_256 = -13,
    cose_alg_ecdsa_sha_256 = -7,
    cose_alg_ecdsa_sha_384 = -35,
    cose_alg_ecdsa_sha_512 = -36,
} cose_alg;

typedef enum {
    cose_header_algorithm = 1,
    cose_header_critical = 2,
    cose_header_content_type = 3,
    cose_header_kid = 4,
    cose_header_iv = 5,
    cose_header_partial_iv = 6,
    cose_header_countersign = 7,
    cose_header_operation_time = 8,
    cose_header_countersign0 = 9,
    cose_header_hkdf_salt = -20,
    cose_header_kdf_u_name = -21,
    cose_header_kdf_u_nonce = -22,
    cose_header_kdf_u_other = -23,
    cose_header_kdf_v_name = -24,
    cose_header_kdf_v_nonce = -25,
    cose_header_kdf_v_other = -26,
    cose_header_ecdh_ephemeral = -1,
    cose_header_ecdh_static = -2,
    cose_header_ecdh_epk = -1,
    cose_header_ecdh_spk = -2,
    cose_header_ecdh_spk_kid = -3,
} cose_header;

typedef enum {
    cose_key_label_kty = 1,
    cose_key_label_kid = 2,
    cose_key_label_alg = 3,
    cose_key_label_key_ops = 4,
    cose_key_label_base_iv = 5,
} cose_key_label;

typedef enum {
    cose_key_op_sign = 1,
    cose_key_op_verify = 2,
    cose_key_op_encrypt = 3,
    cose_key_op_decrypt = 4,
    cose_key_op_wrap_key = 5,
    cose_key_op_unwrap_key = 6,
    cose_key_op_derive_key = 7,
    cose_key_op_derive_bits = 8,
    cose_key_op_mac_create = 9,
    cose_key_op_mac_verify = 10,
} cose_key_op;

typedef enum {
    cose_kty_okp = 1,
    cose_kty_ec2 = 2,
    cose_kty_symmetric = 4,
} cose_kty;

typedef enum {
    cose_ec_param_crv = -1,
    cose_ec_param_x = -2,
    cose_ec_param_y = -3,
    cose_ec_param_d = -4,
} cose_ec_param;

typedef enum {
    cose_octet_param_crv = -1,
    cose_octet_param_x = -2,
    cose_octet_param_d = -4,
} cose_octet_param;

typedef enum {
    cose_symmetric_param_K = -1,
} cose_symmetric_param;

typedef enum {
    cose_curve_p256 = 1,
    cose_curve_p384 = 2,
    cose_curve_p251 = 3,
    cose_curve_x25519 = 4,
    cose_curve_x448 = 5,
    cose_curve_ed25519 = 6,
    cose_curve_ed448 = 7,
} cose_curve;

typedef struct {
    cose_kty kty;
    uint8_t kid[16];
    cose_alg alg;
    size_t len_kid;
    size_t len_key;
} cose_key;

typedef struct {
    cose_key key;
    mbedtls_pk_context pk;
    mbedtls_md_type_t md_alg;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
} cose_sign_context;

typedef struct {
    cose_key key;
    mbedtls_pk_context pk;
    mbedtls_md_type_t md_alg;
} cose_verify_context;

typedef struct {
    cose_key key;
    int cipher;
    size_t len_mac;
    mbedtls_gcm_context gcm;
} cose_crypt_context;

int cose_sign_init(cose_sign_context * ctx,
        const uint8_t * key, const size_t len_key,
        const uint8_t * kid, const size_t len_kid);

int cose_verify_init(cose_verify_context * ctx,
        const uint8_t * key, const size_t len_key,
        const uint8_t * kid, const size_t len_kid);

int cose_crypt_init(cose_crypt_context * ctx,
        const uint8_t * key, cose_alg alg,
        const uint8_t * kid, const size_t len_kid);

void cose_sign_free(cose_sign_context * ctx);
void cose_verify_free(cose_verify_context * ctx);
void cose_crypt_free(cose_crypt_context * ctx);

int cose_sign_write(cose_sign_context * ctx, 
        const uint8_t * pld, const size_t len_pld, 
        const uint8_t * aad, const size_t len_aad,
        uint8_t * obj, size_t * len_obj);

int cose_sign_read(cose_verify_context * ctx,
        const uint8_t * obj, const size_t len_obj, 
        const uint8_t * aad, const size_t len_aad,
        uint8_t * pld, size_t * len_pld);

int cose_encrypt0_write(cose_crypt_context *ctx,
        const uint8_t * pld, const size_t len_pld, 
        const uint8_t * aad, const size_t len_aad,
        const uint8_t * iv, const size_t len_iv,
        uint8_t * obj, size_t * len_obj);

int cose_encrypt0_read(cose_crypt_context * ctx,
        const uint8_t * obj, const size_t len_obj, 
        const uint8_t * aad, const size_t len_aad,
        uint8_t * pld, size_t * len_pld);

int cose_mac0_write(cose_crypt_context *ctx,
        const uint8_t * pld, const size_t len_pld, 
        const uint8_t * aad, const size_t len_aad,
        const uint8_t * iv, const size_t len_iv,
        uint8_t * obj, size_t * len_obj);

int cose_mac0_read(cose_crypt_context * ctx,
        const uint8_t * obj, const size_t len_obj, 
        const uint8_t * aad, const size_t len_aad,
        uint8_t * pld, size_t * len_pld);

#endif /* COSE_H */
