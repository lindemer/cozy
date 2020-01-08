#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <zephyr.h>

typedef enum {
    cose_tag_sign = 98,
    cose_tag_sign1 = 18,
    cose_tag_encrypt = 96,
    cose_tag_encrypt0 = 16,
    cose_tag_mac = 97,
    cose_tag_mac0 = 17,
} cose_tag;

typedef enum {
    cose_algo_aes_gcm_128 = 1,
    cose_algo_aes_gcm_192 = 2,
    cose_algo_aes_gcm_256 = 3,
    cose_algo_hmac_256_64 = 4,
    cose_algo_hmac_256_256 = 5,
    cose_algo_hmac_384_384 = 6,
    cose_algo_hmac_512_512 = 7,
    cose_algo_cbc_mac_128_64 = 14,
    cose_algo_cbc_mac_256_64 = 15,
    cose_algo_cbc_mac_128_128 = 25,
    cose_algo_cbc_mac_256_128 = 26,
    cose_algo_aes_ccm_16_64_128 = 10,
    cose_algo_aes_ccm_16_64_256 = 11,
    cose_algo_aes_ccm_64_64_128 = 12,
    cose_algo_aes_ccm_64_64_256 = 13,
    cose_algo_aes_ccm_16_128_128 = 30,
    cose_algo_aes_ccm_16_128_256 = 31,
    cose_algo_aes_ccm_64_128_128 = 32,
    cose_algo_aes_ccm_64_128_256 = 33,
    cose_algo_ecdh_es_hkdf_256 = -25,
    cose_algo_ecdh_es_hkdf_512 = -26,
    cose_algo_ecdh_ss_hkdf_256 = -27,
    cose_algo_ecdh_ss_hkdf_512 = -28,
    cose_algo_ecdh_es_a128kw = -29,
    cose_algo_ecdh_es_a192kw = -30,
    cose_algo_ecdh_es_a256kw = -31,
    cose_algo_ecdh_ss_a128kw = -32,
    cose_algo_ecdh_ss_a192kw = -33,
    cose_algo_ecdh_ss_a256kw = -34,
    cose_algo_aes_kw_128 = -3,
    cose_algo_aes_kw_192 = -4,
    cose_algo_aes_kw_256 = -5,
    cose_algo_direct = -6,
    cose_algo_direct_hkdf_hmac_sha_256 = -10,
    cose_algo_direct_hkdf_hmac_sha_512 = -11,
    cose_algo_direct_hkdf_aes_128 = -12,
    cose_algo_direct_hkdf_aes_256 = -13,
    cose_algo_ecdsa_sha_256 = -7,
    cose_algo_ecdsa_sha_384 = -35,
    cose_algo_ecdsa_sha_512 = -36,
} cose_algo;

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
    cose_key_type_okp = 1,
    cose_key_type_ec2 = 2,
    cose_key_type_symmetric = 4,
} cose_key_type;

typedef enum {
    cose_key_ec_param_crv = -1,
    cose_key_ec_param_x = -2,
    cose_key_ec_param_y = -3,
    cose_key_ec_param_d = -4,
} cose_key_ec_param;

typedef enum {
    cose_key_octet_param_crv = -1,
    cose_key_octet_param_x = -2,
    cose_key_octet_param_d = -4,
} cose_key_octet_param;

typedef enum {
    cose_key_symmetric_param_k = -1,
} cose_key_symmetric_param;

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
    bool tagged;
    size_t payload_size;
    const uint8_t * payload;
    uint8_t * buffer;
} cose_config;

int cose_encode_sign1(cose_config * config);
int cose_encode_sign(cose_config * config);
int cose_encode_encrypt(cose_config * config);
int cose_encode_encrypt0(cose_config * config);
int cose_encode_mac(cose_config * config);
int cose_encode_mac0(cose_config * config);
