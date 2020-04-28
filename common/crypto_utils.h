#ifndef _CRYPTO_UTILS_H
#define _CRYPTO_UTILS_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>

#include "tvp_msg.h"

int generate_key_pair(int curve_id, mbedtls_ecp_keypair* key_pair, uint8_t* public_key,
                      size_t public_key_size, mbedtls_ctr_drbg_context* rng_ctx);

int hash_voting(tvp_voting_id_t* vid, const uint8_t* nonce, size_t nonce_len,
                       const tvp_msg_register_voting_eh_ve_t* vd);

int generate_nonce(nonce_t* nonce, mbedtls_ctr_drbg_context* rng_ctx);

int sign_hash(uint8_t* sig, size_t slen, const uint8_t* hash, size_t hlen, mbedtls_ecp_keypair* key,
              mbedtls_ctr_drbg_context* rng_ctx);

int verify_hash(uint8_t* sig, size_t slen, const uint8_t* hash, size_t hlen,
                mbedtls_ecp_keypair* key);

int kdf(uint8_t* shared_sec, size_t shared_sec_len, uint8_t* salt, size_t salt_len, uint8_t* out,
        size_t out_len);

#endif // _CRYPTO_UTILS_H
