#ifndef _CRYPTO_UTILS_H
#define _CRYPTO_UTILS_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>

#include "tvp_msg.h"

int generate_key_pair(int curve_id, mbedtls_ecp_keypair* key_pair, public_key_t* public_key,
                      mbedtls_ctr_drbg_context* rng_ctx);

int hash_voting(tvp_voting_id_t* vid, const nonce_t* nonce,
                const tvp_msg_register_voting_eh_ve_t* vd);

int generate_nonce(nonce_t* nonce, mbedtls_ctr_drbg_context* rng_ctx);

int sign_hash(signature_t* sig, const hash_t* hash, mbedtls_ecp_keypair* key,
              mbedtls_ctr_drbg_context* rng_ctx);

int verify_hash(const signature_t* sig, const hash_t* hash, mbedtls_ecp_keypair* key);

int kdf(uint8_t* shared_sec, size_t shared_sec_len, uint8_t* salt, size_t salt_len, uint8_t* out,
        size_t out_len);

#endif // _CRYPTO_UTILS_H
