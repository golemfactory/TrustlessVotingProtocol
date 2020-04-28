#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#include "crypto_utils.h"

static int export_public_key(mbedtls_ecp_keypair* key_pair, uint8_t* public_key,
                             size_t public_key_size) {
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (!key_pair)
        goto out;

    size_t pubkey_size;
    ret = mbedtls_ecp_point_write_binary(&key_pair->grp, &key_pair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pubkey_size, NULL, 0);
    if (ret != MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL) {
        goto out;
    }

    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (pubkey_size != public_key_size) {
        goto out;
    }

    ret = mbedtls_ecp_point_write_binary(&key_pair->grp, &key_pair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pubkey_size, public_key, pubkey_size);
    if (ret != 0) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int generate_key_pair(int curve_id, mbedtls_ecp_keypair* key_pair, uint8_t* public_key,
                      size_t public_key_size, mbedtls_ctr_drbg_context* rng_ctx) {
    mbedtls_ecp_keypair_init(key_pair);
    int ret = mbedtls_ecp_gen_key(curve_id, key_pair, mbedtls_ctr_drbg_random, rng_ctx);
    if (ret != 0) {
        goto out;
    }

    ret = export_public_key(key_pair, public_key, public_key_size);
out:
    return ret;
}

static int hash_update_voter(mbedtls_sha256_context* sha, const tvp_voter_t* voter) {
    if (mbedtls_sha256_update_ret(sha, voter->public_key, sizeof(voter->public_key))) {
        return -1;
    }
    if (mbedtls_sha256_update_ret(sha, (unsigned char*)&voter->weight, sizeof(voter->weight))) {
        return -1;
    }
    return 0;
}

int hash_voting(tvp_voting_id_t* vid, const uint8_t* nonce, size_t nonce_len,
                       const tvp_msg_register_voting_eh_ve_t* vd) {
    _Static_assert(sizeof(vid->vid) == 32, "Invalid hash size!\n");
    mbedtls_sha256_context sha = { 0 };
    mbedtls_sha256_init(&sha);

    int ret = mbedtls_sha256_starts_ret(&sha, /*is224=*/0);
    if (ret) {
        goto out;
    }

    ret = mbedtls_sha256_update_ret(&sha, nonce, nonce_len);
    if (ret) {
        goto out;
    }

#define ADD_FIELD_TO_SHA(f) do {                                                        \
        ret = mbedtls_sha256_update_ret(&sha, (unsigned char*)&vd->f, sizeof(vd->f));   \
        if (ret) {                                                                      \
            goto out;                                                                   \
        }                                                                               \
    } while (0)

    ADD_FIELD_TO_SHA(start_time);
    ADD_FIELD_TO_SHA(end_time);
    ADD_FIELD_TO_SHA(num_options);
    ADD_FIELD_TO_SHA(num_voters);
    for (size_t i = 0; i < vd->num_voters; ++i) {
        ret = hash_update_voter(&sha, &vd->voters[i]);
        if (ret) {
            goto out;
        }
    }
    ADD_FIELD_TO_SHA(description_size);
    ret = mbedtls_sha256_update_ret(&sha, (unsigned char*)vd->description, vd->description_size);
    if (ret) {
        goto out;
    }
#undef ADD_FIELD_TO_SHA

    ret = mbedtls_sha256_finish_ret(&sha, vid->vid);
    if (ret) {
        goto out;
    }

    ret = 0;
out:
    mbedtls_sha256_free(&sha);
    return ret;
}

int generate_nonce(nonce_t* nonce, mbedtls_ctr_drbg_context* rng_ctx) {
    return mbedtls_ctr_drbg_random(rng_ctx, (unsigned char*)nonce, sizeof(*nonce));
}

int sign_hash(uint8_t* sig, size_t slen, const uint8_t* hash, size_t hlen, mbedtls_ecp_keypair* key,
              mbedtls_ctr_drbg_context* rng_ctx) {
    int ret = -1;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    ret = mbedtls_ecdsa_sign(&key->grp, &r, &s, &key->d, hash, hlen,
                             mbedtls_ctr_drbg_random, rng_ctx);
    if (ret) {
        goto out;
    }

    if (mbedtls_mpi_size(&r) != slen / 2 || mbedtls_mpi_size(&s) != slen / 2) {
        goto out;
    }

    ret = mbedtls_mpi_write_binary(&r, sig, slen / 2);
    if (ret) {
        goto out;
    }
    ret = mbedtls_mpi_write_binary(&s, sig + slen / 2, slen / 2);
    if (ret) {
        goto out;
    }

    ret = 0;
out:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ret;
}

int verify_hash(uint8_t* sig, size_t slen, const uint8_t* hash, size_t hlen,
                mbedtls_ecp_keypair* key) {
    int ret = -1;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    ret = mbedtls_mpi_read_binary(&r, sig, slen / 2);
    if (ret) {
        goto out;
    }
    ret = mbedtls_mpi_read_binary(&s, sig + slen / 2, slen / 2);
    if (ret) {
        goto out;
    }

    ret = mbedtls_ecdsa_verify(&key->grp, hash, hlen, &key->Q, &r, &s);
    if (ret) {
        goto out;
    }

    ret = 0;
out:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ret;
}

int kdf(uint8_t* shared_sec, size_t shared_sec_len, uint8_t* salt, size_t salt_len, uint8_t* out,
        size_t out_len) {
    int ret = -1;
    mbedtls_md_context_t sha_ctx;

    mbedtls_md_init(&sha_ctx);

    ret = mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret) {
        goto out;
    }

    /* TODO: 1000 is just for dev, increase it later. */
    ret = mbedtls_pkcs5_pbkdf2_hmac(&sha_ctx, shared_sec, shared_sec_len, salt, salt_len, 1000, out_len, out);

out:
    mbedtls_md_free(&sha_ctx);
    return ret;
}
