#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>

#include <sgx_lfence.h>
#include <sgx_thread.h>
#include <sgx_trts.h>
#include <sgx_utils.h>

#include "crypto_utils.h"
#include "tvp_msg.h"

#include "voting_enclave.h"
#include "voting_enclave_t.h"
#include "voting_enclave_mrsigner.h"

/* Intel's assert.h does not define this. */
#define static_assert _Static_assert

static bool                     g_initialized                     = false;
static uint8_t                  g_public_key[EC_PUB_KEY_SIZE]     = {0};
static uint8_t                  g_public_key_hash[sizeof(hash_t)] = {0};
static mbedtls_ecp_keypair      g_signing_key                     = {0};
static mbedtls_ecp_group        g_ec_group                        = {0};
static mbedtls_ctr_drbg_context g_rng                             = {0};
static sgx_thread_mutex_t       g_mutex = SGX_THREAD_MUTEX_INITIALIZER;

/*! Enclave flags that will matter for sealing/unsealing secrets (keys).
 *  The second field (xfrm) is set to 0 as per recommendation in the
 *  Intel SGX Developer Guide, Sealing and Unsealing Process section.
 */
static const sgx_attributes_t g_seal_attributes = {ENCLAVE_SEALING_ATTRIBUTES, 0};

typedef struct {
    tvp_voting_id_t vid;
    uint32_t num_options;
    bool started;
    size_t num_voters;
    tvp_voter_t* voters;
    tvp_registered_vote_t** votes;
} voting_t;

static voting_t g_voting = { 0 };
static bool g_voting_registered = false;

static void zero_memory(void* mem, size_t size) {
    memset_s(mem, size, 0, size);
}

#define PRINT_BUFFER_MAX 4096
static void eprintf(const char* fmt, ...) {
    char buf[PRINT_BUFFER_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, PRINT_BUFFER_MAX, fmt, ap);
    va_end(ap);
    o_print(buf);
}

static void _hexdump(void* data, size_t size) {
    uint8_t* ptr = (uint8_t*)data;

    for (size_t i = 0; i < size; i++)
        eprintf("%02x", ptr[i]);
    eprintf("\n");
}

#define hexdump(x) _hexdump((void*)&x, sizeof(x))

// Seal enclave state
static int seal_data(const mbedtls_ecp_keypair* key_pair, const uint8_t* public_key,
                     size_t public_key_size) {
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
    uint8_t* sealed_data = NULL;
    size_t sealed_size = 0;
    int ret = -1;

    eprintf("Sealing enclave state...\n");

    size_t private_key_size = mbedtls_mpi_size(&key_pair->d);
    size_t unsealed_size = private_key_size + sizeof(g_public_key);
    unsigned char* unsealed_data = malloc(unsealed_size);
    if (!unsealed_data) {
        eprintf("Failed to allocate memory\n");
        goto out;
    }

    // private key
    ret = mbedtls_mpi_write_binary(&key_pair->d, unsealed_data, private_key_size);
    if (ret != 0) {
        eprintf("Failed to get private key data: %d\n", ret);
        goto out;
    }

    // public key
    memcpy(unsealed_data + private_key_size, public_key, public_key_size);

    // We can provide additional plaintext data to be a part of the encrypted blob's MAC if needed.
    sealed_size = sgx_calc_sealed_data_size(0, unsealed_size);
    sealed_data = malloc(sealed_size);
    if (!sealed_data) {
        eprintf("Failed to allocate memory\n");
        goto out;
    }

    sgx_ret = sgx_seal_data_ex(ENCLAVE_SEALING_POLICY,
                               g_seal_attributes,
                               0, // misc mask, reserved
                               0, // additional data size
                               NULL, // no additional data
                               unsealed_size,
                               (const uint8_t*)unsealed_data,
                               sealed_size,
                               (sgx_sealed_data_t*)sealed_data);
    if (sgx_ret != SGX_SUCCESS) {
        eprintf("Failed to seal data\n");
        goto out;
    }

    sgx_ret = o_store_sealed_data(&ret, sealed_data, sealed_size);
    if (sgx_ret != SGX_SUCCESS || ret < 0) {
        eprintf("Failed to store sealed data\n");
    }

out:
    // erase private key data from memory
    if (unsealed_data) {
        zero_memory(unsealed_data, unsealed_size);
        free(unsealed_data);
    }
    free(sealed_data);

    if (sgx_ret == SGX_SUCCESS && ret == 0)
        return 0;

    return -1;
}

// Restore enclave keys from sealed data
static int unseal_data(const uint8_t* sealed_data, size_t sealed_size,
                       mbedtls_ecp_keypair* key_pair, uint8_t* public_key, size_t public_key_size,
                       uint8_t* public_key_hash) {
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
    uint8_t* unsealed_data = NULL;
    uint32_t unsealed_size = 0;

    eprintf("Unsealing enclave state...\n");

    if (sealed_size < sizeof(sgx_sealed_data_t)) {
        eprintf("Invalid sealed data\n");
        goto out;
    }

    unsealed_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t*)sealed_data);
    if (unsealed_size == UINT32_MAX) {
        eprintf("Failed to get unsealed data size\n");
        goto out;
    }

    if (unsealed_size != EC_PRIV_KEY_SIZE + public_key_size) {
        eprintf("Invalid unsealed data size\n");
        goto out;
    }

    unsealed_data = malloc(unsealed_size);
    if (!unsealed_data) {
        eprintf("Failed to allocate memory\n");
        goto out;
    }

    sgx_ret = sgx_unseal_data((const sgx_sealed_data_t*)sealed_data,
                              NULL, // no additional MAC data
                              0, // additional data size
                              unsealed_data,
                              &unsealed_size);
    if (sgx_ret != SGX_SUCCESS) {
        eprintf("Failed to unseal data: %d\n", sgx_ret);
        goto out;
    }

    sgx_ret = SGX_ERROR_UNEXPECTED;
    // recreate private key from the unsealed blob
    int ret = mbedtls_ecp_read_key(EC_CURVE_ID, key_pair, unsealed_data, EC_PRIV_KEY_SIZE);
    if (ret != 0) {
        eprintf("Failed to recreate private key: %d\n", ret);
        goto out;
    }

    ret = mbedtls_ecp_check_privkey(&g_ec_group, &key_pair->d);
    if (ret != 0) {
        eprintf("Unsealed private key is invalid: %d\n", ret);
        goto out;
    }

    memcpy(public_key, unsealed_data + EC_PRIV_KEY_SIZE, public_key_size);

    ret = mbedtls_ecp_point_read_binary(&g_ec_group, &key_pair->Q, public_key, public_key_size);
    if (ret != 0) {
        eprintf("Failed to recreate public key: %d\n", ret);
        goto out;
    }

    ret = mbedtls_ecp_check_pubkey(&g_ec_group, &key_pair->Q);
    if (ret != 0) {
        eprintf("Unsealed public key is invalid: %d\n", ret);
        goto out;
    }

    ret = mbedtls_sha256_ret(public_key, public_key_size, public_key_hash, /*is224=*/0);
    if (ret != 0) {
        eprintf("Failed to hash public key: %d\n", ret);
        goto out;
    }

    sgx_ret = SGX_SUCCESS;

out:
    // erase private key data from memory
    if (unsealed_data) {
        zero_memory(unsealed_data, unsealed_size);
        free(unsealed_data);
    }

    return sgx_ret == SGX_SUCCESS ? 0 : -1;
}

typedef enum {
    VE_NOT_INITIALIZED = 0,
    VE_INIT_OK,
    VE_INIT_FAILED // lockdown mode
} ve_init_state_t;

// global initialization, if this fails then the enclave cannot proceed
static int global_init(void) {
    static ve_init_state_t init_state = VE_NOT_INITIALIZED;

    if (init_state == VE_NOT_INITIALIZED) {
        init_state = VE_INIT_FAILED;
        eprintf("Performing global enclave initialization...\n");

        unsigned char entropy_sig[] = "voting enclave";
        mbedtls_entropy_context entropy;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&g_rng);

        int ret = mbedtls_ctr_drbg_seed(&g_rng, mbedtls_entropy_func, &entropy, entropy_sig,
                                        sizeof(entropy_sig));
        if (ret != 0) {
            eprintf("Failed to seed crypto PRNG: %d\n", ret);
            goto out;
        }

        mbedtls_ecp_group_init(&g_ec_group);
        ret = mbedtls_ecp_group_load(&g_ec_group, EC_CURVE_ID);
        if (ret != 0) {
            eprintf("Failed to load EC group: %d\n", ret);
            goto out;
        }

        init_state = VE_INIT_OK;
    }
out:
    return init_state == VE_INIT_OK ? 0 : -1;
}

/* ECALL: initialize enclave
 * If sealed_data is provided, unseal private key from it. If not, generate new key pair.
 * Enclave public key is stored in pubkey if pubkey_size is enough for it. */
int e_initialize(uint8_t* sealed_data, size_t sealed_size, uint8_t* pubkey, size_t pubkey_size) {
    int ret = -1;

    sgx_thread_mutex_lock(&g_mutex);
    if (global_init() != 0)
        goto out;

    eprintf("Enclave initializing...\n");

    mbedtls_ecp_keypair_init(&g_signing_key);
    if (sealed_data == NULL || sealed_size == 0) {
        eprintf("Generating enclave signing key...\n");
        ret = generate_key_pair(EC_CURVE_ID, &g_signing_key, g_public_key, sizeof(g_public_key),
                                &g_rng);
        if (ret < 0)
            goto out;

        ret = mbedtls_sha256_ret(g_public_key, sizeof(g_public_key), g_public_key_hash, /*is224=*/0);
        if (ret < 0)
            goto out;

        ret = seal_data(&g_signing_key, g_public_key, sizeof(g_public_key));
        if (ret < 0)
            goto out;
    } else {
        ret = unseal_data(sealed_data, sealed_size, &g_signing_key, g_public_key,
                          sizeof(g_public_key), g_public_key_hash);
        if (ret < 0)
            goto out;
    }

    if (mbedtls_mpi_size(&g_signing_key.d) != EC_PRIV_KEY_SIZE) {
        eprintf("Invalid key size: %zu\n", mbedtls_mpi_size(&g_signing_key.d));
        ret = -1;
        goto out;
    }

    eprintf("Enclave public key: ");
    hexdump(g_public_key);
    eprintf("Enclave public key hash: ");
    hexdump(g_public_key_hash);

    ret = -1;
    if (pubkey_size > 0 && pubkey_size != sizeof(g_public_key)) {
        eprintf("Invalid public key size\n");
        goto out;
    }

    if (pubkey_size == sizeof(g_public_key)) {
        eprintf("Copying enclave public key...\n");
        memcpy(pubkey, &g_public_key, sizeof(g_public_key));
    }

    eprintf("Enclave initialization OK\n");
    ret = 0;

out:
    if (ret == 0) {
        g_initialized = true;
    } else { // destroy all secrets and other data
        mbedtls_ecp_keypair_free(&g_signing_key);
        zero_memory(g_public_key, sizeof(g_public_key));
    }

    sgx_thread_mutex_unlock(&g_mutex);
    return ret;
}

static int get_report(const sgx_target_info_t* target_info, const sgx_report_data_t* report_data,
                      sgx_report_t* report) {
    sgx_status_t sgx_ret = sgx_create_report(target_info, report_data, report);
    if (sgx_ret != SGX_SUCCESS) {
        eprintf("Failed to create enclave report: %d\n", sgx_ret);
    }

    return sgx_ret == SGX_SUCCESS ? 0 : -1;
}

/* ECALL: get enclave report */
int e_get_report(const sgx_target_info_t* target_info, sgx_report_t* report) {
    if (!g_initialized)
        return -1;

    sgx_report_data_t report_data = {0};

    // Use public key hash as custom data in the report
    assert(sizeof g_public_key_hash <= sizeof report_data);
    memcpy(&report_data, g_public_key_hash, sizeof g_public_key_hash);

    return get_report(target_info, &report_data, report);
}

static int copy_untrusted_buffer(void** dest, void* src, size_t len) {
    void* buf = NULL;
    if (!*dest) {
        buf = malloc(len);
        if (!buf) {
            return -1;
        }
        *dest = buf;
    }

    if (!sgx_is_outside_enclave(src, len)) {
        goto out_err;
    }
    sgx_lfence();

    memcpy(*dest, src, len);

    return 0;

out_err:
    free(buf);
    return -1;
}

/* ECALL: register new voting */
int e_register_voting(uint8_t* voting_description, size_t vd_size,
                      uint8_t* vdve_buf, size_t vdve_size) {
    int ret = -1;
    tvp_voter_t* voters = NULL;
    char* description = NULL;
    tvp_registered_vote_t** votes = NULL;

    sgx_thread_mutex_lock(&g_mutex);

    if (!g_initialized) {
        goto out;
    }

    if (g_voting_registered) {
        eprintf("Voting already initialized!\n");
        goto out;
    }

    if (vd_size != sizeof(tvp_msg_register_voting_eh_ve_t)) {
        eprintf("Invalid voting_description size: %zu\n", vd_size);
        goto out;
    }
    if (vdve_size != sizeof(tvp_msg_register_voting_ve_eh_t)) {
        eprintf("Invalid vdve size: %zu\n", vdve_size);
        goto out;
    }

    tvp_msg_register_voting_eh_ve_t* vd = (tvp_msg_register_voting_eh_ve_t*)voting_description;

    if (copy_untrusted_buffer((void**)&voters, vd->voters, vd->num_voters * sizeof(tvp_voter_t))
            < 0) {
        eprintf("Failed to copy voters list!\n");
        goto out;
    }
    if (copy_untrusted_buffer((void**)&description, vd->description, vd->description_size) < 0) {
        eprintf("Failed to copy voting description!\n");
        goto out;
    }

    vd->voters = voters;
    vd->description = description;

    nonce_t nonce = { 0 };
    if (generate_nonce(&nonce, &g_rng)) {
        eprintf("Failed to generate a nonce!\n");
        goto out;
    }

    if (hash_voting(&g_voting.vid, (uint8_t*)&nonce, sizeof(nonce), vd)) {
        eprintf("Failed to hash voting!\n");
        goto out;
    }
    g_voting.num_options = vd->num_options;
    g_voting.num_voters = vd->num_voters;
    /* We take ownership of `voters`. */
    g_voting.voters = voters;
    voters = NULL;
    votes = calloc(g_voting.num_voters, sizeof(*votes));
    if (!votes) {
        eprintf("Failed to allocate votes buf!\n");
        goto out;
    }
    g_voting.votes = votes;
    votes = NULL;
    g_voting.started = false;

    signature_t sig = { 0 };
    if (sign_hash(&sig, (const hash_t*)&g_voting.vid, &g_signing_key, &g_rng)) {
        eprintf("Failed to sign voting hash!\n");
        goto out;
    }

    eprintf("VID: ");
    hexdump(g_voting.vid);

    tvp_msg_register_voting_ve_eh_t* vdve = (tvp_msg_register_voting_ve_eh_t*)vdve_buf;

    memcpy(&vdve->vid_nonce, &nonce, sizeof(nonce));
    memcpy(&vdve->vid_sig, &sig, sizeof(signature_t));

    g_voting_registered = true;
    ret = 0;

out:
    if (votes) {
        free(votes);
    }
    if (voters) {
        free(voters);
    }
    if (description) {
        free(description);
    }
    sgx_thread_mutex_unlock(&g_mutex);
    return ret;
}

/* ECALL: start voting */
int e_start_voting(const tvp_voting_id_t* vid) {
    int ret = -1;
    sgx_thread_mutex_lock(&g_mutex);

    if (!g_initialized) {
        goto out;
    }

    if (!g_voting_registered) {
        eprintf("No voting registered!\n");
        goto out;
    }

    if (memcmp(&g_voting.vid.vid, vid, sizeof(g_voting.vid.vid))) {
        eprintf("Voting not recognized!\n");
        goto out;
    }

    if (g_voting.started) {
        eprintf("Voting already started!\n");
        goto out;
    }

    eprintf("Voting started, VID: ");
    hexdump(g_voting.vid);
    g_voting.started = true;

    ret = 0;
out:
    sgx_thread_mutex_unlock(&g_mutex);
    return ret;
}

/*
 * ECALL: register a vote
 * enc_vote structure:
 * - sizeof(public_key_t) bytes of EC point (DH)
 * - SALT_LEN bytes of salt to KDF
 * - IV_LEN bytes of AES IV
 */
int e_register_vote(uint8_t* enc_vote, size_t enc_vote_size, uint8_t* ret_buf,
                    size_t ret_buf_size) {
    int ret = -1;
    mbedtls_mpi key;
    mbedtls_ecp_point eph_key_mat;
    mbedtls_ecp_keypair voter_key;
    mbedtls_aes_context aes_ctx;
    uint8_t* salt = NULL;
    uint8_t iv[IV_LEN];
    uint8_t* dec_vote = NULL;
    mbedtls_sha256_context sha;
    tvp_registered_vote_t* rv = NULL;

    mbedtls_sha256_init(&sha);
    mbedtls_mpi_init(&key);
    mbedtls_ecp_point_init(&eph_key_mat);
    mbedtls_ecp_keypair_init(&voter_key);
    mbedtls_aes_init(&aes_ctx);

    sgx_thread_mutex_lock(&g_mutex);

    if (!g_initialized) {
        goto out;
    }

    if (!g_voting_registered) {
        eprintf("No voting registered!\n");
        goto out;
    }

    if (!g_voting.started) {
        eprintf("Voting not in progress!\n");
        goto out;
    }

    if (enc_vote_size < sizeof(public_key_t) + SALT_LEN + IV_LEN + sizeof(tvp_msg_vote_v_ve_t)) {
        eprintf("Encrypted msg too short!\n");
        goto out;
    }
    if ((enc_vote_size - sizeof(public_key_t) - SALT_LEN - IV_LEN) % 16 != 0) {
        eprintf("Invalid length of encrypted msg!\n");
        goto out;
    }

    ret = mbedtls_ecp_point_read_binary(&g_ec_group, &eph_key_mat, enc_vote, sizeof(public_key_t));
    if (ret) {
        eprintf("Failed to parse eph_key_mat!\n");
        goto out;
    }
    enc_vote += sizeof(public_key_t);
    enc_vote_size -= sizeof(public_key_t);

    ret = mbedtls_ecdh_compute_shared(&g_signing_key.grp, &key, &eph_key_mat, &g_signing_key.d,
                                      NULL, NULL);
    if (ret) {
        goto out;
    }

    uint8_t shared[EC_PRIV_KEY_SIZE] = { 0 };
    ret = mbedtls_mpi_write_binary(&key, shared, sizeof(shared));
    if (ret) {
        goto out;
    }

    salt = enc_vote;
    enc_vote += SALT_LEN;
    enc_vote_size -= SALT_LEN;

    uint8_t aes_key[32];
    ret = kdf(shared, sizeof(shared), salt, SALT_LEN, aes_key, sizeof(aes_key));
    if (ret) {
        eprintf("Failed to derive aes key!\n");
        goto out;
    }

    ret = mbedtls_aes_setkey_dec(&aes_ctx, aes_key, 8 * sizeof(aes_key));
    if (ret) {
        goto out;
    }

    memcpy(iv, enc_vote, sizeof(iv));
    enc_vote += IV_LEN;
    enc_vote_size -= IV_LEN;

    dec_vote = calloc(enc_vote_size, 1);
    if (!dec_vote) {
        goto out;
    }

    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, enc_vote_size, iv, enc_vote,
                                dec_vote);
    if (ret) {
        eprintf("Decryption failed!\n");
        goto out;
    }

    tvp_msg_vote_v_ve_t* vote = (tvp_msg_vote_v_ve_t*)dec_vote;

    ret = mbedtls_ecp_group_copy(&voter_key.grp, &g_ec_group);
    if (ret) {
        eprintf("Failed to copy group!\n");
        goto out;
    }
    ret = mbedtls_ecp_point_read_binary(&voter_key.grp, &voter_key.Q, vote->vote.voter,
                                        sizeof(vote->vote.voter));
    if (ret) {
        eprintf("Failed to parse voter public key!\n");
        goto out;
    }

    hash_t hash;
    ret = mbedtls_sha256_ret((uint8_t*)&vote->vote, sizeof(vote->vote), hash, /*is224=*/0);
    if (ret) {
        goto out;
    }

    ret = verify_hash(&vote->sig, &hash, &voter_key);
    if (ret) {
        eprintf("Wrong signature!\n");
        goto out;
    }

    if (memcmp(&g_voting.vid.vid, &vote->vote.vid, sizeof(g_voting.vid.vid))) {
        eprintf("Voting not recognized!\n");
        goto out;
    }

    size_t voter_id = 0;
    for (size_t i = 0; i < g_voting.num_voters; ++i) {
        if (!memcmp(&g_voting.voters[i].public_key, &vote->vote.voter, sizeof(vote->vote.voter))) {
            voter_id = i + 1;
            break;
        }
    }
    if (!voter_id) {
        eprintf("Voter not recognized!\n");
        goto out;
    }
    voter_id -= 1;

    if (vote->vote.option == 0 || vote->vote.option > g_voting.num_options) {
        eprintf("Invalid voting option!\n");
        ret = -2;
        goto out;
    }

    if (g_voting.votes[voter_id] != NULL) {
        goto out_send_result;
    }

    rv = malloc(sizeof(*rv));
    if (!rv) {
        goto out;
    }

    memcpy(&rv->vote, &vote->vote, sizeof(rv->vote));

    if (generate_nonce(&rv->nonce, &g_rng)) {
        eprintf("Failed to generate a nonce!\n");
        goto out;
    }

    g_voting.votes[voter_id] = rv;
    rv = NULL;

out_send_result:
    mbedtls_aes_free(&aes_ctx);
    mbedtls_aes_init(&aes_ctx);

    ret = mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 8 * sizeof(aes_key));
    if (ret) {
        goto out;
    }

    ret = mbedtls_ctr_drbg_random(&g_rng, iv, sizeof(iv));
    if (ret) {
        goto out;
    }

    unsigned char vvr_data[SIZE_WITH_PAD(sizeof(tvp_msg_vote_ve_v_t))] = { 0 };
    tvp_msg_vote_ve_v_t* vvr = (tvp_msg_vote_ve_v_t*)&vvr_data;
    memcpy(&vvr->rv, g_voting.votes[voter_id], sizeof(vvr->rv));

    ret = mbedtls_sha256_ret((uint8_t*)&vvr->rv, sizeof(vvr->rv), hash, /*is224=*/0);
    if (ret) {
        goto out;
    }

    ret = mbedtls_sha256_starts_ret(&sha, /*is224=*/0);
    if (ret) {
        goto out;
    }
    ret = mbedtls_sha256_update_ret(&sha, hash, sizeof(hash));
    if (ret) {
        goto out;
    }
    ret = mbedtls_sha256_update_ret(&sha, (uint8_t*)&vvr->rv.vote.vid, sizeof(vvr->rv.vote.vid));
    if (ret) {
        goto out;
    }
    ret = mbedtls_sha256_finish_ret(&sha, hash);
    if (ret) {
        goto out;
    }

    if (sign_hash(&vvr->sig, &hash, &g_signing_key, &g_rng)) {
        goto out;
    }

    if (ret_buf_size != IV_LEN + sizeof(vvr_data)) {
        eprintf("Invalid ret_buf size!\n");
        goto out;
    }

    /* Add padding */
    for (size_t i = sizeof(*vvr); i < sizeof(vvr_data); ++i) {
        vvr_data[i] = sizeof(vvr_data) - sizeof(*vvr);
    }

    memcpy(ret_buf, &iv, IV_LEN);
    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, sizeof(vvr_data), iv, vvr_data,
                                ret_buf + IV_LEN);
    if (ret) {
        eprintf("Encryption failed!\n");
        goto out;
    }

out:
    sgx_thread_mutex_unlock(&g_mutex);
    mbedtls_sha256_free(&sha);
    free(rv);
    free(dec_vote);
    mbedtls_aes_free(&aes_ctx);
    mbedtls_ecp_keypair_free(&voter_key);
    mbedtls_mpi_free(&key);
    return ret;
}

void mbedtls_platform_zeroize(void* buf, size_t size) {
    zero_memory(buf, size);
}

int mbedtls_hardware_poll(void* data, unsigned char* output, size_t len, size_t* olen) {
    (void)data; // not used
    assert(output && olen);
    *olen = 0;

    sgx_status_t sgx_ret = sgx_read_rand(output, len);
    if (sgx_ret != SGX_SUCCESS) {
        eprintf("Failed to read random data: %d\n", sgx_ret);
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    *olen = len;
    return 0;
}
