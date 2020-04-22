#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>

#include <sgx_thread.h>
#include <sgx_utils.h>

#include "voting_enclave.h"
#include "voting_enclave_t.h"
#include "voting_enclave_mrsigner.h"

bool                     g_initialized             = false;
uint8_t                  g_public_key[EC_KEY_SIZE] = {0};
mbedtls_ecp_keypair      g_signing_key             = {0};
mbedtls_ecp_group        g_ec_group                = {0};
mbedtls_ctr_drbg_context g_rng                     = {0};
sgx_thread_mutex_t       g_mutex = SGX_THREAD_MUTEX_INITIALIZER;

/*! Enclave flags that will matter for sealing/unsealing secrets (keys).
 *  The second field (xfrm) is set to 0 as per recommendation in the
 *  Intel SGX Developer Guide, Sealing and Unsealing Process section.
 */
const sgx_attributes_t g_seal_attributes = {ENCLAVE_SEALING_ATTRIBUTES, 0};

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

static int export_public_key(mbedtls_ecp_keypair* key_pair, uint8_t* public_key,
                             size_t public_key_size) {
    int ret = -1;
    if (!key_pair)
        goto out;

    size_t pubkey_size;
    ret = mbedtls_ecp_point_write_binary(&g_ec_group, &key_pair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pubkey_size, NULL, 0);
    if (ret != MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL) {
        eprintf("Failed to get public key size: %d\n", ret);
        goto out;
    }

    if (pubkey_size != public_key_size) {
        eprintf("Invalid public key size\n");
        goto out;
    }

    ret = mbedtls_ecp_point_write_binary(&g_ec_group, &key_pair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pubkey_size, public_key, pubkey_size);
    if (ret != 0) {
        eprintf("Failed to get public key: %d\n", ret);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int generate_key_pair(mbedtls_ecp_keypair* key_pair, uint8_t* public_key,
                             size_t public_key_size) {
    eprintf("Generating enclave signing key...\n");

    mbedtls_ecp_keypair_init(key_pair);
    int ret = mbedtls_ecp_gen_key(EC_CURVE_ID, key_pair, mbedtls_ctr_drbg_random, &g_rng);
    if (ret != 0) {
        eprintf("Failed to generate signing key: %d\n", ret);
        goto out;
    }

    eprintf("Generated signing private key size: %d\n", mbedtls_mpi_size(&key_pair->d));

    ret = export_public_key(key_pair, public_key, public_key_size);
out:
    return ret;
}

static void destroy_key_pair(mbedtls_ecp_keypair* key_pair) {
    mbedtls_ecp_keypair_free(key_pair);
}

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
    // function that restores it expects little-endian data so we use this write variant
    ret = mbedtls_mpi_write_binary_le(&key_pair->d, unsealed_data, private_key_size);
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
static int unseal_data(const uint8_t* sealed_data, size_t sealed_size, mbedtls_ecp_keypair* key_pair,
                       uint8_t* public_key, size_t public_key_size) {
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

    if (unsealed_size != EC_KEY_SIZE + public_key_size) {
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
    int ret = mbedtls_ecp_read_key(EC_CURVE_ID, key_pair, unsealed_data, EC_KEY_SIZE);
    if (ret != 0) {
        eprintf("Failed to recreate private key: %d\n", ret);
        goto out;
    }

    ret = mbedtls_ecp_check_privkey(&g_ec_group, &key_pair->d);
    if (ret != 0) {
        eprintf("Unsealed private key in invalid: %d\n", ret);
        goto out;
    }

    memcpy(public_key, unsealed_data + EC_KEY_SIZE, public_key_size);

    ret = mbedtls_ecp_point_read_binary(&g_ec_group, &key_pair->Q, public_key, public_key_size);
    if (ret != 0) {
        eprintf("Failed to recreate public key: %d\n", ret);
        goto out;
    }

    ret = mbedtls_ecp_check_pubkey(&g_ec_group, &key_pair->Q);
    if (ret != 0) {
        eprintf("Unsealed public key in invalid: %d\n", ret);
        goto out;
    }

    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);

    /* For some reasone mbedtls_ecp_mul grp argument is non-const, copying just in case. */
    mbedtls_ecp_group_copy(&grp, &key_pair->grp);

    ret = mbedtls_ecp_mul(&grp, &Q, &key_pair->d, &key_pair->grp.G, NULL, NULL);
    if (ret != 0) {
        eprintf("Failed to generate public key from private: %d\n", ret);
        goto out;
    }

    if (mbedtls_ecp_point_cmp(&Q, &key_pair->Q)) {
        eprintf("Unsealed public key does not match private key!\n");
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
        ret = generate_key_pair(&g_signing_key, g_public_key, sizeof(g_public_key));
        if (ret < 0)
            goto out;

        ret = seal_data(&g_signing_key, g_public_key, sizeof(g_public_key));
        if (ret < 0)
            goto out;
    } else {
        ret = unseal_data(sealed_data, sealed_size, &g_signing_key, g_public_key,
                          sizeof(g_public_key));
        if (ret < 0)
            goto out;
    }

    eprintf("Enclave public key: ");
    hexdump(g_public_key);

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
        destroy_key_pair(&g_signing_key);
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

    // Use public key as custom data in the report
    assert(sizeof g_public_key <= sizeof report_data);
    memcpy(&report_data, g_public_key, sizeof g_public_key);

    return get_report(target_info, &report_data, report);
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
