#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>

#include <mbedtls/sha256.h>
#include <sgx_uae_service.h>

#include "ve_user.h"
#include "voting_enclave.h"
#include "voting_enclave_u.h"

ssize_t get_file_size(int fd) {
    struct stat st;

    if (fstat(fd, &st) != 0)
        return -1;

    return st.st_size;
}

void* read_file(void* buffer, const char* path, size_t* size) {
    FILE* f = NULL;
    ssize_t fs = 0;
    void* buf = buffer;

    if (!size || !path)
        return NULL;

    f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open file '%s' for reading: %s\n", path, strerror(errno));
        goto out;
    }

    if (*size == 0) { // read whole file
        fs = get_file_size(fileno(f));
        if (fs < 0) {
            fprintf(stderr, "Failed to get size of file '%s': %s\n", path, strerror(errno));
            goto out;
        }
    } else {
        fs = *size;
    }

    if (!buffer) {
        buffer = malloc(fs);
        if (!buffer) {
            fprintf(stderr, "No memory\n");
            goto out;
        }
    }

    if (fread(buffer, fs, 1, f) != 1) {
        fprintf(stderr, "Failed to read file '%s'\n", path);
        if (!buf) {
            free(buffer);
            buffer = NULL;
        }
    }

out:
    if (f)
        fclose(f);

    if (*size == 0)
        *size = fs;

    return buffer;
}

int write_file(const char* path, size_t size, const void* buffer) {
    FILE* f = NULL;
    int status;

    f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open file '%s' for writing: %s\n", path, strerror(errno));
        goto out;
    }

    if (size > 0 && buffer) {
        if (fwrite(buffer, size, 1, f) != 1) {
            fprintf(stderr, "Failed to write file '%s': %s\n", path, strerror(errno));
            goto out;
        }
    }

    errno = 0;

out:
    status = errno;
    if (f)
        fclose(f);
    return status;
}

/* Returns 0 on failure */
static sgx_enclave_id_t enclave_load(const char* enclave_path, bool debug_enabled) {
    int is_token_updated = 0;
    sgx_launch_token_t launch_token = {0};
    sgx_misc_attribute_t misc_attribs = {0};
    sgx_enclave_id_t enclave_id = 0;

    printf("Loading enclave from file '%s'\n", enclave_path);

    sgx_status_t sgx_ret = sgx_create_enclave(enclave_path, debug_enabled, &launch_token,
                                              &is_token_updated, &enclave_id, &misc_attribs);
    if (sgx_ret != SGX_SUCCESS) {
        fprintf(stderr, "Failed to load enclave: %d\n", sgx_ret);
    } else {
        printf("Enclave loaded successfully, id = 0x%lx\n", enclave_id);
    }

    return enclave_id;
}

static sgx_status_t enclave_unload(sgx_enclave_id_t enclave_id) {
    sgx_status_t sgx_ret = sgx_destroy_enclave(enclave_id);
    if (sgx_ret != SGX_SUCCESS)
        fprintf(stderr, "Failed to unload enclave\n");
    else
        printf("Enclave unloaded\n");

    return sgx_ret;
}

static sgx_enclave_id_t g_enclave_id = 0;
static const char* g_sealed_state_path = NULL;

static int load_ve(const char* enclave_path, bool debug_enabled, const char* sealed_state_path,
                   bool load_sealed_state, const char* public_key_path) {
    int ret = -1;
    uint8_t* sealed_state = NULL;

    if (g_enclave_id != 0) {
        fprintf(stderr, "Enclave already loaded with id %lu\n", g_enclave_id);
        goto out;
    }

    g_sealed_state_path = sealed_state_path;

    g_enclave_id = enclave_load(enclave_path, debug_enabled);
    if (g_enclave_id == 0)
        goto out;

    size_t sealed_size = 0;

    if (load_sealed_state) {
        printf("Loading sealed enclave state from '%s'\n", sealed_state_path);
        sealed_state = read_file(NULL, sealed_state_path, &sealed_size); // may return NULL
        if (sealed_state == NULL)
            goto out;
    }

    uint8_t enclave_public_key[EC_KEY_SIZE];
    // ECALL: enclave initialization
    sgx_status_t sgx_ret;
    if (public_key_path) {
        sgx_ret = e_initialize(g_enclave_id, &ret, sealed_state, sealed_size, enclave_public_key,
                               EC_KEY_SIZE);
    } else {
        sgx_ret = e_initialize(g_enclave_id, &ret, sealed_state, sealed_size, NULL, 0);
    }

    if (sgx_ret != SGX_SUCCESS) {
        fprintf(stderr, "Failed to call enclave initialization\n");
        goto out;
    }

    if (ret < 0) {
        fprintf(stderr, "Enclave initialization failed\n");
        goto out;
    }

    if (public_key_path) {
        printf("Saving public enclave key to '%s'\n", public_key_path);
        ret = write_file(public_key_path, EC_KEY_SIZE, &enclave_public_key);
    } else {
        ret = 0;
    }

out:
    free(sealed_state);
    return ret;
}

static int generate_enclave_quote(sgx_spid_t sp_id, sgx_quote_sign_type_t quote_type,
                                  const char* quote_path) {
    int ret = -1;
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
    sgx_epid_group_id_t epid_group_id = { 0 };
    sgx_target_info_t qe_info = { 0 };
    sgx_report_t report = { 0 };
    sgx_quote_nonce_t qe_nonce = { 0 };
    sgx_report_t qe_report = { 0 };
    uint32_t quote_size = 0;
    sgx_quote_t* quote = NULL;
    mbedtls_sha256_context sha = { 0 };

    if (g_enclave_id == 0) {
        fprintf(stderr, "Enclave not loaded\n");
        goto out;
    }

    // Initialize the quoting process, get quoting enclave info
    sgx_ret = sgx_init_quote(&qe_info, &epid_group_id);
    if (sgx_ret != SGX_SUCCESS) {
        fprintf(stderr, "Failed to initialize quoting process\n");
        goto out;
    }

    // TODO: use revocation list from IAS if available
    sgx_ret = sgx_calc_quote_size(NULL, 0, &quote_size);

    if (sgx_ret != SGX_SUCCESS) {
        fprintf(stderr, "Failed to calculate quote size\n");
        goto out;
    }

    quote = malloc(quote_size);
    if (!quote) {
        fprintf(stderr, "No memory\n");
        goto out;
    }

    // ECALL: generate enclave's report, targeted to Quoting Enclave (QE)
    sgx_ret = e_get_report(g_enclave_id, &ret, &qe_info, &report);
    if (sgx_ret != SGX_SUCCESS || ret < 0) {
        ret = -1;
        fprintf(stderr, "Failed to get enclave's report\n");
        goto out;
    }

    // Prepare random nonce
    // TODO: ideally this nonce would be received from a 3rd party on a different system
    // that will verify the QE report
    size_t nonce_size = sizeof(qe_nonce);
    if (!read_file(&qe_nonce, "/dev/urandom", &nonce_size)) {
        ret = -1;
        goto out;
    }

    // Get enclave's quote. TODO: use revocation list
    sgx_ret = sgx_get_quote(&report,
                            quote_type,
                            &sp_id, // service provider id
                            &qe_nonce, // nonce for QE report
                            NULL, // no revocation list
                            0, // revocation list size
                            &qe_report, // optional QE report
                            quote,
                            quote_size);

    if (sgx_ret != SGX_SUCCESS) {
        ret = -1;
        fprintf(stderr, "Failed to get enclave quote: %d\n", sgx_ret);
        goto out;
    }

    // Calculate expected qe_report.body.report_data
    // It should be sha256(nonce||quote)
    uint8_t hash[32];

    mbedtls_sha256_init(&sha);
    ret = mbedtls_sha256_starts_ret(&sha, /*is224=*/0);
    if (ret != 0) {
        fprintf(stderr, "Failed to start nonce hash: %d\n", ret);
        goto out;
    }

    ret = mbedtls_sha256_update_ret(&sha, (const unsigned char*)&qe_nonce, sizeof(qe_nonce));
    if (ret != 0) {
        fprintf(stderr, "Failed to calculate nonce hash: %d\n", ret);
        goto out;
    }

    ret = mbedtls_sha256_update_ret(&sha, (const unsigned char*)quote, quote_size);
    if (ret != 0) {
        fprintf(stderr, "Failed to calculate nonce hash: %d\n", ret);
        goto out;
    }

    ret = mbedtls_sha256_finish_ret(&sha, hash);
    if (ret != 0) {
        fprintf(stderr, "Failed to finish nonce hash: %d\n", ret);
        goto out;
    }

    if (memcmp(&qe_report.body.report_data, hash, sizeof(hash)) != 0) {
        fprintf(stderr, "Quoting Enclave report contains invalid data\n");
        goto out;
    }

    if (write_file(quote_path, quote_size, quote) == 0) {
        printf("Enclave quote saved to '%s'\n", quote_path);
    } else {
        goto out;
    }

    ret = 0;
out:
    mbedtls_sha256_free(&sha);
    free(quote);
    return ret;
}

int ve_init_enclave(const char* enclave_path, const char* sp_id_str, const char* sp_quote_type_str,
                    const char* sealed_state_path, const char* enclave_pubkey_path,
                    const char* quote_path) {
    sgx_spid_t sp_id = { 0 };
    sgx_quote_sign_type_t sp_quote_type;

    int ret = load_ve(enclave_path, ENCLAVE_DEBUG_ENABLED, sealed_state_path,
                      false, // overwrite existing sealed state
                      enclave_pubkey_path); // export public key
    if (ret < 0)
        goto out;

    ret = -1;
    // parse SPID
    if (strlen(sp_id_str) != 32) {
        fprintf(stderr, "Invalid SPID: %s\n", sp_id_str);
        goto out;
    }

    for (int i = 0; i < 16; i++) {
        if (!isxdigit(sp_id_str[i * 2]) || !isxdigit(sp_id_str[i * 2 + 1])) {
            fprintf(stderr, "Invalid SPID: %s\n", sp_id_str);
            goto out;
        }

        sscanf(sp_id_str + i * 2, "%02hhx", &sp_id.id[i]);
    }

    // parse quote type
    if (*sp_quote_type_str == 'l' || *sp_quote_type_str == 'L') {
        sp_quote_type = SGX_LINKABLE_SIGNATURE;
    } else if (*sp_quote_type_str == 'u' || *sp_quote_type_str == 'U') {
        sp_quote_type = SGX_UNLINKABLE_SIGNATURE;
    } else {
        fprintf(stderr, "Invalid quote type: %s\n", sp_quote_type_str);
        goto out;
    }

    ret = generate_enclave_quote(sp_id, sp_quote_type, quote_path);
out:
    return ret;
}

int ve_load_enclave(const char* enclave_path, const char* sealed_state_path) {
    return load_ve(enclave_path, ENCLAVE_DEBUG_ENABLED, sealed_state_path,
                   true, // load existing sealed state
                   NULL); // don't export public key
}

int ve_unload_enclave(void) {
    if (g_enclave_id == 0)
        return 0;
    int ret = enclave_unload(g_enclave_id);
    if (ret == 0)
        g_enclave_id = 0;
    return ret;
}

// OCALL: save sealed enclave state
int o_store_sealed_data(const uint8_t* sealed_data, size_t sealed_size) {
    printf("Saving sealed enclave state to '%s'\n", g_sealed_state_path);
    return write_file(g_sealed_state_path, sealed_size, sealed_data);
}

// OCALL: print string
void o_print(const char* str) {
    static bool nl = true;
    if (nl) {
        printf("[VE] ");
        nl = false;
    }

    printf("%s", str);
    if (str[strlen(str) - 1] == '\n')
        nl = true;
}

// mbedtls callbacks
// TODO: this would not be needed if we rebuilt mbedtls a second time just for non-enclave binaries

void mbedtls_platform_zeroize(void* buf, size_t size) {
    // TODO: use proper function like memset_s (Ubuntu 16.04 has too old glibc)
    memset(buf, 0, size);
}
