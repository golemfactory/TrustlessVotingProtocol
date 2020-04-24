#include <stdbool.h>

#include <mbedtls/sha256.h>

#include "tvp_msg.h"
#include "util.h"
#include "ve_user.h"
#include "voting_enclave.h"
#include "voting_enclave_u.h"

static sgx_enclave_id_t g_enclave_id = 0;
static const char* g_sealed_state_path = NULL;

static int load_ve(const char* enclave_path, bool debug_enabled, const char* sealed_state_path,
                   bool load_sealed_state, const char* public_key_path) {
    int ret = -1;
    uint8_t* sealed_state = NULL;

    if (g_enclave_id != 0) {
        ERROR("Enclave already loaded with id %lu\n", g_enclave_id);
        goto out;
    }

    g_sealed_state_path = sealed_state_path;

    g_enclave_id = enclave_load(enclave_path, debug_enabled);
    if (g_enclave_id == 0)
        goto out;

    size_t sealed_size = 0;

    if (load_sealed_state) {
        INFO("Loading sealed enclave state from '%s'\n", sealed_state_path);
        sealed_state = read_file(sealed_state_path, NULL, &sealed_size); // may return NULL
        if (sealed_state == NULL)
            goto out;
    }

    uint8_t enclave_public_key[EC_PUB_KEY_SIZE];
    // ECALL: enclave initialization
    sgx_status_t sgx_ret;
    if (public_key_path) {
        sgx_ret = e_initialize(g_enclave_id, &ret, sealed_state, sealed_size, enclave_public_key,
                               EC_PUB_KEY_SIZE);
    } else {
        sgx_ret = e_initialize(g_enclave_id, &ret, sealed_state, sealed_size, NULL, 0);
    }

    if (sgx_ret != SGX_SUCCESS) {
        ERROR("Failed to call enclave initialization\n");
        goto out;
    }

    if (ret < 0) {
        ERROR("Enclave initialization failed\n");
        goto out;
    }

    if (public_key_path) {
        INFO("Saving public enclave key to '%s'\n", public_key_path);
        ret = write_file(public_key_path, &enclave_public_key, EC_PUB_KEY_SIZE);
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
        ERROR("Enclave not loaded\n");
        goto out;
    }

    // Initialize the quoting process, get quoting enclave info
    sgx_ret = sgx_init_quote(&qe_info, &epid_group_id);
    if (sgx_ret != SGX_SUCCESS) {
        ERROR("Failed to initialize quoting process\n");
        goto out;
    }

    // TODO: use revocation list from IAS if available
    sgx_ret = sgx_calc_quote_size(NULL, 0, &quote_size);

    if (sgx_ret != SGX_SUCCESS) {
        ERROR("Failed to calculate quote size\n");
        goto out;
    }

    quote = malloc(quote_size);
    if (!quote) {
        ERROR("No memory\n");
        goto out;
    }

    // ECALL: generate enclave's report, targeted to Quoting Enclave (QE)
    sgx_ret = e_get_report(g_enclave_id, &ret, &qe_info, &report);
    if (sgx_ret != SGX_SUCCESS || ret < 0) {
        ret = -1;
        ERROR("Failed to get enclave's report\n");
        goto out;
    }

    // Prepare random nonce
    // TODO: ideally this nonce would be received from a 3rd party on a different system
    // that will verify the QE report
    size_t nonce_size = sizeof(qe_nonce);
    if (!read_file("/dev/urandom", &qe_nonce, &nonce_size)) {
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
        ERROR("Failed to get enclave quote: %d\n", sgx_ret);
        goto out;
    }

    // Calculate expected qe_report.body.report_data
    // It should be sha256(nonce||quote)
    uint8_t hash[32];

    mbedtls_sha256_init(&sha);
    ret = mbedtls_sha256_starts_ret(&sha, /*is224=*/0);
    if (ret != 0) {
        ERROR("Failed to start nonce hash: %d\n", ret);
        goto out;
    }

    ret = mbedtls_sha256_update_ret(&sha, (const unsigned char*)&qe_nonce, sizeof(qe_nonce));
    if (ret != 0) {
        ERROR("Failed to calculate nonce hash: %d\n", ret);
        goto out;
    }

    ret = mbedtls_sha256_update_ret(&sha, (const unsigned char*)quote, quote_size);
    if (ret != 0) {
        ERROR("Failed to calculate nonce hash: %d\n", ret);
        goto out;
    }

    ret = mbedtls_sha256_finish_ret(&sha, hash);
    if (ret != 0) {
        ERROR("Failed to finish nonce hash: %d\n", ret);
        goto out;
    }

    if (memcmp(&qe_report.body.report_data, hash, sizeof(hash)) != 0) {
        ERROR("Quoting Enclave report contains invalid data\n");
        goto out;
    }

    if (write_file(quote_path, quote, quote_size) == 0) {
        INFO("Enclave quote saved to '%s'\n", quote_path);
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

    // parse SPID
    ret = parse_hex(sp_id_str, &sp_id, sizeof(sp_id));
    if (ret < 0) {
        ERROR("Invalid SPID: %s\n", sp_id_str);
        goto out;
    }

    // parse quote type
    if (*sp_quote_type_str == 'l' || *sp_quote_type_str == 'L') {
        sp_quote_type = SGX_LINKABLE_SIGNATURE;
    } else if (*sp_quote_type_str == 'u' || *sp_quote_type_str == 'U') {
        sp_quote_type = SGX_UNLINKABLE_SIGNATURE;
    } else {
        ERROR("Invalid quote type: %s\n", sp_quote_type_str);
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

int ve_submit_voting(void) {
    /* Just a testing data.
     * TODO: receive it from outside. */
    tvp_voter_t voters[2] = {
        { "a", 3},
        { "b", 4},
    };
    tvp_msg_register_voting_eh_ve_t voting_description = {
        .num_options = 4,
        .num_voters = 2,
        .voters = voters,
        .description_size = 4,
        .description = "abcd",
    };

    tvp_msg_register_voting_ve_eh_t vdve = { 0 };

    int ret = 0;
    sgx_status_t sgx_ret = e_register_voting(g_enclave_id, &ret,
                                (uint8_t*)&voting_description, sizeof(voting_description),
                                (uint8_t*)&vdve, sizeof(vdve));
    if (sgx_ret != SGX_SUCCESS || ret < 0) {
        ERROR("Voting registration failed: %d\n", ret);
        return ret;
    }

    INFO("Nonce: ");
    HEXDUMP(vdve.vid_nonce);
    INFO("Sig: ");
    HEXDUMP(vdve.vid_sig);

    return 0;
}

// OCALL: save sealed enclave state
int o_store_sealed_data(const uint8_t* sealed_data, size_t sealed_size) {
    INFO("Saving sealed enclave state to '%s'\n", g_sealed_state_path);
    return write_file(g_sealed_state_path, sealed_data, sealed_size);
}

// OCALL: print string
void o_print(const char* str) {
    static bool nl = true;
    if (nl) {
        INFO("[VE] ");
        nl = false;
    }

    INFO("%s", str);
    if (str[strlen(str) - 1] == '\n')
        nl = true;
}
