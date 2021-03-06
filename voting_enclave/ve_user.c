#include <stdbool.h>

#include <mbedtls/sha256.h>

#include "ias.h"
#include "tvp_msg.h"
#include "util.h"
#include "ve_user.h"
#include "voting_enclave.h"
#include "voting_enclave_u.h"

static sgx_enclave_id_t g_enclave_id = 0;
static const char* g_sealed_state_path = NULL;

static int load_ve(const char* enclave_path, bool debug_enabled, const char* sealed_state_path,
                   bool load_sealed_state, public_key_t* enclave_pubkey) {
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

    // ECALL: enclave initialization
    sgx_status_t sgx_ret;
    if (enclave_pubkey) {
        sgx_ret = e_initialize(g_enclave_id, &ret, sealed_state, sealed_size, enclave_pubkey);
    } else {
        sgx_ret = e_initialize(g_enclave_id, &ret, sealed_state, sealed_size, NULL);
    }

    if (sgx_ret != SGX_SUCCESS) {
        ERROR("Failed to call enclave initialization\n");
        goto out;
    }

    if (ret < 0) {
        ERROR("Enclave initialization failed\n");
        goto out;
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

    INFO("MR_ENCLAVE: ");
    HEXDUMP(report.body.mr_enclave);
    INFO("MR_SIGNER:  ");
    HEXDUMP(report.body.mr_signer);
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

int ve_generate_keys(const char* enclave_path, const char* sealed_state_path,
                     public_key_t* enclave_pubkey) {
    return load_ve(enclave_path, ENCLAVE_DEBUG_ENABLED, sealed_state_path,
                   false, // overwrite existing sealed state
                   enclave_pubkey); // export public key
}

int ve_get_quote(const char* sp_id_str, const char* sp_quote_type_str, const char* quote_path) {
    sgx_spid_t sp_id = { 0 };
    sgx_quote_sign_type_t sp_quote_type;

    // parse SPID
    int ret = parse_hex(sp_id_str, &sp_id, sizeof(sp_id));
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

int ve_verify_quote(const char* ias_api_key, const char* nonce, const char* quote_path,
                    const char* report_path, const char* sig_path) {
    int ret = -1;
    void* quote_data = NULL;

    if (!ias_api_key || !quote_path || !report_path)
        goto out;

    struct ias_context_t* ias = ias_init(ias_api_key, IAS_URL_REPORT, IAS_URL_SIGRL);
    size_t quote_size = 0;
    quote_data = read_file(quote_path, NULL, &quote_size);
    if (!quote_data)
        goto out;

    if (quote_size < sizeof(sgx_quote_t)) {
        ERROR("Quote is too small\n");
        goto out;
    }

    sgx_quote_t* quote = (sgx_quote_t*)quote_data;
    if (quote_size < sizeof(sgx_quote_t) + quote->signature_len) {
        ERROR("Quote is too small\n");
        goto out;
    }
    quote_size = sizeof(sgx_quote_t) + quote->signature_len;

    ret = ias_verify_quote(ias, quote_data, quote_size, nonce, report_path, sig_path, NULL, NULL);

out:
    free(quote_data);
    return ret;
}

int ve_load_enclave(const char* enclave_path, const char* sealed_state_path,
                    public_key_t* enclave_pubkey) {
    return load_ve(enclave_path, ENCLAVE_DEBUG_ENABLED, sealed_state_path,
                   true, // load existing sealed state
                   enclave_pubkey);
}

int ve_unload_enclave(void) {
    if (g_enclave_id == 0)
        return 0;
    int ret = enclave_unload(g_enclave_id);
    if (ret == 0)
        g_enclave_id = 0;
    return ret;
}

int ve_register_voting(const tvp_msg_register_voting_eh_ve_t* vd,
                       tvp_msg_register_voting_ve_eh_t* vdve) {
    int ret = -1;
    sgx_status_t sgx_ret = e_register_voting(g_enclave_id, &ret,
                                             vd, sizeof(*vd),
                                             vdve, sizeof(*vdve));
    if (sgx_ret != SGX_SUCCESS || ret < 0) {
        ERROR("Voting registration failed: %d\n", ret);
        return ret;
    }

    return 0;
}

int ve_start_voting(const tvp_voting_id_t* vid) {
    int ret = -1;
    sgx_status_t sgx_ret = e_start_voting(g_enclave_id, &ret, vid);
    if (sgx_ret != SGX_SUCCESS || ret < 0) {
        ERROR("Voting start failed: %d\n", ret);
        return ret;
    }
    return 0;
}

int ve_stop_voting(const tvp_voting_id_t* vid, void** vrve_ptr, size_t* vrve_size) {
    int ret = -1;
    sgx_status_t sgx_ret = e_stop_voting(g_enclave_id, &ret, vid, NULL, 0, vrve_size);
    if (sgx_ret != SGX_SUCCESS || ret < 0) {
        ERROR("Failed to get voting results size: %d\n", ret);
        goto out;
    }
    DBG("VRVE size: %zu\n", *vrve_size);

    *vrve_ptr = malloc(*vrve_size);
    if (!*vrve_ptr) {
        ERROR("Out of memory!\n");
        goto out;
    }

    sgx_ret = e_stop_voting(g_enclave_id, &ret, vid, *vrve_ptr, *vrve_size, NULL);
    if (sgx_ret != SGX_SUCCESS || ret < 0) {
        ERROR("Failed to get voting results: %d\n", ret);
        goto out;
    }
    ret = 0;
out:
    return ret;
}

int ve_submit_vote(void* enc_vote, size_t enc_vote_size, void** vvr_ptr, size_t* vvr_size) {
    int ret = -1;

    *vvr_size = IV_SIZE + SIZE_WITH_PAD(sizeof(tvp_msg_vote_ve_v_t));
    *vvr_ptr = malloc(*vvr_size);
    if (!*vvr_ptr) {
        ERROR("Out of memory!\n");
        goto out;
    }

    sgx_status_t sgx_ret = e_register_vote(g_enclave_id, &ret, enc_vote, enc_vote_size, *vvr_ptr,
                                           *vvr_size);
    if (sgx_ret != SGX_SUCCESS || ret < 0) {
        ERROR("Adding the vote failed: %d\n", ret);
        goto out;
    }

    ret = 0;
out:
    if (ret != 0)
        *vvr_size = 0;
    return ret;
}

// OCALL: save sealed enclave state
int o_store_sealed_data(const void* sealed_data, size_t sealed_size) {
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
