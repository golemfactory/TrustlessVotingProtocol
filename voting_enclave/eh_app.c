#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

#include "crypto_utils.h"
#include "eh_app.h"
#include "util.h"
#include "ve_user.h"

static mbedtls_ecp_keypair g_eh_key = {0};
static uint8_t g_eh_public_key[EC_PUB_KEY_SIZE] = {0};
static mbedtls_ctr_drbg_context g_rng = {0};

static struct option g_options[] = {
    { "help", no_argument, 0, 'h' },
    { "sealed-path", required_argument, 0, 's' },
    { "enclave-path", required_argument, 0, 'e' },
    { "pubkey-path", required_argument, 0, 'p' },
    { "eh-pubkey-path", required_argument, 0, 'P' },
    { "eh-prvkey-path", required_argument, 0, 'K' },
    { "spid", required_argument, 0, 'i' },
    { "quote-type", required_argument, 0, 't' },
    { "api-key", required_argument, 0, 'k' },
    { "quote-path", required_argument, 0, 'q' },
    { "report-path", required_argument, 0, 'r' },
    { "sig-path", required_argument, 0, 'g' },
    { 0, 0, 0, 0 }
};

static void usage(const char* exec) {
    printf("Usage: %s mode [options]\n", exec);
    printf("Available modes:\n");
    printf("  init                       Generate enclave's key pair and export the public key\n");
    printf("  gen-key                    Generate enclave host's key pair and export the public key\n");
    printf("  quote                      Generate enclave quote and export it,\n");
    printf("                             verify the quote with IAS and save the report\n");
    printf("  run                        Run enclave from sealed state. Listens for commands on stdin.\n");
    printf("Available general options:\n");
    printf("  --help, -h                 Display this help\n");
    printf("  --sealed-path, -s PATH     Path for sealed enclave storage, default: "
           DEFAULT_ENCLAVE_STATE_PATH "\n");
    printf("  --enclave-path, -e PATH    Path for enclave binary, default: "
           DEFAULT_ENCLAVE_PATH "\n");
    printf("Available init options:\n");
    printf("  --pubkey-path, -p PATH     Path to save enclave public key to, default: "
           DEFAULT_ENCLAVE_PUBLIC_KEY_PATH "\n");
    printf("Available gen-key options:\n");
    printf("  --eh-pubkey-path, -P PATH  Path to save enclave host's public key to, default: "
           DEFAULT_ENCLAVE_HOST_PUBLIC_KEY_PATH "\n");
    printf("  --eh-prvkey-path, -K PATH  Path to save enclave host's private key to, default: "
           DEFAULT_ENCLAVE_HOST_PRIVATE_KEY_PATH "\n");
    printf("Available quote options:\n");
    printf("  --spid, -i SPID            Service Provider ID received during IAS registration"
           " (hex string)\n");
    printf("  --api-key, -k KEY          IAS API key (hex string)\n");
    printf("  --quote-type, -t TYPE      Service Provider quote type, (l)inkable or (u)nlinkable)\n");
    printf("  --quote-path, -q PATH      Path to save enclave quote to, default: "
           DEFAULT_ENCLAVE_QUOTE_PATH "\n");
    printf("  --report-path, -r PATH     Path to save IAS quote verification report to, default: "
           DEFAULT_ENCLAVE_REPORT_PATH "\n");
    printf("  --sig-path, -g PATH        Path to save IAS quote verification report's signature to, default: "
           DEFAULT_ENCLAVE_REPORT_SIG_PATH "\n");
    printf("Available run options:\n");
    printf("  --eh-pubkey-path, -P PATH  Path to load enclave host's public key from, default: "
           DEFAULT_ENCLAVE_HOST_PUBLIC_KEY_PATH "\n");
    printf("  --eh-prvkey-path, -K PATH  Path to load enclave host's private key from, default: "
           DEFAULT_ENCLAVE_HOST_PRIVATE_KEY_PATH "\n");
}

// assumes vd has valid structure, caller needs to free returned buffer
static void* serialize_vd(const tvp_msg_register_voting_eh_ve_t* vd, size_t* vd_serialized_size) {
    const size_t constant_size = offsetof(tvp_msg_register_voting_eh_ve_t, voters);
    size_t voters_size = vd->num_voters * sizeof(*vd->voters);
    size_t vd_size = constant_size
                     + voters_size
                     + sizeof(vd->description_size)
                     + vd->description_size;
    void* vd_serialized = calloc(1, vd_size);
    if (!vd_serialized) {
        ERROR("Out of memory\n");
        goto out;
    }

    uint8_t* p = vd_serialized;
    memcpy(p, vd, constant_size);
    p += constant_size;
    memcpy(p, vd->voters, voters_size);
    p += voters_size;
    memcpy(p, &vd->description_size, sizeof(vd->description_size));
    p += sizeof(vd->description_size);
    memcpy(p, vd->description, vd->description_size);
    *vd_serialized_size = vd_size;
out:
    return vd_serialized;
}

// vd must be serialized
static void* serialize_vdeh(const void* vd, size_t vd_size,
                            const tvp_msg_register_voting_ve_eh_t* vdve, const void* ias_report,
                            size_t ias_report_size, const public_key_t* ve_pubkey,
                            size_t* vdeh_serialized_size) {
    int ret = -1;
    size_t vdeh_size = vd_size
                       + sizeof(*vdve)
                       + sizeof(signature_t) // eh_sig
                       + sizeof(public_key_t) // ve_public_key
                       + sizeof(size_t) // ve_quote_ias_report_size
                       + ias_report_size;
    void* vdeh = malloc(vdeh_size);
    if (!vdeh)
        goto out;

    uint8_t* p = vdeh;
    memcpy(p, vd, vd_size);
    p += vd_size;
    memcpy(p, vdve, sizeof(*vdve));
    p += sizeof(*vdve);

    // sign hash(VD|VDVE)
    signature_t* vdeh_sig = (signature_t*)p;
    hash_t hash = { 0 };
    mbedtls_sha256_context sha = { 0 };

    mbedtls_sha256_init(&sha);
    ret = mbedtls_sha256_starts_ret(&sha, /*is224=*/0);
    if (ret)
        goto out;

    ret = mbedtls_sha256_update_ret(&sha, vd, vd_size);
    if (ret)
        goto out;

    ret = mbedtls_sha256_update_ret(&sha, (const unsigned char*)vdve, sizeof(*vdve));
    if (ret)
        goto out;

    ret = mbedtls_sha256_finish_ret(&sha, (unsigned char*)&hash);
    if (ret)
        goto out;

    ret = sign_hash(vdeh_sig, &hash, &g_eh_key, &g_rng);
    if (ret) {
        ERROR("Signing hash(VD|VDVE) failed\n");
        goto out;
    }
    // sanity check
    ret = verify_hash(vdeh_sig, &hash, &g_eh_key);
    if (ret) {
        ERROR("Verifying sig(EH, hash(VD|VDVE)) failed\n");
        goto out;
    }
    p += sizeof(*vdeh_sig);

    memcpy(p, ve_pubkey, sizeof(*ve_pubkey));
    p += sizeof(*ve_pubkey);

    memcpy(p, &ias_report_size, sizeof(ias_report_size));
    p += sizeof(ias_report_size);

    memcpy(p, ias_report, ias_report_size);
    *vdeh_serialized_size = vdeh_size;
    ret = 0;
out:
    if (ret) {
        free(vdeh);
        vdeh = NULL;
    }
    return vdeh;
}

static int register_voting(const public_key_t* ve_pubkey) {
    int ret = -1;
    size_t len;
    void* vd_serialized = NULL;
    void* ias_report = NULL;
    void* vdeh = NULL;

    tvp_msg_register_voting_eh_ve_t* vd = calloc(1, sizeof(*vd));
    if (!vd) {
        fprintf(stderr, "Out of memory: %m\n");
        goto out;
    }

    puts("Enter start time:");
    if (!fgets(vd->start_time, sizeof(vd->start_time), stdin)) {
        fprintf(stderr, "Reading start time failed\n");
        goto out;
    }
    len = strlen(vd->start_time);
    if (len > 0 && vd->start_time[len - 1] == '\n') {
        vd->start_time[len - 1] = '\0';
    }

    puts("Enter end time:");
    if (!fgets(vd->end_time, sizeof(vd->end_time), stdin)) {
        fprintf(stderr, "Reading end time failed\n");
        goto out;
    }
    len = strlen(vd->end_time);
    if (len > 0 && vd->end_time[len - 1] == '\n') {
        vd->end_time[len - 1] = '\0';
    }

    puts("Enter number of options:");
    if (fscanf(stdin, "%u%*1[ \r\n]", &vd->num_options) != 1) {
        fprintf(stderr, "Reading number of options failed\n");
        goto out;
    }

    puts("Enter number of voters:");
    if (fscanf(stdin, "%u%*1[ \r\n]", &vd->num_voters) != 1) {
        fprintf(stderr, "Reading number of voters failed\n");
        goto out;
    }

    vd->voters = malloc(sizeof(*vd->voters) * vd->num_voters);
    if (!vd->voters) {
        fprintf(stderr, "Out of memory: %m\n");
        goto out;
    }

    for (size_t i = 0; i < vd->num_voters; ++i) {
        printf("Enter public key (hex) of voter number %zu:\n", i + 1);
        char* key_str = read_line();
        // parse_hex checks for proper string length
        if (parse_hex(key_str, &vd->voters[i].public_key, sizeof(vd->voters[i].public_key)) < 0) {
            fprintf(stderr, "Invalid public key of voter number %zu\n", i + 1);
            free(key_str);
            goto out;
        }
        free(key_str);

        printf("Enter weight of voter number %zu:\n", i + 1);
        if (fscanf(stdin, "%u%*1[ \r\n]", &vd->voters[i].weight) != 1) {
            fprintf(stderr, "Reading weight of voter number %zu failed\n", i + 1);
            goto out;
        }
    }

    puts("Enter description:");
    vd->description = read_line(); // TODO: accept newlines
    vd->description_size = strlen(vd->description);

    // send to enclave
    tvp_msg_register_voting_ve_eh_t vdve = { 0 };
    ret = ve_register_voting(vd, &vdve);
    if (ret < 0) {
        printf("Voting registration failed: %d\n", ret);
        goto out;
    }

    INFO("Voting registration successful\n");
    INFO("VDVE nonce: ");
    HEXDUMP(vdve.vid_nonce);
    INFO("VDVE signature: ");
    HEXDUMP(vdve.vid_sig);

    // prepare VDEH
    size_t vd_size = 0;
    vd_serialized = serialize_vd(vd, &vd_size);
    if (!vd_serialized)
        goto out;

    ret = write_file("vd.tvp", vd_serialized, vd_size);
    if (ret < 0)
        goto out;

    ret = write_file("vdve.tvp", &vdve, sizeof(vdve));
    if (ret < 0)
        goto out;

    ret = -1;
    puts("Enter path to enclave IAS report (empty for default):");
    char* ias_report_path = read_line();
    if (!*ias_report_path)
        ias_report_path = DEFAULT_ENCLAVE_REPORT_PATH;
    size_t ias_report_size = 0;
    ias_report = read_file(ias_report_path, NULL, &ias_report_size);
    if (!ias_report)
        goto out;

    size_t vdeh_size = 0;
    vdeh = serialize_vdeh(vd_serialized, vd_size, &vdve, ias_report, ias_report_size, ve_pubkey,
                          &vdeh_size);
    if (!vdeh)
        goto out;

    ret = write_file("vdeh.tvp", vdeh, vdeh_size);
    if (ret == 0)
        printf("VDEH saved to 'vdeh.tvp'\n");

out:
    free(vdeh);
    free(ias_report);
    free(vd_serialized);
    if (vd) {
        free(vd->description);
        free(vd->voters);
    }
    free(vd);
    return ret;
}

static int begin_voting(void) {
    int ret = -1;
    tvp_voting_id_t vid = { 0 };
    puts("Enter VID:");
    char* vid_str = read_line();
    if (parse_hex(vid_str, &vid, sizeof(vid)) < 0) {
        ERROR("Invalid VID\n");
        goto out;
    }
    ret = ve_start_voting(&vid);
out:
    free(vid_str);
    return ret;
}

static int end_voting(void) {
    int ret = -1;
    tvp_voting_id_t vid = { 0 };
    void* vrve = NULL;

    puts("Enter VID:");
    char* vid_str = read_line();
    if (parse_hex(vid_str, &vid, sizeof(vid)) < 0) {
        ERROR("Invalid VID\n");
        goto out;
    }

    size_t vrve_size = 0;
    ret = ve_stop_voting(&vid, &vrve, &vrve_size);
    if (ret < 0)
        goto out;

    ret = write_file("vrve.tvp", vrve, vrve_size);
    if (ret < 0)
        goto out;

    // VREH is VRVE|eh_signature
    size_t vreh_size = vrve_size + sizeof(signature_t);
    vrve = realloc(vrve, vreh_size);
    if (!vrve) {
        ret = -1;
        ERROR("Out of memory\n");
        goto out;
    }

    hash_t hash = { 0 };

    ret = mbedtls_sha256_ret(vrve, vrve_size, (uint8_t*)&hash, /*is224=*/0);
    if (ret < 0)
        goto out;

    ret = sign_hash(vrve + vrve_size, &hash, &g_eh_key, &g_rng);
    if (ret < 0)
        goto out;

    ret = write_file("vreh.tvp", vrve, vreh_size);
    if (ret < 0)
        goto out;

    puts("VREH:");
    hexdump_mem(vrve, vreh_size);
out:
    free(vid_str);
    free(vrve);
    return ret;
}

static int submit_vote(void) {
    int ret = -1;
    char* buf = NULL;
    void* enc_vote = NULL;

    puts("Enter encrypted vote:");
    buf = read_line();
    size_t len = strlen(buf);
    if (len % 2 != 0) {
        ERROR("Invalid encrypted vote length!\n");
        goto out;
    }

    enc_vote = malloc(len / 2);
    if (!enc_vote) {
        ERROR("Out of memory!\n");
        goto out;
    }
    if (parse_hex(buf, enc_vote, len / 2) < 0) {
        goto out;
    }

    void* vvr = NULL;
    size_t vvr_size;
    ret = ve_submit_vote(enc_vote, len / 2, &vvr, &vvr_size);
    if (ret == 0) {
        INFO("Encrypted VVR: ");
        hexdump_mem(vvr, vvr_size);
        free(vvr);
    }

out:
    free(buf);
    free(enc_vote);
    return ret;
}

static int eh_generate_keys(const char* eh_private_key_path, const char* eh_public_key_path) {
    void* buf = NULL;
    INFO("Generating EH key pair...\n");
    int ret = generate_key_pair(EC_CURVE_ID, &g_eh_key, &g_eh_public_key, &g_rng);
    if (ret != 0) {
        ERROR("Failed to seed crypto PRNG: %d\n", ret);
        goto out;
    }

    size_t private_key_size = mbedtls_mpi_size(&g_eh_key.d);
    buf = malloc(private_key_size);
    if (!buf) {
        ERROR("Out of memory\n");
        goto out;
    }

    INFO("EH public key: ");
    HEXDUMP(g_eh_public_key);

    ret = mbedtls_mpi_write_binary(&g_eh_key.d, buf, private_key_size);
    if (ret != 0) {
        ERROR("Failed to get private key data: %d\n", ret);
        goto out;
    }

    INFO("Writing EH private key to '%s'\n", eh_private_key_path);
    ret = write_file(eh_private_key_path, buf, private_key_size);
    if (ret != 0) {
        goto out;
    }

    INFO("Writing EH public key to '%s'\n", eh_public_key_path);
    ret = write_file(eh_public_key_path, g_eh_public_key, sizeof(g_eh_public_key));
out:
    if (buf)
        memset(buf, 0, private_key_size); // TODO: secure wipe
    free(buf);
    return ret;
}

static int eh_load_keys(const char* eh_private_key_path, const char* eh_public_key_path) {
    private_key_t key = { 0 };
    int ret = -1;

    INFO("Reading EH private key from '%s'\n", eh_private_key_path);
    size_t key_size = sizeof(key);
    if (!read_file(eh_private_key_path, &key, &key_size)) {
        goto out;
    }

    ret = mbedtls_ecp_read_key(EC_CURVE_ID, &g_eh_key, (uint8_t*)&key, key_size);
    if (ret != 0) {
        ERROR("Failed to recreate private key: %d\n", ret);
        goto out;
    }

    ret = mbedtls_ecp_check_privkey(&g_eh_key.grp, &g_eh_key.d);
    if (ret != 0) {
        ERROR("Loaded private key is invalid: %d\n", ret);
        goto out;
    }

    INFO("Reading EH public key from '%s'\n", eh_public_key_path);
    key_size = sizeof(g_eh_public_key);
    if (!read_file(eh_public_key_path, &g_eh_public_key, &key_size)) {
        goto out;
    }

    ret = mbedtls_ecp_point_read_binary(&g_eh_key.grp, &g_eh_key.Q, (const uint8_t*)&g_eh_public_key,
                                        key_size);
    if (ret != 0) {
        ERROR("Failed to recreate public key: %d\n", ret);
        goto out;
    }

    ret = mbedtls_ecp_check_pubkey(&g_eh_key.grp, &g_eh_key.Q);
    if (ret != 0) {
        ERROR("Loaded public key is invalid: %d\n", ret);
        goto out;
    }

    INFO("EH public key: ");
    HEXDUMP(g_eh_public_key);
out:
    memset(&key, 0, sizeof(key)); // TODO: secure wipe
    return ret;
}

static int rng_init(void) {
    unsigned char entropy_sig[] = "enclave host app";
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&g_rng);

    int ret = mbedtls_ctr_drbg_seed(&g_rng, mbedtls_entropy_func, &entropy, entropy_sig,
                                    sizeof(entropy_sig));
    if (ret != 0) {
        ERROR("Failed to seed crypto PRNG: %d\n", ret);
    }
    return ret;
}

static bool g_keep_listening = true;
static void sigint_handler(int _unused) {
    (void)_unused;
    g_keep_listening = false;
}

static void print_banner(void) {
    puts("\nEnter a command:");
    puts("(s)ubmit a voting");
    puts("(b)egin the voting");
    puts("(e)nd the voting");
    puts("submit a (v)ote");
}

int main(int argc, char* argv[]) {
    int this_option = 0;
    char* sp_id = NULL;
    char* sp_quote_type = NULL;
    char* api_key = NULL;
    char* enclave_state_path = DEFAULT_ENCLAVE_STATE_PATH;
    char* enclave_public_key_path = DEFAULT_ENCLAVE_PUBLIC_KEY_PATH;
    char* eh_public_key_path = DEFAULT_ENCLAVE_HOST_PUBLIC_KEY_PATH;
    char* eh_private_key_path = DEFAULT_ENCLAVE_HOST_PRIVATE_KEY_PATH;
    char* enclave_path = DEFAULT_ENCLAVE_PATH;
    char* quote_path = DEFAULT_ENCLAVE_QUOTE_PATH;
    char* report_path = DEFAULT_ENCLAVE_REPORT_PATH;
    char* sig_path = DEFAULT_ENCLAVE_REPORT_SIG_PATH;
    char* mode = NULL;
    int ret = -1;

    while (true) {
        this_option = getopt_long(argc, argv, "hs:e:p:P:K:i:t:k:q:r:g:", g_options, NULL);

        if (this_option == -1)
            break;

        switch (this_option) {
            case 'h':
                usage(argv[0]);
                return 0;
            case 's':
                enclave_state_path = optarg;
                break;
            case 'e':
                enclave_path = optarg;
                break;
            case 'p':
                enclave_public_key_path = optarg;
                break;
            case 'P':
                eh_public_key_path = optarg;
                break;
            case 'K':
                eh_private_key_path = optarg;
                break;
            case 'i':
                sp_id = optarg;
                break;
            case 't':
                sp_quote_type = optarg;
                break;
            case 'k':
                api_key = optarg;
                break;
            case 'q':
                quote_path = optarg;
                break;
            case 'r':
                report_path = optarg;
                break;
            case 'g':
                sig_path = optarg;
                break;
            default:
                printf("Unknown option: %c\n", this_option);
                usage(argv[0]);
                goto out;
        }
    }

    if (optind >= argc) {
        printf("Mode not specified\n");
        usage(argv[0]);
        goto out;
    }

    mode = argv[optind++];

    if (rng_init() < 0)
        goto out;

    switch (mode[0]) {
        case 'i': { // init
            public_key_t ve_pubkey = { 0 };
            ret = ve_generate_keys(enclave_path, enclave_state_path, &ve_pubkey);
            if (ret < 0)
                goto out;

            INFO("Saving public enclave key to '%s'\n", enclave_public_key_path);
            ret = write_file(enclave_public_key_path, &ve_pubkey, sizeof(ve_pubkey));
            break;
        }

        case 'g': { // gen-key
            ret = eh_generate_keys(eh_private_key_path, eh_public_key_path);
            break;
        }

        case 'q': { // quote
            if (!sp_id) {
                printf("SPID not set\n");
                usage(argv[0]);
                goto out;
            }

            if (!sp_quote_type) {
                printf("Quote type not set\n");
                usage(argv[0]);
                goto out;
            }

            if (!api_key) {
                printf("IAS API key not set\n");
                usage(argv[0]);
                goto out;
            }

            ret = ve_load_enclave(enclave_path, enclave_state_path, NULL);
            if (ret < 0)
                goto out;

            ret = ve_get_quote(sp_id, sp_quote_type, quote_path);
            if (ret < 0)
                goto out;

            uint8_t nonce_data[24];
            char nonce[33];
            size_t nonce_size = sizeof(nonce_data);
            if (!read_file("/dev/urandom", nonce_data, &nonce_size))
                goto out;

            ret = mbedtls_base64_encode((unsigned char*)nonce, sizeof(nonce), &nonce_size,
                                        nonce_data, sizeof(nonce_data));
            if (ret < 0) {
                printf("Failed to encode IAS nonce: %d\n", ret);
                goto out;
            }
            assert(nonce[32] == 0);
            printf("IAS nonce: %s\n", nonce);

            ret = ve_verify_quote(api_key, nonce, quote_path, report_path, sig_path);
            break;
        }

        case 'r': { // run
            public_key_t ve_pubkey = { 0 };
            ret = ve_load_enclave(enclave_path, enclave_state_path, &ve_pubkey);
            if (ret < 0)
                goto out;

            ret = eh_load_keys(eh_private_key_path, eh_public_key_path);
            if (ret < 0)
                goto out;

            struct sigaction sa = { 0 };
            sa.sa_flags = SA_RESETHAND;
            sa.sa_handler = sigint_handler;
            ret = sigaction(SIGINT, &sa, NULL);
            if (ret < 0) {
                break;
            }

            while (g_keep_listening) {
                char buf[0x10];

                print_banner();

                if (!fgets(buf, sizeof buf, stdin)) {
                    g_keep_listening = false;
                    break;
                }

                ret = 0;
                switch (buf[0]) {
                    case 's':
                        ret = register_voting(&ve_pubkey);
                        break;
                    case 'b':
                        ret = begin_voting();
                        break;
                    case 'e':
                        ret = end_voting();
                        g_keep_listening = false;
                        break;
                    case 'v':
                        ret = submit_vote();
                        break;
                    default:
                        puts("Invalid option!\n");
                        break;
                }

                if (ret < 0) {
                    g_keep_listening = false;
                }
            }

            break;
        }

        default: {
            usage(argv[0]);
            ret = 0;
            break;
        }
    }

    ve_unload_enclave();
out:
    return ret;
}
