#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

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
}

static bool g_keep_listening = true;
static void sigint_handler(int _unused) {
    (void)_unused;
    g_keep_listening = false;
}

static void print_banner(void) {
    puts("Enter a command:");
    puts("(s)ubmit a voting");
    puts("(b)egin the voting");
    puts("(e)nd the voting");
    puts("submit a (v)ote");
}

static char* read_line(void) {
    size_t buf_size = 256;
    char* str = malloc(buf_size);
    if (!str)
        return NULL;
    int c;
    size_t len = 0;

    while ((c = getchar()) != EOF && c != '\n') {
        str[len++] = c;
        if (len == buf_size) {
            buf_size *= 2;
            char* old = str;
            str = realloc(str, buf_size);
            if (!str) {
                free(old);
                return NULL;
            }
        }
    }

    str[len] = '\0';
    return str;
}

// assumes vd has valid structure, caller needs to free returned buffer
void* serialize_vd(const tvp_msg_register_voting_eh_ve_t* vd, size_t* vd_serialized_size) {
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

    memcpy(vd_serialized, vd, constant_size);
    memcpy(vd_serialized + constant_size, vd->voters, voters_size);
    memcpy(vd_serialized + constant_size + voters_size, &vd->description_size,
           sizeof(vd->description_size));
    memcpy(vd_serialized + constant_size + voters_size + sizeof(vd->description_size),
           vd->description, vd->description_size);
    *vd_serialized_size = vd_size;
out:
    return vd_serialized;
}

static int submit_voting(void) {
    int ret = -1;
    size_t len;
    tvp_msg_register_voting_eh_ve_t* vd = calloc(1, sizeof(*vd));
    if (!vd) {
        fprintf(stderr, "Out of memory: %m\n");
        goto out;
    }

    puts("Enter start date:");
    if (!fgets(vd->start_time, sizeof(vd->start_time), stdin)) {
        fprintf(stderr, "Reading start date failed\n");
        goto out;
    }
    len = strlen(vd->start_time);
    if (len > 0 && vd->start_time[len - 1] == '\n') {
        vd->start_time[len - 1] = '\0';
    }

    puts("Enter end date:");
    if (!fgets(vd->end_time, sizeof(vd->end_time), stdin)) {
        fprintf(stderr, "Reading end date failed\n");
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
        printf("Enter public key (hex) of voter number %zu:\n", i);
        char* key_str = read_line();
        // parse_hex checks for proper string length
        if (parse_hex(key_str, &vd->voters[i].public_key, sizeof(vd->voters[i].public_key)) < 0) {
            fprintf(stderr, "Invalid public key of voter number %zu\n", i);
            free(key_str);
            goto out;
        }
        free(key_str);

        printf("Enter weight of voter number %zu:\n", i);
        if (fscanf(stdin, "%u%*1[ \r\n]", &vd->voters[i].weight) != 1) {
            fprintf(stderr, "Reading weight of voter number %zu failed\n", i);
            goto out;
        }
    }

    puts("Enter description:");
    vd->description = read_line(); // TODO: accept newlines
    vd->description_size = strlen(vd->description) + 1;

#ifdef DEBUG
    size_t vds_size;
    void* vds = serialize_vd(vd, &vds_size);
    if (!vds)
        goto out;

    ret = write_file("vd.tvp", vds, vds_size);
    free(vds);
    if (ret < 0)
        goto out;
#endif

    ret = ve_submit_voting(vd);
    if (ret < 0) {
        printf("Voting submit failed: %d\n", ret);
    } else {
        puts("Voting submit successful\n");
    }

out:
    free(vd->description);
    free(vd->voters);
    free(vd);
    return ret;
}

static int begin_voting(void) {
    return -1;
}

static int end_voting(void) {
    return -1;
}

static int submit_vote(void) {
    int ret = -1;
    char buf[0x400] = { 0 };
    size_t len = 0;

    puts("Enter encrypted vote:");
    if (!fgets(buf, sizeof buf, stdin)) {
        puts("Reading encrypted vote failed!");
        goto out;
    }
    len = strlen(buf);
    if (len && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
        --len;
    }
    if (len % 2 != 0) {
        puts("Invalid encrypted vote length!");
        goto out;
    }

    uint8_t* enc_vote = malloc(len / 2);
    if (!enc_vote) {
        puts("Out of memory!\n");
        goto out;
    }
    if (parse_hex(buf, enc_vote, len / 2) < 0) {
        goto out;
    }

    ret = ve_submit_vote(enc_vote, len / 2);

out:
    return ret;
}

static int eh_generate_keys(const char* eh_private_key_path, const char* eh_public_key_path) {
    void* buf = NULL;
    int ret = generate_key_pair(EC_CURVE_ID, &g_eh_key, g_eh_public_key, sizeof(g_eh_public_key),
                                &g_rng);
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

    INFO("Writing EH private key to %s...\n", eh_private_key_path);
    ret = write_file(eh_private_key_path, buf, private_key_size);
    if (ret != 0) {
        goto out;
    }

    INFO("Writing EH public key to %s...\n", eh_public_key_path);
    ret = write_file(eh_public_key_path, g_eh_public_key, sizeof(g_eh_public_key));
out:
    if (buf)
        memset(buf, 0, private_key_size);
    free(buf);
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
    char* mode = NULL;
    int ret = -1;

    while (true) {
        this_option = getopt_long(argc, argv, "hs:e:p:P:K:i:t:k:q:r:", g_options, NULL);

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
            ret = ve_generate_keys(enclave_path, enclave_state_path, enclave_public_key_path);
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

            ret = ve_load_enclave(enclave_path, enclave_state_path);
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

            ret = ve_verify_quote(api_key, nonce, quote_path, report_path);
            break;
        }

        case 'r': { // run
            ret = ve_load_enclave(enclave_path, enclave_state_path);
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
                        ret = submit_voting();
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
