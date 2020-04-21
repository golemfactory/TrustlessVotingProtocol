#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>

#include "ve_app.h"
#include "ve_user.h"

struct option g_options[] = {
    { "help", no_argument, 0, 'h' },
    { "sealed-path", required_argument, 0, 's' },
    { "enclave-path", required_argument, 0, 'e' },
    { "pubkey-path", required_argument, 0, 'p' },
    { "spid", required_argument, 0, 'i' },
    { "quote-type", required_argument, 0, 't' },
    { "quote-path", required_argument, 0, 'q' },
    { 0, 0, 0, 0 }
};

void usage(const char* exec) {
    printf("Usage: %s mode [options]\n", exec);
    printf("Available modes:\n");
    printf("  init                     Generate enclave's key pair and export the public key,\n");
    printf("                           generate enclave quote and export it\n");
    printf("  test                     Test loading enclave with sealed state\n");
    printf("Available general options:\n");
    printf("  --help, -h               Display this help\n");
    printf("  --sealed-path, -s PATH   Path for sealed enclave storage, default: "
           DEFAULT_ENCLAVE_STATE_PATH "\n");
    printf("  --enclave-path, -e PATH  Path for enclave binary, default: "
           DEFAULT_ENCLAVE_PATH "\n");
    printf("Available init options:\n");
    printf("  --pubkey-path, -p PATH   Path to save enclave public key to, default: "
           DEFAULT_ENCLAVE_PUBLIC_KEY_PATH "\n");
    printf("  --spid, -i SPID          Service Provider ID received during IAS registration"
           " (hex string)\n");
    printf("  --quote-type, -t TYPE    Service Provider quote type, (l)inkable or (u)nlinkable)\n");
    printf("  --quote-path, -q PATH    Path to save enclave quote to, default: "
           DEFAULT_ENCLAVE_QUOTE_PATH "\n");
}

int main(int argc, char* argv[]) {
    int this_option = 0;
    char* sp_id = NULL;
    char* sp_quote_type = NULL;
    char* enclave_state_path = DEFAULT_ENCLAVE_STATE_PATH;
    char* enclave_public_key_path = DEFAULT_ENCLAVE_PUBLIC_KEY_PATH;
    char* enclave_path = DEFAULT_ENCLAVE_PATH;
    char* quote_path = DEFAULT_ENCLAVE_QUOTE_PATH;
    char* mode = NULL;
    int ret = -1;

    while (true) {
        this_option = getopt_long(argc, argv, "hs:e:p:i:t:q:", g_options, NULL);

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
            case 'i':
                sp_id = optarg;
                break;
            case 't':
                sp_quote_type = optarg;
                break;
            case 'q':
                quote_path = optarg;
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

    switch (mode[0]) {
        case 'i': { // init
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

            ret = ve_init_enclave(enclave_path, sp_id, sp_quote_type, enclave_state_path,
                                  enclave_public_key_path, quote_path);
            if (ret < 0)
                goto out;

            ret = ve_unload_enclave();
            break;
        }

        case 't': { // test
            ret = ve_load_enclave(enclave_path, enclave_state_path);
            if (ret < 0)
                goto out;

            ret = ve_unload_enclave();
            break;
        }

        default: {
            usage(argv[0]);
            ret = 0;
            break;
        }
    }

out:
    return ret;
}
