#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "tvp_msg.h"
#include "tvp_voter.h"
#include "util.h"
#include "voter_app.h"

struct option g_options[] = {
    { "help", no_argument, 0, 'h' },
    { "eh-pubkey-path", required_argument, 0, 'e' },
    { "vdeh-path", required_argument, 0, 'd' },
    { 0, 0, 0, 0 }
};

void usage(const char* exec) {
    printf("Usage: %s mode [options]\n", exec);
    printf("Available modes:\n");
    printf("  start                      Parse voting description message (VDEH).\n");
    printf("  run                        Listen for commands on stdin.\n");
    printf("Available general options:\n");
    printf("  --help, -h                 Display this help\n");
    printf("Available start options:\n");
    printf("  --eh-pubkey-path, -e PATH  Path to EH public key, default: "
           DEFAULT_ENCLAVE_HOST_PUBLIC_KEY_PATH "\n"); 
    printf("  --vdeh-path, -d PATH       Path to the VDEH message, default: "
           DEFAULT_MSG_VDEH_PATH "\n");
}

int main(int argc, char* argv[]) {
    int this_option = 0;
    char* eh_pubkey_path = DEFAULT_ENCLAVE_HOST_PUBLIC_KEY_PATH;
    char* vdeh_path = DEFAULT_MSG_VDEH_PATH;
    char* mode = NULL;
    int ret = -1;

    while (true) {
        this_option = getopt_long(argc, argv, "he:d:", g_options, NULL);

        if (this_option == -1)
            break;

        switch (this_option) {
            case 'h':
                usage(argv[0]);
                return 0;
            case 'e':
                eh_pubkey_path = optarg;
                break;
            case 'd':
                vdeh_path = optarg;
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
        case 's': { // parse VDEH
            if (!vdeh_path || !eh_pubkey_path) {
                usage(argv[0]);
                goto out;
            }

            size_t vdeh_size = 0;
            void* vdeh = read_file(vdeh_path, NULL, &vdeh_size);
            if (!vdeh)
                goto out;

            public_key_t eh_pubkey;
            size_t eh_pubkey_size = sizeof(eh_pubkey);
            if (!read_file(eh_pubkey_path, &eh_pubkey, &eh_pubkey_size))
                goto out;

            ret = v_parse_vdeh(vdeh, vdeh_size, eh_pubkey, eh_pubkey_size);
            break;
        }

        case 'r': { // run interactively
            // TODO
            ret = 0;
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
