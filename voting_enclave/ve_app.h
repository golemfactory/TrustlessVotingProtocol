#ifndef VE_CONFIG_H
#define VE_CONFIG_H

/** Default file name to save sealed keys to. */
#define DEFAULT_ENCLAVE_STATE_PATH "ve.state"

/** Default path to enclave binary. */
#define DEFAULT_ENCLAVE_PATH "voting_enclave.signed.so"

/** Default file name to save public key to. */
#define DEFAULT_ENCLAVE_PUBLIC_KEY_PATH "ve_pubkey"

/** Default file name to save enclave quote to. */
#define DEFAULT_ENCLAVE_QUOTE_PATH "ve.quote"

/** Enables enclave debugging and NULLIFIES ENCLAVE MEMORY PROTECTION. */
#define ENCLAVE_DEBUG_ENABLED 1

#endif /* VE_CONFIG_H */
