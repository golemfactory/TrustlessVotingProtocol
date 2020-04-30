#ifndef EH_APP_H
#define EH_APP_H

/*! Default file name to save sealed keys to. */
#define DEFAULT_ENCLAVE_STATE_PATH "ve.state"

/*! Default path to enclave binary. */
#define DEFAULT_ENCLAVE_PATH "voting_enclave.signed.so"

/*! Default file name to save enclave public key to. */
#define DEFAULT_ENCLAVE_PUBLIC_KEY_PATH "ve_pubkey"

/*! Default file name to save enclave host's public key to. */
#define DEFAULT_ENCLAVE_HOST_PUBLIC_KEY_PATH "eh_pubkey"

/*! Default file name to save enclave host's private key to. */
#define DEFAULT_ENCLAVE_HOST_PRIVATE_KEY_PATH "eh_privkey"

/*! Default file name to save enclave quote to. */
#define DEFAULT_ENCLAVE_QUOTE_PATH "ve.quote"

/*! Default file name to save IAS verification report to. */
#define DEFAULT_ENCLAVE_REPORT_PATH "ve.quote.report"

/*! Default file name to save IAS verification report's signature to. */
#define DEFAULT_ENCLAVE_REPORT_SIG_PATH "ve.quote.report.sig"

/*! Enables enclave debugging and NULLIFIES ENCLAVE MEMORY PROTECTION. */
#define ENCLAVE_DEBUG_ENABLED 1

#endif /* EH_APP_H */
