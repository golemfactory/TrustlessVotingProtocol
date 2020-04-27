#ifndef VOTING_ENCLAVE_H
#define VOTING_ENCLAVE_H

#include <sgx_attributes.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>

#include <stdint.h>

/*! Enclave sealing policy:
 *  sealing keys can be derived using MRENCLAVE or MRSIGNER. */
#define ENCLAVE_SEALING_POLICY SGX_KEYPOLICY_MRENCLAVE

/*! Enclave flags that will matter for sealing/unsealing secrets (keys). */
#define ENCLAVE_SEALING_ATTRIBUTES (SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG | SGX_FLAGS_MODE64BIT) 

/*! Sizes of the EC keys (in bytes). */
#define EC_PUB_KEY_SIZE 65
#define EC_PRIV_KEY_SIZE 32

/*! Size of the EC signature (in bytes). */
#define EC_SIGNATURE_SIZE 64

/*! EC curve ID used for digital signatures.
 * TODO: change it to Curve25519 once MbedTLS implements EdDSA. */
#define EC_CURVE_ID MBEDTLS_ECP_DP_SECP256R1

#define IV_LEN 16
#define SALT_LEN IV_LEN
#define SIZE_WITH_PAD(x) ((x) / 16 * 16 + 16)

#endif
