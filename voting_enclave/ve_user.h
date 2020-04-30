#ifndef VE_USER_H
#define VE_USER_H

#include "tvp_msg.h"

/*! Enables enclave debugging and NULLIFIES ENCLAVE MEMORY PROTECTION. */
#define ENCLAVE_DEBUG_ENABLED 1

/*! Default base URL for IAS API endpoints. Remove "/dev" for production environment. */
#define IAS_URL_BASE "https://api.trustedservices.intel.com/sgx/dev"

/*! Default URL for IAS "verify attestation evidence" API endpoint. */
#define IAS_URL_REPORT IAS_URL_BASE "/attestation/v4/report"

/*! Default URL for IAS "Retrieve SigRL" API endpoint. EPID group id is added at the end. */
#define IAS_URL_SIGRL IAS_URL_BASE "/attestation/v4/sigrl"

/*!
 *  \brief Get size of an open file.
 *
 *  \param[in] fd Open file descriptor.
 *
 *  \return File size or -1 on error.
 */
ssize_t get_file_size(int fd);

/*!
 *  \brief Read file contents to buffer.
 *
 *  \param[in]     path   Path to the file.
 *  \param[in]     buffer Buffer to read data to. If NULL, this function allocates one.
 *  \param[in,out] size   On entry, number of bytes to read. 0 means to read the entire file.
 *                        On exit, number of bytes read.
 *
 *  \return On success, pointer to the data buffer. If \p buffer was NULL, caller should free this.
 *          On failure, NULL.
 */
void* read_file(const char* path, void* buffer, size_t* size);

/*!
 *  \brief Write buffer to file.
 *
 *  \param[in] path   File path.
 *  \param[in] buffer Buffer to write data from.
 *  \param[in] size   \p buffer size.
 *
 *  \return 0 on success, errno on error.
 */
int write_file(const char* path, const void* buffer, size_t size);

/*!
 *  \brief Loads the enclave, generates new enclave key pair, seals enclave state, exports enclave
 *         public key.
 *
 *  \param[in]  enclave_path      Path to enclave binary.
 *  \param[in]  sealed_state_path Path to sealed enclave state (will be overwritten).
 *  \param[out] enclave_pubkey    Enclave public key.
 *
 *  \return 0 on success, negative on error.
 */
int ve_generate_keys(const char* enclave_path, const char* sealed_state_path,
                     public_key_t* enclave_pubkey);

/*!
 *  \brief Get SGX quote of the enclave.
 *
 *  \param[in] sp_id_str         Service Provider ID (hex string).
 *  \param[in] sp_quote_type_str Quote type as string ("linkable"/"unlinkable").
 *  \param[in] quote_path        Path where enclave SGX quote will be saved.
 *
 *  \return 0 on success, negative on error.
 *
 *  \details The enclave must be loaded.
 */
int ve_get_quote(const char* sp_id_str, const char* sp_quote_type_str, const char* quote_path);

/*!
 *  \brief Submit enclave quote to IAS and save the response.
 *
 *  \param[in] ias_api_key IAS API key (hex string).
 *  \param[in] nonce       (Optional) Nonce to be included in the IAS report (max 32 characters).
 *  \param[in] quote_path  Path to the enclave quote.
 *  \param[in] report_path Path where IAS report will be saved.
 *  \param[in] sig_path    Path where IAS report's signature will be saved.
 *
 *  \return 0 on success, negative on error.
 */
int ve_verify_quote(const char* ias_api_key, const char* nonce, const char* quote_path,
                    const char* report_path, const char* sig_path);

/*!
 *  \brief Load voting enclave and restore its state from a sealed blob.
 *
 *  \param[in]  enclave_path      Path to enclave binary.
 *  \param[in]  sealed_state_path Path to sealed enclave state.
 *  \param[out] enclave_pubkey    (Optional) Enclave public key.
 *
 *  \return 0 on success, negative on error.
 */
int ve_load_enclave(const char* enclave_path, const char* sealed_state_path,
                    public_key_t* enclave_pubkey);

/*!
 *  \brief Unload voting enclave.
 *
 *  \return 0 on success, negative on error.
 */
int ve_unload_enclave(void);

int ve_register_voting(const tvp_msg_register_voting_eh_ve_t* vd,
                       tvp_msg_register_voting_ve_eh_t* vdve);

int ve_start_voting(const tvp_voting_id_t* vid);

int ve_submit_vote(void* enc_vote, size_t enc_vote_size, void** vvr_ptr, size_t* vvr_size);

int ve_stop_voting(const tvp_voting_id_t* vid, void** vrve_ptr, size_t* vrve_size);

#endif /* VE_USER_H */
