#ifndef _TVP_MSG_H
#define _TVP_MSG_H

#include <stdint.h>
#include <sgx_report.h>

#pragma pack(push, 1)

/*
Message/struct definitions for Trustless Voting Protocol.

EH is Enclave Host, VE is Voting Enclave, V is Voter.

EH <-> VE communication messages don't need to be serialized, VE can access EH's memory.
V  <-> VE messages need to be serialized for network transport or other medium and go through EH
          who sends them to/from the VE.
V  <-> EH messages need to be serialized as well.

asymmetric keys: EC SECP256R1
hash: sha256
*/

typedef uint8_t nonce_t[32];
typedef uint8_t hash_t[32];
typedef uint8_t public_key_t[65];
typedef uint8_t private_key_t[32];
typedef uint8_t signature_t[64];

// protocol message type
// format: TVP_MSG_OPERATION_FROM_TO
typedef enum {
    TVP_MSG_INIT_ENCLAVE_EH_VE = 1,
    TVP_MSG_INIT_ENCLAVE_VE_EH,
    TVP_MSG_REGISTER_VOTING_EH_VE,
    TVP_MSG_REGISTER_VOTING_VE_EH,
    TVP_MSG_REGISTER_VOTING_EH_V,
    TVP_MSG_REQUEST_VD_V_EH,
    TVP_MSG_START_VOTING_EH_VE,
    TVP_MSG_VOTE_V_VE,
    TVP_MSG_VOTE_VE_V,
    TVP_MSG_STOP_VOTING_EH_VE,
    TVP_MSG_REQUEST_VR_V_EH,
} tvp_msg_t;

/*
init enclave:
EH->VE  {}
VE->EH  {report(VE), pubkey(VE)}
        report(VE) contains pubkey(VE) in the report_data field but we include it in a separate
        field here in case the key format changes and can't fit in report_data.
        EH gets quote(VE), verifies it with IAS (SPID must match), gets IASreport(VE)
*/
typedef struct { // VE -> EH
    public_key_t ve_public_key;
    sgx_report_t ve_report;
} tvp_msg_init_enclave_ve_eh_t;

/*
register voting:
EH->VE  VD:{desc, num_options, start_time, end_time, voters[public_key, weight]}
        VE saves voters, VID {hash(vid_nonce | VD)} vid_nonce is unique per voting
        VE->EH  VDVE:{vid_nonce, sig(VE, VID)} VDVE doesn't include VD, no need for that
        EH->V   VDEH:{VD, VDVE, sig(EH, hash(VD | VDVE)), quote(VE), pubkey(VE)}
                V verifies receiving before start_time
        V->EH   {VID} request for VDEH
*/
typedef struct {
    public_key_t public_key;
    uint32_t     weight;
} tvp_voter_t;

typedef struct { // EH -> VE [VD]
    char         start_time[32]; // ISO-8601
    char         end_time[32];   // ISO-8601
    uint32_t     num_options;
    uint32_t     num_voters;
    tvp_voter_t* voters;         // [!] pointer to untrusted memory, or embedded here in serialized form
    size_t       description_size;
    char*        description;    // [!] pointer to untrusted memory, or embedded here in serialized form
} tvp_msg_register_voting_eh_ve_t;

typedef struct {
    hash_t vid; // hash(vid_nonce | VD) [VID]
} tvp_voting_id_t;

typedef struct { // VE -> EH [VDVE]
    nonce_t     vid_nonce;
    signature_t vid_sig; // sig(VE, VID)
} tvp_msg_register_voting_ve_eh_t;

typedef struct { // EH -> V [VDEH]
    tvp_msg_register_voting_eh_ve_t vd;    // serialized
    tvp_msg_register_voting_ve_eh_t vdve;
    signature_t  eh_sig;                   // sig(EH, hash(VD | VDVE))
    public_key_t ve_public_key;            // embedded in quote(VE)
    size_t       ve_quote_ias_report_size; // size of ve_quote_ias_report
    char         ve_quote_ias_report[];    // serialized IAS report of quote(VE) verification,
                                           // contains embedded quote
} tvp_msg_register_voting_eh_v_t;

typedef struct { // V -> EH
    tvp_voting_id_t vid;
} tvp_msg_request_vd_v_eh_t;
// response: tvp_msg_register_voting_eh_v_t

/*
start voting:
EH->VE  {VID}
        response is just success/failure return of the ECALL
*/
typedef struct { // EH -> VE
    tvp_voting_id_t vid;
} tvp_start_voting_eh_ve_t;

/*
handshake: V<->VE  {ECDH}
           both parties know their respective public keys already
*/
/////////////////// TODO ///////////////////

/*
vote:
V->VE   VV:{vote:{voter_id, VID, option}, sig(V, hash(vote))}
        VE creates RV:{vote, nonce}, checks voter_list, saves RV
VE->V   VVR:{RV, sig(VE, hash(hash(RV) | VID))}
*/
typedef struct {
    public_key_t    voter;
    tvp_voting_id_t vid;
    uint32_t        option;
} tvp_vote_t;

typedef struct { // V -> VE [VV]
    tvp_vote_t  vote;
    signature_t sig;   // sig(V, hash(vote))
} tvp_msg_vote_v_ve_t;

typedef struct { // [RV]
    tvp_vote_t vote;
    nonce_t    nonce; // unique per vote
} tvp_registered_vote_t;

typedef struct { // VE -> V [VVR]
    tvp_registered_vote_t rv;
    signature_t           sig; // sig(VE, hash(hash(RV) | vote.vid))
} tvp_msg_vote_ve_v_t;

/*
stop voting:
EH->VE  {VID}
VE->EH  VRVE:{VID, results[option, count], votes[hash(RV)], sig(VE, hash(VRVE - sig))}
EH->V   VREH:{VRVE, sig(EH, hash(VREH))}
V->EH   {VID} request for VREH
*/
typedef struct { // EH -> VE
    tvp_voting_id_t vid;
} tvp_msg_stop_voting_eh_ve_t;

typedef struct { // VE -> EH [VRVE]
    tvp_voting_id_t vid;
    uint32_t        num_options; // not really needed but included for convenience
    uint32_t*       results;     // [!] pointer to untrusted memory, weighted option counts
    size_t          num_votes;
    hash_t*         votes;       // [!] pointer to untrusted memory, hash(tvp_registered_vote_t)
    signature_t     ve_sig;      // sig(VE, hash(previous fields))
} tvp_msg_stop_voting_ve_eh_t;

typedef struct { // EH -> V [VREH]
    tvp_msg_stop_voting_ve_eh_t vrve;   // serialized
    signature_t                 eh_sig; // sig(EH, hash(vrve))
} tvp_msg_stop_voting_eh_v_t;

typedef struct { // V -> EH
    tvp_voting_id_t vid;
} tvp_msg_request_vr_v_eh_t;
// response: tvp_msg_stop_voting_eh_v_t

#pragma pack(pop)

#endif // _TVP_MSG_H
