#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define SECURITY 32

#define R 64

#define T 32

#define T_8 (T / 8)

#define KAPPA 256

#define SECP256K1_ENCODED_SIZE 33

#define SALT_LEN (2 * SECURITY)

typedef struct CScalar {
  uint8_t bytes[32];
} CScalar;

typedef struct CScalarVec {
  const struct CScalar *data;
  uintptr_t len;
} CScalarVec;

typedef struct CParameters {
  uint8_t threshold;
  uint8_t share_count;
} CParameters;

typedef struct CSessionData {
  struct CParameters parameters;
  uint8_t party_index;
  uintptr_t session_id_len;
  const uint8_t *session_id;
} CSessionData;

typedef struct CAffinePoint {
  uint8_t bytes[SECP256K1_ENCODED_SIZE];
} CAffinePoint;

typedef struct CInteractiveDLogProof {
  uint8_t challenge[T_8];
  struct CScalar challenge_response;
} CInteractiveDLogProof;

typedef struct CDLogProof {
  struct CAffinePoint point;
  struct CAffinePoint rand_commitments[R];
  struct CInteractiveDLogProof proofs[R];
} CDLogProof;

typedef uint8_t CHashOutput[SECURITY];

typedef struct CProofCommitment {
  uint8_t index;
  struct CDLogProof proof;
  CHashOutput commitment;
} CProofCommitment;

typedef uint8_t CSeed[SECURITY];

typedef struct CKeepInitZeroSharePhase2to3 {
  CSeed seed;
  uint8_t salt[SALT_LEN];
} CKeepInitZeroSharePhase2to3;

typedef struct CBTreeMapData_CKeepInitZeroSharePhase2to3 {
  uint8_t key;
  struct CKeepInitZeroSharePhase2to3 val;
} CBTreeMapData_CKeepInitZeroSharePhase2to3;

typedef struct CBTreeMap_CKeepInitZeroSharePhase2to3 {
  const struct CBTreeMapData_CKeepInitZeroSharePhase2to3 *data;
  uintptr_t len;
} CBTreeMap_CKeepInitZeroSharePhase2to3;

typedef struct CPartiesMessage {
  uint8_t sender;
  uint8_t receiver;
} CPartiesMessage;

typedef struct CTransmitInitZeroSharePhase2to4 {
  struct CPartiesMessage parties;
  CHashOutput commitment;
} CTransmitInitZeroSharePhase2to4;

typedef struct CTransmitInitZeroSharePhase2to4Vec {
  const struct CTransmitInitZeroSharePhase2to4 *data;
  uintptr_t len;
} CTransmitInitZeroSharePhase2to4Vec;

typedef uint8_t CChainCode[32];

typedef struct CUniqueKeepDerivationPhase2to3 {
  CChainCode aux_chain_code;
  uint8_t cc_salt[SALT_LEN];
} CUniqueKeepDerivationPhase2to3;

typedef struct CBroadcastDerivationPhase2to4 {
  uint8_t sender_index;
  CHashOutput cc_commitment;
} CBroadcastDerivationPhase2to4;

typedef struct CPhase2Out {
  struct CScalar poly_point;
  struct CProofCommitment proof_commitment;
  struct CBTreeMap_CKeepInitZeroSharePhase2to3 zero_keep;
  struct CTransmitInitZeroSharePhase2to4Vec zero_transmit;
  struct CUniqueKeepDerivationPhase2to3 bip_keep;
  struct CBroadcastDerivationPhase2to4 bip_broadcast;
} CPhase2Out;

typedef struct CKeepInitZeroSharePhase3to4 {
  CSeed seed;
} CKeepInitZeroSharePhase3to4;

typedef struct CBTreeMapData_CKeepInitZeroSharePhase3to4 {
  uint8_t key;
  struct CKeepInitZeroSharePhase3to4 val;
} CBTreeMapData_CKeepInitZeroSharePhase3to4;

typedef struct CBTreeMap_CKeepInitZeroSharePhase3to4 {
  const struct CBTreeMapData_CKeepInitZeroSharePhase3to4 *data;
  uintptr_t len;
} CBTreeMap_CKeepInitZeroSharePhase3to4;

typedef struct CTransmitInitZeroSharePhase3to4 {
  struct CPartiesMessage parties;
  CSeed seed;
  uint8_t salt[SALT_LEN];
} CTransmitInitZeroSharePhase3to4;

typedef struct CTransmitInitZeroSharePhase3to4Vec {
  const struct CTransmitInitZeroSharePhase3to4 *data;
  uintptr_t len;
} CTransmitInitZeroSharePhase3to4Vec;

typedef struct COTSender {
  struct CScalar s;
  struct CDLogProof proof;
} COTSender;

typedef struct COTReceiver {
  CSeed seed;
} COTReceiver;

typedef struct CKeepInitMulPhase3to4 {
  struct COTSender ot_sender;
  struct CScalar nonce;
  struct COTReceiver ot_receiver;
  bool correlation[KAPPA];
  struct CScalar vec_r[KAPPA];
} CKeepInitMulPhase3to4;

typedef struct CBTreeMapData_CKeepInitMulPhase3to4 {
  uint8_t key;
  struct CKeepInitMulPhase3to4 val;
} CBTreeMapData_CKeepInitMulPhase3to4;

typedef struct CBTreeMap_CKeepInitMulPhase3to4 {
  const struct CBTreeMapData_CKeepInitMulPhase3to4 *data;
  uintptr_t len;
} CBTreeMap_CKeepInitMulPhase3to4;

typedef struct CCPProof {
  struct CAffinePoint base_g;
  struct CAffinePoint base_h;
  struct CAffinePoint point_u;
  struct CAffinePoint point_v;
  struct CScalar challenge_response;
} CCPProof;

typedef struct CRandomCommitments {
  struct CAffinePoint rc_g;
  struct CAffinePoint rc_h;
} CRandomCommitments;

typedef struct CEncProof {
  struct CCPProof proof0;
  struct CCPProof proof1;
  struct CRandomCommitments commitments0;
  struct CRandomCommitments commitments1;
  struct CScalar challenge0;
  struct CScalar challenge1;
} CEncProof;

typedef struct CTransmitInitMulPhase3to4 {
  struct CPartiesMessage parties;
  struct CDLogProof dlog_proof;
  struct CScalar nonce;
  struct CEncProof enc_proofs[KAPPA];
  CSeed seed;
} CTransmitInitMulPhase3to4;

typedef struct CTransmitInitMulPhase3to4Vec {
  const struct CTransmitInitMulPhase3to4 *data;
  uintptr_t len;
} CTransmitInitMulPhase3to4Vec;

typedef struct CBroadcastDerivationPhase3to4 {
  uint8_t sender_index;
  CChainCode aux_chain_code;
  uint8_t cc_salt[SALT_LEN];
} CBroadcastDerivationPhase3to4;

typedef struct CPhase3Out {
  struct CBTreeMap_CKeepInitZeroSharePhase3to4 zero_keep;
  struct CTransmitInitZeroSharePhase3to4Vec zero_transmit;
  struct CBTreeMap_CKeepInitMulPhase3to4 mul_keep;
  struct CTransmitInitMulPhase3to4Vec mul_transmit;
  struct CBroadcastDerivationPhase3to4 bip_broadcast;
} CPhase3Out;

struct CScalarVec dkls_phase1(const struct CSessionData *session);

struct CPhase2Out dkls_phase2(const struct CSessionData *session,
                              const struct CScalarVec *c_poly_fragments);

struct CPhase3Out dkls_phase3(const struct CSessionData *c_session,
                              const struct CBTreeMap_CKeepInitZeroSharePhase2to3 *c_zero_kept,
                              const struct CUniqueKeepDerivationPhase2to3 *c_bip_kept);
#endif
