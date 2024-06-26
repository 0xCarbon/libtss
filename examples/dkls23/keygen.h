#include <stdint.h>
#include <stdlib.h>

#define SECP256K1_ENCODED_SIZE 33
#define T 32
#define R 64
#define SECURITY 32

typedef uint8_t HashOutput[SECURITY];
typedef uint8_t ChainCode[32];

typedef struct {
    uint8_t threshold;
    uint8_t share_count;
} Parameters;

typedef struct {
    Parameters parameters;
    uint8_t party_index;
    size_t session_id_len;
    uint8_t* session_id;
} SessionData;

typedef struct {
    uint8_t bytes[32];
} Scalar;

typedef struct {
    const Scalar* data;
    size_t len;
} ScalarVec;

typedef struct {
    uint8_t bytes[SECP256K1_ENCODED_SIZE];
} AffinePoint;

typedef struct {
    uint8_t challenge[T / 8];
    Scalar challenge_response;
} InteractiveDLogProof;

typedef struct {
    AffinePoint point;
    AffinePoint rand_commitments[R];
    InteractiveDLogProof proofs[R];
} DLogProof;

typedef struct {
    uint8_t index;
    DLogProof proof;
    HashOutput commitment;
} ProofCommitment;

typedef struct {
    uint8_t sender;
    uint8_t receiver;
} PartiesMessage;

typedef struct {
    PartiesMessage parties;
    HashOutput commitment;
} TransmitInitZeroSharePhase2to4;

typedef struct {
    const TransmitInitZeroSharePhase2to4* data;
    size_t len;
} TransmitInitZeroSharePhase2to4Vec;

typedef struct {
    ChainCode aux_chain_code;
    uint8_t cc_salt[2 * SECURITY];
} UniqueKeepDerivationPhase2to3;

typedef struct {
    uint8_t sender_index;
    HashOutput cc_commitment;
} BroadcastDerivationPhase2to4;

typedef struct {
    Scalar poly_point;
    ProofCommitment proof_commitment;
    //pub zero_keep: CBTreeMap<u8, KeepInitZeroSharePhase2to3>,
    TransmitInitZeroSharePhase2to4Vec zero_transmit;
    UniqueKeepDerivationPhase2to3 bip_keep;
    BroadcastDerivationPhase2to4 bip_broadcast;
} Phase2Out;

extern ScalarVec dkls_phase1(const SessionData *data);
extern Phase2Out dkls_phase2(
    const SessionData *data,
    const ScalarVec *poly_fragments
);
