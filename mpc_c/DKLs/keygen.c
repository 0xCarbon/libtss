#include <stdio.h>
#include <stdlib.h>

typedef struct {
    unsigned char threshold;
    unsigned char share_count;
} CParameters;

typedef struct {
    CParameters parameters;
    unsigned char party_index;
    const unsigned char *session_id;
    size_t session_id_len;
} CSessionData;

typedef struct {
    unsigned char bytes[32];
} Scalar;

typedef struct {
    unsigned char x[32];
    unsigned char y[32];
    unsigned char infinity;
} CAffinePoint;

typedef struct {
    const unsigned char *challenge;
    size_t challenge_len;
    Scalar challenge_response;
} CInteractiveDLogProof;

typedef struct {
    CAffinePoint point;
    const CAffinePoint *rand_commitments;
    size_t rand_commitments_len;
    const CInteractiveDLogProof *proofs;
    size_t proofs_len;
} CDLogProof;

typedef struct {
    unsigned char index;
    CDLogProof proof;
    unsigned char commitment[32]; // Assuming SECURITY is 32
} CProofCommitment;

typedef struct {
    unsigned char seed[32]; // Assuming SECURITY is 32
    const unsigned char *salt;
    size_t salt_len;
} CKeepInitZeroSharePhase2to3;

typedef struct {
    unsigned char sender;
    unsigned char receiver;
} CPartiesMessage;

typedef struct {
    CPartiesMessage parties;
    unsigned char commitment[32]; // Assuming SECURITY is 32
} CTransmitInitZeroSharePhase2to4;

typedef struct {
    unsigned char aux_chain_code[32];
    const unsigned char *cc_salt;
    size_t cc_salt_len;
} CUniqueKeepDerivationPhase2to3;

typedef struct {
    unsigned char sender_index;
    unsigned char cc_commitment[32]; // Assuming SECURITY is 32
} CBroadcastDerivationPhase2to4;

extern Scalar* dkls_dkg_phase_1(const CSessionData *data);

Scalar* dkls_keygen_1(
    const CSessionData data
) {
    Scalar* result = dkls_dkg_phase_1(&data);

    // size_t result_len = 2;
    // for (size_t i = 0; i < result_len; ++i) {
    //     printf("Scalar %zu: ", i);
    //     for (size_t j = 0; j < 32; ++j) {
    //         printf("%02x", result[i].bytes[j]);
    //     }
    //     printf("\n");
    // }

    // this function should return a vec of Scalars
    return result;
}

extern void dkls_dkg_phase_2(
    const CSessionData *data,
    const Scalar *poly_fragments,
    size_t poly_fragments_len,
    Scalar *out_scalar,
    CProofCommitment *out_proof_commitment,
    CKeepInitZeroSharePhase2to3 **out_zero_shares,
    size_t *out_zero_shares_len,
    CTransmitInitZeroSharePhase2to4 **out_transmit_zero_shares,
    size_t *out_transmit_zero_shares_len,
    CUniqueKeepDerivationPhase2to3 *out_unique_keep,
    CBroadcastDerivationPhase2to4 *out_broadcast
);

void dkls_keygen_2(
    const CSessionData data,
    const Scalar *poly_fragments,
    size_t poly_fragments_len,
    Scalar *out_scalar,
    CProofCommitment *out_proof_commitment,
    CKeepInitZeroSharePhase2to3 **out_zero_shares,
    size_t *out_zero_shares_len,
    CTransmitInitZeroSharePhase2to4 **out_transmit_zero_shares,
    size_t *out_transmit_zero_shares_len,
    CUniqueKeepDerivationPhase2to3 *out_unique_keep,
    CBroadcastDerivationPhase2to4 *out_broadcast
) {
    dkls_dkg_phase_2(
        &data,
        poly_fragments,
        poly_fragments_len,
        out_scalar,
        out_proof_commitment,
        out_zero_shares,
        out_zero_shares_len,
        out_transmit_zero_shares,
        out_transmit_zero_shares_len,
        out_unique_keep,
        out_broadcast
    );
}

int main() {
    //  ****THIS MAIN FUNCTION IS BEING USED FOR TEST PHASES****
    
    // start phase 1
    unsigned char session_id[] = {1, 2, 3, 4, 5};
    CParameters params = { .threshold = 2, .share_count = 2 };
    CSessionData data = { .parameters = params, .party_index = 1, .session_id = session_id, .session_id_len = sizeof(session_id) };

    // phase 1 result
    Scalar* phase_1_result = dkls_keygen_1(data);
    size_t result_len = 2;
    for (size_t i = 0; i < result_len; ++i) {
        printf("Phase 1 %zu: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", phase_1_result[i].bytes[j]);
        }
        printf("\n");
    }


    /////////////////////////////////////////////
    // start phase 2
    for (size_t i = 0; i < 2; ++i) {
        for (size_t j = 0; j < 32; ++j) {
            phase_1_result[i].bytes[j] = (unsigned char)(i + j);
        }
    }

    Scalar out_scalar;
    CProofCommitment out_proof_commitment;
    CKeepInitZeroSharePhase2to3 *out_zero_shares;
    size_t out_zero_shares_len;
    CTransmitInitZeroSharePhase2to4 *out_transmit_zero_shares;
    size_t out_transmit_zero_shares_len;
    CUniqueKeepDerivationPhase2to3 out_unique_keep;
    CBroadcastDerivationPhase2to4 out_broadcast;

    dkls_keygen_2(
        data,
        phase_1_result,
        2,
        &out_scalar,
        &out_proof_commitment,
        &out_zero_shares,
        &out_zero_shares_len,
        &out_transmit_zero_shares,
        &out_transmit_zero_shares_len,
        &out_unique_keep,
        &out_broadcast
    );

    // Print phase 2 
    printf("Phase 2: ");
    for (size_t j = 0; j < 32; ++j) {
        printf("%02x", out_scalar.bytes[j]);
    }
    printf("\n");


    // Free allocated memory
    free(out_zero_shares);
    free(out_transmit_zero_shares);
    free(phase_1_result);

    return 0;
}