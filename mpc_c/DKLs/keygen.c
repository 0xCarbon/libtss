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

typedef struct {
    unsigned char seed[32]; // Assuming SECURITY is 32
} CKeepInitZeroSharePhase3to4;

typedef struct {
    CPartiesMessage parties;
    unsigned char seed[32]; // Assuming SECURITY is 32
    const unsigned char *salt;
    size_t salt_len;
} CTransmitInitZeroSharePhase3to4;

typedef struct {
    Scalar s;
    CDLogProof proof;
} COTSender;

typedef struct {
    unsigned char seed[32]; // Assuming SECURITY is 32
} COTReceiver;

typedef struct {
    COTSender ot_sender;
    Scalar nonce;
    COTReceiver ot_receiver;
    const unsigned char *correlation;
    size_t correlation_len;
    const Scalar *vec_r;
    size_t vec_r_len;
} CKeepInitMulPhase3to4;

typedef struct {
    CPartiesMessage parties;
    CDLogProof dlog_proof;
    Scalar nonce;
    const void *enc_proofs; // Placeholder for CEncProof
    size_t enc_proofs_len;
    unsigned char seed[32]; // Assuming SECURITY is 32
} CTransmitInitMulPhase3to4;

typedef struct {
    unsigned char sender_index;
    unsigned char aux_chain_code[32];
    const unsigned char *cc_salt;
    size_t cc_salt_len;
} CBroadcastDerivationPhase3to4;

extern Scalar* dkls_dkg_phase_1(const CSessionData *data);

Scalar* dkls_keygen_1(const CSessionData data) {
    Scalar* result = dkls_dkg_phase_1(&data);
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

extern void dkls_dkg_phase_3(
    const CSessionData *data,
    const CKeepInitZeroSharePhase2to3 *zero_kept,
    size_t zero_kept_len,
    const CUniqueKeepDerivationPhase2to3 *bip_kept,
    CKeepInitZeroSharePhase3to4 **out_zero_shares,
    size_t *out_zero_shares_len,
    CTransmitInitZeroSharePhase3to4 **out_transmit_zero_shares,
    size_t *out_transmit_zero_shares_len,
    CKeepInitMulPhase3to4 **out_keep_mul,
    size_t *out_keep_mul_len,
    CTransmitInitMulPhase3to4 **out_transmit_mul,
    size_t *out_transmit_mul_len,
    CBroadcastDerivationPhase3to4 *out_broadcast
);

void dkls_keygen_3(
    const CSessionData data,
    const CKeepInitZeroSharePhase2to3 *zero_kept,
    size_t zero_kept_len,
    const CUniqueKeepDerivationPhase2to3 *bip_kept,
    CKeepInitZeroSharePhase3to4 **out_zero_shares,
    size_t *out_zero_shares_len,
    CTransmitInitZeroSharePhase3to4 **out_transmit_zero_shares,
    size_t *out_transmit_zero_shares_len,
    CKeepInitMulPhase3to4 **out_keep_mul,
    size_t *out_keep_mul_len,
    CTransmitInitMulPhase3to4 **out_transmit_mul,
    size_t *out_transmit_mul_len,
    CBroadcastDerivationPhase3to4 *out_broadcast
) {
    dkls_dkg_phase_3(
        &data,
        zero_kept,
        zero_kept_len,
        bip_kept,
        out_zero_shares,
        out_zero_shares_len,
        out_transmit_zero_shares,
        out_transmit_zero_shares_len,
        out_keep_mul,
        out_keep_mul_len,
        out_transmit_mul,
        out_transmit_mul_len,
        out_broadcast
    );
}

int main() {
    //  ****THIS MAIN FUNCTION IS BEING USED FOR TEST PHASES****
    
    // start phase 1
    unsigned char session_id[] = {1, 2, 3, 4, 5};
    CParameters params = { .threshold = 2, .share_count = 2 };

    CSessionData data_party_1 = { .parameters = params, .party_index = 1, .session_id = session_id, .session_id_len = sizeof(session_id) };
    CSessionData data_party_2 = { .parameters = params, .party_index = 2, .session_id = session_id, .session_id_len = sizeof(session_id) };

    // phase 1 result
    Scalar* party_1_phase_1_result = dkls_keygen_1(data_party_1);
    size_t result_len = 2;
    // for (size_t i = 0; i < result_len; ++i) {
    //     printf("Phase 1 party 1 %zu: ", i);
    //     for (size_t j = 0; j < 32; ++j) {
    //         printf("%02x", party_1_phase_1_result[i].bytes[j]);
    //     }
    //     printf("\n");
    // }
    
    Scalar* party_2_phase_1_result = dkls_keygen_1(data_party_2);
    // for (size_t i = 0; i < result_len; ++i) {
    //     printf("Phase 1 party 2 %zu: ", i);
    //     for (size_t j = 0; j < 32; ++j) {
    //         printf("%02x", party_2_phase_1_result[i].bytes[j]);
    //     }
    //     printf("\n");
    // }

    


    /////////////////////////////////////////////
    // start phase 2
    // for (size_t i = 0; i < 2; ++i) {
    //     for (size_t j = 0; j < 32; ++j) {
    //         party_1_phase_1_result[i].bytes[j] = (unsigned char)(i + j);
    //     }
    // }

    // p1 phase 2 results in variables below
    Scalar p1_phase_2_out_scalar;
    CProofCommitment p1_phase_2_out_proof_commitment;
    CKeepInitZeroSharePhase2to3 *p1_phase_2_out_zero_shares;
    size_t p1_phase_2_out_zero_shares_len;
    CTransmitInitZeroSharePhase2to4 *p1_phase_2_out_transmit_zero_shares;
    size_t p1_phase_2_out_transmit_zero_shares_len;
    CUniqueKeepDerivationPhase2to3 p1_phase_2_out_unique_keep;
    CBroadcastDerivationPhase2to4 p1_phase_2_out_broadcast;

    dkls_keygen_2(
        data_party_1,
        party_1_phase_1_result,
        2,
        &p1_phase_2_out_scalar,
        &p1_phase_2_out_proof_commitment,
        &p1_phase_2_out_zero_shares,
        &p1_phase_2_out_zero_shares_len,
        &p1_phase_2_out_transmit_zero_shares,
        &p1_phase_2_out_transmit_zero_shares_len,
        &p1_phase_2_out_unique_keep,
        &p1_phase_2_out_broadcast
    );
    
    printf("p1 Phase 2: ");
    for (size_t j = 0; j < 32; ++j) {
        printf("%02x", p1_phase_2_out_scalar.bytes[j]);
    }
    printf("\n");
    
    // p2 phase 2 results in variables below
    Scalar p2_phase_2_out_scalar;
    CProofCommitment p2_phase_2_out_proof_commitment;
    CKeepInitZeroSharePhase2to3 *p2_phase_2_out_zero_shares;
    size_t p2_phase_2_out_zero_shares_len;
    CTransmitInitZeroSharePhase2to4 *p2_phase_2_out_transmit_zero_shares;
    size_t p2_phase_2_out_transmit_zero_shares_len;
    CUniqueKeepDerivationPhase2to3 p2_phase_2_out_unique_keep;
    CBroadcastDerivationPhase2to4 p2_phase_2_out_broadcast;

    dkls_keygen_2(
        data_party_2,
        party_2_phase_1_result,
        2,
        &p2_phase_2_out_scalar,
        &p2_phase_2_out_proof_commitment,
        &p2_phase_2_out_zero_shares,
        &p2_phase_2_out_zero_shares_len,
        &p2_phase_2_out_transmit_zero_shares,
        &p2_phase_2_out_transmit_zero_shares_len,
        &p2_phase_2_out_unique_keep,
        &p2_phase_2_out_broadcast
    );

    // Print phase 2 
    printf("p2 Phase 2: ");
    for (size_t j = 0; j < 32; ++j) {
        printf("%02x", p2_phase_2_out_scalar.bytes[j]);
    }
    printf("\n");


    // p1 phase 3 results below
    CKeepInitZeroSharePhase3to4 *p1_out_zero_shares_phase3;
    size_t p1_out_zero_shares_len_phase3;
    CTransmitInitZeroSharePhase3to4 *p1_out_transmit_zero_shares_phase3;
    size_t p1_out_transmit_zero_shares_len_phase3;
    CKeepInitMulPhase3to4 *p1_out_keep_mul_phase3;
    size_t p1_out_keep_mul_len_phase3;
    CTransmitInitMulPhase3to4 *p1_out_transmit_mul_phase3;
    size_t p1_out_transmit_mul_len_phase3;
    CBroadcastDerivationPhase3to4 p1_out_broadcast_phase3;

    dkls_keygen_3(
        data_party_1,
        p1_phase_2_out_zero_shares,
        p1_phase_2_out_zero_shares_len,
        &p1_phase_2_out_unique_keep,
        &p1_out_zero_shares_phase3,
        &p1_out_zero_shares_len_phase3,
        &p1_out_transmit_zero_shares_phase3,
        &p1_out_transmit_zero_shares_len_phase3,
        &p1_out_keep_mul_phase3,
        &p1_out_keep_mul_len_phase3,
        &p1_out_transmit_mul_phase3,
        &p1_out_transmit_mul_len_phase3,
        &p1_out_broadcast_phase3
    );

    // Print p1 phase 3 results
    printf("p1 Phase 3 Zero Shares Length: %zu\n", p1_out_zero_shares_len_phase3);
    for (size_t i = 0; i < p1_out_zero_shares_len_phase3; ++i) {
        printf("Zero Share %zu Seed: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", p1_out_zero_shares_phase3[i].seed[j]);
        }
        printf("\n");
    }

    printf("p1 Phase 3 Transmit Zero Shares Length: %zu\n", p1_out_transmit_zero_shares_len_phase3);
    for (size_t i = 0; i < p1_out_transmit_zero_shares_len_phase3; ++i) {
        printf("Transmit Zero Share %zu Seed: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", p1_out_transmit_zero_shares_phase3[i].seed[j]);
        }
        printf("\n");
    }

    printf("p1 Phase 3 Keep Mul Length: %zu\n", p1_out_keep_mul_len_phase3);
    for (size_t i = 0; i < p1_out_keep_mul_len_phase3; ++i) {
        printf("Keep Mul %zu Nonce: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", p1_out_keep_mul_phase3[i].nonce.bytes[j]);
        }
        printf("\n");
    }

    printf("p1 Phase 3 Transmit Mul Length: %zu\n", p1_out_transmit_mul_len_phase3);
    for (size_t i = 0; i < p1_out_transmit_mul_len_phase3; ++i) {
        printf("Transmit Mul %zu Nonce: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", p1_out_transmit_mul_phase3[i].nonce.bytes[j]);
        }
        printf("\n");
    }

    printf("p1 Phase 3 Broadcast Sender Index: %u\n", p1_out_broadcast_phase3.sender_index);
    printf("p1 Phase 3 Broadcast Aux Chain Code: ");
    for (size_t j = 0; j < 32; ++j) {
        printf("%02x", p1_out_broadcast_phase3.aux_chain_code[j]);
    }
    printf("\n");


    // p2 phase 3 results below
    CKeepInitZeroSharePhase3to4 *p2_out_zero_shares_phase3;
    size_t p2_out_zero_shares_len_phase3;
    CTransmitInitZeroSharePhase3to4 *p2_out_transmit_zero_shares_phase3;
    size_t p2_out_transmit_zero_shares_len_phase3;
    CKeepInitMulPhase3to4 *p2_out_keep_mul_phase3;
    size_t p2_out_keep_mul_len_phase3;
    CTransmitInitMulPhase3to4 *p2_out_transmit_mul_phase3;
    size_t p2_out_transmit_mul_len_phase3;
    CBroadcastDerivationPhase3to4 p2_out_broadcast_phase3;


    dkls_keygen_3(
        data_party_2,
        p2_phase_2_out_zero_shares,
        p2_phase_2_out_zero_shares_len,
        &p2_phase_2_out_unique_keep,
        &p2_out_zero_shares_phase3,
        &p2_out_zero_shares_len_phase3,
        &p2_out_transmit_zero_shares_phase3,
        &p2_out_transmit_zero_shares_len_phase3,
        &p2_out_keep_mul_phase3,
        &p2_out_keep_mul_len_phase3,
        &p2_out_transmit_mul_phase3,
        &p2_out_transmit_mul_len_phase3,
        &p2_out_broadcast_phase3
    );

    // Print p1 phase 3 results
    printf("p2 Phase 3 Zero Shares Length: %zu\n", p2_out_zero_shares_len_phase3);
    for (size_t i = 0; i < p2_out_zero_shares_len_phase3; ++i) {
        printf("Zero Share %zu Seed: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", p2_out_zero_shares_phase3[i].seed[j]);
        }
        printf("\n");
    }

    printf("p2 Phase 3 Transmit Zero Shares Length: %zu\n", p2_out_transmit_zero_shares_len_phase3);
    for (size_t i = 0; i < p2_out_transmit_zero_shares_len_phase3; ++i) {
        printf("Transmit Zero Share %zu Seed: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", p2_out_transmit_zero_shares_phase3[i].seed[j]);
        }
        printf("\n");
    }

    printf("p2 Phase 3 Keep Mul Length: %zu\n", p2_out_keep_mul_len_phase3);
    for (size_t i = 0; i < p2_out_keep_mul_len_phase3; ++i) {
        printf("Keep Mul %zu Nonce: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", p2_out_keep_mul_phase3[i].nonce.bytes[j]);
        }
        printf("\n");
    }

    printf("p2 Phase 3 Transmit Mul Length: %zu\n", p2_out_transmit_mul_len_phase3);
    for (size_t i = 0; i < p2_out_transmit_mul_len_phase3; ++i) {
        printf("Transmit Mul %zu Nonce: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", p2_out_transmit_mul_phase3[i].nonce.bytes[j]);
        }
        printf("\n");
    }

    printf("p2 Phase 3 Broadcast Sender Index: %u\n", p2_out_broadcast_phase3.sender_index);
    printf("p2 Phase 3 Broadcast Aux Chain Code: ");
    for (size_t j = 0; j < 32; ++j) {
        printf("%02x", p2_out_broadcast_phase3.aux_chain_code[j]);
    }
    printf("\n");

    return 0;
}