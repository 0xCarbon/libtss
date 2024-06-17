#include <stdio.h>
#include <stdlib.h>

typedef struct {
    const unsigned char *sign_id;
    size_t sign_id_len;
    const unsigned char *counterparties;
    size_t counterparties_len;
    unsigned char message_hash[32]; // Assuming SECURITY is 32
} CSignData;

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
    unsigned char data[32]; // Assuming EXTENDED_BATCH_SIZE / 8 is 32
} CPRGOutput;

typedef struct {
    Scalar b;
    const unsigned char *choice_bits;
    size_t choice_bits_len;
    const CPRGOutput *extended_seeds;
    size_t extended_seeds_len;
    const Scalar *chi_tilde;
    size_t chi_tilde_len;
    const Scalar *chi_hat;
    size_t chi_hat_len;
} CMulDataToKeepReceiver;

typedef struct {
    const CPRGOutput *u;
    size_t u_len;
    Scalar verify_x;
    const Scalar *verify_t;
    size_t verify_t_len;
} COTEDataToSender;

typedef struct {
    const unsigned char *salt;
    size_t salt_len;
    Scalar chi;
    CMulDataToKeepReceiver mul_keep;
} CKeepPhase1to2;

typedef struct {
    unsigned char sender;
    unsigned char receiver;
} CPartiesMessage;

typedef struct {
    CPartiesMessage parties;
    unsigned char commitment[32]; // Assuming SECURITY is 32
    COTEDataToSender mul_transmit;
} CTransmitPhase1to2;

typedef struct {
    Scalar instance_key;
    CAffinePoint instance_point;
    Scalar inversion_mask;
    Scalar zeta;
} CUniqueKeep1to2;

extern void dkls_sign_phase_1(
    const void *party,
    const CSignData *sign_data,
    CUniqueKeep1to2 *out_unique_keep,
    CKeepPhase1to2 **out_keep_phase,
    size_t *out_keep_phase_len,
    CTransmitPhase1to2 **out_transmit_phase,
    size_t *out_transmit_phase_len
);

void sign_phase_1(
    const void *party,
    const CSignData *sign_data,
    CUniqueKeep1to2 *out_unique_keep,
    CKeepPhase1to2 **out_keep_phase,
    size_t *out_keep_phase_len,
    CTransmitPhase1to2 **out_transmit_phase,
    size_t *out_transmit_phase_len
) {
    dkls_sign_phase_1(
        party,
        sign_data,
        out_unique_keep,
        out_keep_phase,
        out_keep_phase_len,
        out_transmit_phase,
        out_transmit_phase_len
    );
}

typedef struct {
    Scalar instance_key;
    CAffinePoint instance_point;
    Scalar inversion_mask;
    Scalar key_share;
    CAffinePoint public_share;
} CUniqueKeep2to3;

typedef struct {
    Scalar c_u;
    Scalar c_v;
    unsigned char commitment[32]; // Assuming SECURITY is 32
    CMulDataToKeepReceiver mul_keep;
    Scalar chi;
} CKeepPhase2to3;

typedef struct {
    const Scalar *vector_of_tau;
    size_t vector_of_tau_len;
    unsigned char verify_r[32]; // Assuming SECURITY is 32
    const Scalar *verify_u;
    size_t verify_u_len;
    const Scalar *gamma_sender;
    size_t gamma_sender_len;
} CMulDataToReceiver;

typedef struct {
    CPartiesMessage parties;
    CAffinePoint gamma_u;
    CAffinePoint gamma_v;
    Scalar psi;
    CAffinePoint public_share;
    CAffinePoint instance_point;
    const unsigned char *salt;
    size_t salt_len;
    CMulDataToReceiver mul_transmit;
} CTransmitPhase2to3;

extern unsigned char dkls_sign_phase_2(
    const void *party,
    const CSignData *sign_data,
    const CUniqueKeep1to2 *unique_kept,
    const CKeepPhase1to2 *kept,
    size_t kept_len,
    const CTransmitPhase1to2 *received,
    size_t received_len,
    CUniqueKeep2to3 *out_unique_keep,
    CKeepPhase2to3 **out_keep_phase,
    size_t *out_keep_phase_len,
    CTransmitPhase2to3 **out_transmit_phase,
    size_t *out_transmit_phase_len
);

unsigned char sign_phase_2(
    const void *party,
    const CSignData *sign_data,
    const CUniqueKeep1to2 *unique_kept,
    const CKeepPhase1to2 *kept,
    size_t kept_len,
    const CTransmitPhase1to2 *received,
    size_t received_len,
    CUniqueKeep2to3 *out_unique_keep,
    CKeepPhase2to3 **out_keep_phase,
    size_t *out_keep_phase_len,
    CTransmitPhase2to3 **out_transmit_phase,
    size_t *out_transmit_phase_len
) {
    return dkls_sign_phase_2(
        party,
        sign_data,
        unique_kept,
        kept,
        kept_len,
        received,
        received_len,
        out_unique_keep,
        out_keep_phase,
        out_keep_phase_len,
        out_transmit_phase,
        out_transmit_phase_len
    );
}


int main() {
    unsigned char sign_id[] = {1, 2, 3, 4, 5};
    unsigned char counterparties[] = {2};
    unsigned char message_hash[32] = {0};

    CSignData sign_data = {
        .sign_id = sign_id,
        .sign_id_len = sizeof(sign_id),
        .counterparties = counterparties,
        .counterparties_len = sizeof(counterparties),
        .message_hash = {0}
    };

    CUniqueKeep1to2 out_unique_keep_phase1;
    CKeepPhase1to2 *out_keep_phase_phase1;
    size_t out_keep_phase_len_phase1;
    CTransmitPhase1to2 *out_transmit_phase_phase1;
    size_t out_transmit_phase_len_phase1;

    // Assuming `party` is initialized properly
    void *party = NULL;

    // Call phase 1
    sign_phase_1(
        party,
        &sign_data,
        &out_unique_keep_phase1,
        &out_keep_phase_phase1,
        &out_keep_phase_len_phase1,
        &out_transmit_phase_phase1,
        &out_transmit_phase_len_phase1
    );

    // // Print results of phase 1
    // printf("Unique Keep Instance Key (Phase 1): ");
    // for (size_t i = 0; i < 32; ++i) {
    //     printf("%02x", out_unique_keep_phase1.instance_key.bytes[i]);
    // }
    // printf("\n");

    // // Prepare for phase 2
    // CUniqueKeep2to3 out_unique_keep_phase2;
    // CKeepPhase2to3 *out_keep_phase_phase2;
    // size_t out_keep_phase_len_phase2;
    // CTransmitPhase2to3 *out_transmit_phase_phase2;
    // size_t out_transmit_phase_len_phase2;

    // // Call phase 2
    // unsigned char result = sign_phase_2(
    //     party,
    //     &sign_data,
    //     &out_unique_keep_phase1,
    //     out_keep_phase_phase1,
    //     out_keep_phase_len_phase1,
    //     out_transmit_phase_phase1,
    //     out_transmit_phase_len_phase1,
    //     &out_unique_keep_phase2,
    //     &out_keep_phase_phase2,
    //     &out_keep_phase_len_phase2,
    //     &out_transmit_phase_phase2,
    //     &out_transmit_phase_len_phase2
    // );

    // if (result == 0) {
    //     // Print results of phase 2
    //     printf("Unique Keep Instance Key (Phase 2): ");
    //     for (size_t i = 0; i < 32; ++i) {
    //         printf("%02x", out_unique_keep_phase2.instance_key.bytes[i]);
    //     }
    //     printf("\n");
    // } else {
    //     printf("Phase 2 failed\n");
    // }

    // // Free allocated memory
    // free(out_keep_phase_phase1);
    // free(out_transmit_phase_phase1);
    // free(out_keep_phase_phase2);
    // free(out_transmit_phase_phase2);

    return 0;
}
