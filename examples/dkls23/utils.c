#include "utils.h"

SessionData* create_session(
    uint8_t party_index,
    uint8_t threshold,
    uint8_t share_count,
    size_t session_id_len
) {
    SessionData *session_data = malloc(sizeof(*session_data) +
                                       session_id_len * sizeof(uint8_t));
    session_data->session_id = malloc(session_id_len * sizeof(uint8_t));

    for (uint8_t i = 0; i < session_id_len; i++) {
        uint8_t byte = rand();
        session_data->session_id[i] = byte;
    }

    Parameters p;
    p.threshold = threshold;
    p.share_count = share_count;

    session_data->party_index = party_index;
    session_data->session_id_len = session_id_len;
    session_data->parameters = p;

    return session_data;
}

void print_bytes(const uint8_t* bytes, const char* label, size_t len) {
    printf("%s: ", label);
    for (uint8_t i = 0; i < len; i++) {
        printf("%d ", bytes[i]);
    }
    printf("\n");
}

void print_scalar_vec(const ScalarVec* scalar_vec) {
    for (uint8_t i = 0; i < scalar_vec->len; i++) {
        print_bytes(scalar_vec->data[i].bytes, "scalar", 32);
        printf("\n");
    }
}

void print_dlog_proof(const DLogProof* dlog_proof) {
    printf("DLogProof {\n");
    print_bytes(dlog_proof->point.bytes, "point", SECP256K1_ENCODED_SIZE);
    printf("rand_commitments:\n");
    for (size_t i = 0; i < R; i++) {
        char label[100];
        sprintf(label, "AffinePoint %d", i);
        print_bytes(dlog_proof->rand_commitments[i].bytes, label, SECP256K1_ENCODED_SIZE);
    }

    printf("proofs:\n");
    for (size_t i = 0; i < R; i++) {
        char label[100];
        print_bytes(dlog_proof->proofs[i].challenge, "challenge", T / 8);
        print_bytes(dlog_proof->proofs[i].challenge_response.bytes, "challenge_response", 32);
    }
    printf("}\n");
}

void print_proof_commitment(const ProofCommitment* proof) {
    printf("ProofCommitment {\n");
    printf("index: %d\n", proof->index);
    print_dlog_proof(&proof->proof);
    print_bytes(proof->commitment, "commitment", SECURITY);
    printf("}");
}

void print_phase_2(const Phase2Out* phase2) {
    print_bytes(phase2->poly_point.bytes, "scalar", 32);
    print_proof_commitment(&phase2->proof_commitment);
}
