#include <stdio.h>
#include "keygen.h"

SessionData* create_session(
    uint8_t party_index,
    uint8_t threshold,
    uint8_t share_count,
    size_t session_id_len
);

void print_scalar_vec(const ScalarVec* scalar_vec);
void print_phase_2(const Phase2Out* phase2);
void print_phase_2(const CPhase2Out* phase2);
