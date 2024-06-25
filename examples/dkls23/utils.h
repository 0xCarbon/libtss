#include <stdio.h>
#include "keygen.h"

SessionData* create_session(
    uint8_t party_index,
    uint8_t threshold,
    uint8_t share_count,
    size_t session_id_len
);

void print_scalar_vec(const ScalarVec* scalar_vec);
