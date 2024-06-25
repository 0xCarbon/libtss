#include <stdint.h>
#include <stdlib.h>

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

extern ScalarVec dkls_phase1(const SessionData *data);
extern uint8_t* dkls_phase2(
    const SessionData *data,
    const ScalarVec *poly_fragments
);
