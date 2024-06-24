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

void print_scalars(const Scalar* scalars) {
    for (uint8_t i = 0; i < 32; i++) {
        printf("%02X", scalars[0].bytes[i]);
    }
    printf("\n");
    for (uint8_t i = 0; i < 32; i++) {
        printf("%02X", scalars[1].bytes[i]);
    }
}
