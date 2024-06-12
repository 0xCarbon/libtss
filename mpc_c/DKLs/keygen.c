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

extern Scalar* dkls_dkg_phase_1(const CSessionData *data);

int main() {
    unsigned char session_id[] = {1, 2, 3, 4, 5};
    CParameters params = { .threshold = 2, .share_count = 2 };
    CSessionData data = { .parameters = params, .party_index = 1, .session_id = session_id, .session_id_len = sizeof(session_id) };

    Scalar* result = dkls_dkg_phase_1(&data);

    size_t result_len = 2;
    for (size_t i = 0; i < result_len; ++i) {
        printf("Scalar %zu: ", i);
        for (size_t j = 0; j < 32; ++j) {
            printf("%02x", result[i].bytes[j]);
        }
        printf("\n");
    }

    free(result);

    return 0;
}
