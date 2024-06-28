#include "keygen.h"
#include "mocks.h"

bool test_phase1() {
    CScalarVec scalars = dkls_phase1(&session);

    for (size_t i = 0; i < 2; i++) {
        for (size_t j = 0; j < 32; j++) {
            if (scalars.data[i].bytes[j] != PHASE1_FRAGMENTS[i][j]) {
                return false;
            }
        }
    }
    return true;
}
