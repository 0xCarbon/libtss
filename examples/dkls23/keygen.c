#include <time.h>
#include "utils.h"

int main() {
    time_t t;
    srand(time(&t));

    SessionData *session_data_1 = create_session(1, 2, 2, 32);
    ScalarVec scalars = dkls_phase1(session_data_1);
    //print_scalar_vec(&scalars);

    Phase2Out phase2_out = dkls_phase2(session_data_1, &scalars);
    print_phase_2(&phase2_out);
}
