#include <time.h>
#include "utils.h"

int main() {
    time_t t;
    srand(time(&t));

    SessionData *session_data_1 = create_session(1, 2, 2, 32);
    const Scalar* scalars = dkls_phase1(session_data_1);
    print_scalars(scalars);
}
