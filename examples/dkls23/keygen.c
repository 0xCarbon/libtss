#include <stdio.h>
#include <stdlib.h>
#include "tests.h"

int main() {
    bool success = test_phase1();
    if (success) {
        printf("phase 1: passed");
    } else {
        printf("phase 1 failed");
        exit(1);
    }
}
