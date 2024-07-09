#include "dkls23.h"

void dkg(const char** ins, const char** outs) {
    outs[0] = dkls_dkg_phase1(ins[0]);
    outs[1] = dkls_dkg_phase2(ins[1]);
    outs[2] = dkls_dkg_phase3(ins[2]);
    outs[3] = dkls_dkg_phase4(ins[3]);
}

void sign(const char** ins, const char** outs) {
    outs[0] = dkls_sign_phase1(ins[0]);
    outs[1] = dkls_sign_phase2(ins[1]);
    outs[2] = dkls_sign_phase3(ins[2]);
    outs[3] = dkls_sign_phase4(ins[3]);
}
