#ifndef DKLS23_H
#define DKLS23_H

// DKG
const char* dkls_dkg_phase1(const char* phase1_in);
const char* dkls_dkg_phase2(const char* phase2_in);
const char* dkls_dkg_phase3(const char* phase3_in);
const char* dkls_dkg_phase4(const char* phase4_in);

// SIGN
const char* dkls_sign_phase1(const char* phase1_in);
const char* dkls_sign_phase2(const char* phase2_in);
const char* dkls_sign_phase3(const char* phase3_in);
const char* dkls_sign_phase4(const char* phase4_in);

// Veriy ECDSA signature
const char* dkls_verify_ecdsa_signature(const char* verify_in);

void dkg(const char* ins[], const char* outs[]);
void sign(const char* ins[], const char* outs[]);
void verify(const char* ins[], const char* outs[]);
#endif

