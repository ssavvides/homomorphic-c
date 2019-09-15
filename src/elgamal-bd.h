#ifndef ELGAMAL_BD_H
#define ELGAMAL_BD_H

#include "bigd.h"
#include "bigdRand.h"

typedef struct {
    BIGD n;
    BIGD g;
    BIGD h;

    // pre-computation
    BIGD sPre;
    BIGD c1Pre;
} elg_bd_pk;

typedef struct {
    BIGD n;
    BIGD g;
    BIGD h;
    BIGD x;
} elg_bd_sk;


void elgamal_bd_init(elg_bd_pk *pk, elg_bd_sk *sk);

void elgamal_bd_encrypt(BIGD c1, BIGD c2, BIGD msg, elg_bd_pk *pk);

void elgamal_bd_encrypt_pre(BIGD c1, BIGD c2, BIGD msg, elg_bd_pk *pk);

void elgamal_bd_decrypt(BIGD msg, BIGD c1, BIGD c2, elg_bd_sk *sk);

#endif
