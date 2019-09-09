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


void init_elgamal_bd(elg_bd_pk *pk, elg_bd_sk *sk);
void encrypt_elgamal_bd(BIGD c1, BIGD c2, BIGD msg, elg_bd_pk *pk);
void encrypt_pre_elgamal_bd(BIGD c1, BIGD c2, BIGD msg, elg_bd_pk *pk);
void decrypt_elgamal_bd(BIGD msg, BIGD c1, BIGD c2, elg_bd_sk *sk);

#endif
