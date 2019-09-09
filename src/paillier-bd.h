#ifndef _PAILLIER_BD_H_
#define _PAILLIER_BD_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bigd.h"
#include "bigdRand.h"

typedef struct {
	BIGD n, n2;
	BIGD g;
	BIGD tmp2Pre;
} paillier_bd_pk;

typedef struct {
	BIGD n, n2;
	BIGD lamda, mu;
	// optimizations
	BIGD p2invq2, p2, q2;
} paillier_bd_sk;

static BIGD threshold_bd;

void init_paillier_bd(paillier_bd_pk *pubKey, paillier_bd_sk *privKey);
void encrypt_paillier_bd(BIGD ctxt, const BIGD ptxt, const paillier_bd_pk *pubKey);
void encrypt_pre_paillier_bd(BIGD ctxt, const BIGD ptxt, const paillier_bd_pk *pubKey);
void decrypt_paillier_bd(BIGD ptxt, const BIGD ctxt, const paillier_bd_sk *key);

#endif
