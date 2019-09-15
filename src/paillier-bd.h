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

void paillier_bd_init(paillier_bd_pk *pubKey, paillier_bd_sk *privKey);

void paillier_bd_encrypt(BIGD ctxt, const BIGD ptxt, const paillier_bd_pk *pubKey);

void paillier_bd_encrypt_pre(BIGD ctxt, const BIGD ptxt, const paillier_bd_pk *pubKey);

void paillier_bd_decrypt(BIGD ptxt, const BIGD ctxt, const paillier_bd_sk *key);

void paillier_bd_decrypt_crt(BIGD ptxt, const BIGD ctxt, const paillier_bd_sk *key);

#endif
