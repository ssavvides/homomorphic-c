#ifndef ELGAMAL_BD_H
#define ELGAMAL_BD_H

#include <stdbool.h>

#include "bigd.h"
#include "bigdRand.h"

typedef struct {
    BIGD n;
    BIGD g;
    BIGD h;

    // pre-computation
    BIGD sPre;
    BIGD c1Pre;
} elgamal_bd_pk;

typedef struct {
    BIGD n;
    BIGD g;
    BIGD h;
    BIGD x;
} elgamal_bd_sk;

typedef struct {
    int packed_ops;
    BIGD c1;
    BIGD c2;
} elgamal_bd_ctxt;

void elgamal_bd_ctxt_init(elgamal_bd_ctxt *ctxt);
void elgamal_bd_init(elgamal_bd_pk *pk, elgamal_bd_sk *sk);

void elgamal_bd_encrypt(elgamal_bd_ctxt* ctxt, int msg, elgamal_bd_pk *pk,
    bool precomptation);
void elgamal_bd_encrypt_bd(elgamal_bd_ctxt* ctxt, BIGD ptxt, elgamal_bd_pk *pk,
    bool precomptation);
void elgamal_bd_encrypt_packed(elgamal_bd_ctxt* ctxt, int* messages, int len,
    elgamal_bd_pk *pk, bool precomptation);

void elgamal_bd_decrypt(long* msg, elgamal_bd_ctxt* ctxt, elgamal_bd_sk *sk);
void elgamal_bd_decrypt_packed(long* messages, elgamal_bd_ctxt *ctxt, elgamal_bd_sk *sk);
void elgamal_bd_decrypt_bd(BIGD ptxt, elgamal_bd_ctxt *ctxt, elgamal_bd_sk *sk);

#endif
