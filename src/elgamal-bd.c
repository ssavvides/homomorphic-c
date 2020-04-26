#include "pk.h"
#include "bd-ops.h"
#include "elgamal-bd.h"


void elgamal_bd_init(elg_bd_pk *pk, elg_bd_sk *sk) {
    sk->n = bdNew();
    sk->g = bdNew();
    sk->h = bdNew();
    sk->x = bdNew();
    pk->n = bdNew();
    pk->g = bdNew();
    pk->h = bdNew();

    bd_prime(sk->n, DEFAULT_KEY_LEN);
    bd_rand(sk->x, DEFAULT_KEY_LEN, false);
    bd_prime(sk->g, DEFAULT_KEY_LEN);

    // h = g^x (mod n)
    bdModExp(sk->h, sk->g, sk->x, sk->n);

    bdSetEqual(pk->n, sk->n);
    bdSetEqual(pk->g, sk->g);
    bdSetEqual(pk->h, sk->h);

    // PRECOMPUTATION
    BIGD y = bdNew();
    bd_rand(y, DEFAULT_KEY_LEN, false);

    pk->sPre = bdNew();
    pk->c1Pre = bdNew();
    bdModExp(pk->sPre, pk->h, y, pk->n);
    bdModExp(pk->c1Pre, pk->g, y, pk->n);

    bdFree(&y);
}

void elgamal_bd_encrypt(BIGD c1, BIGD c2, int msg, elg_bd_pk *pk) {

    BIGD ptxt = bdNew();
    int_to_bd(ptxt, msg);

    BIGD y = bdNew();
    bd_rand(y, DEFAULT_KEY_LEN, false);

    BIGD s = bdNew();
    bdModExp(s, pk->h, y, pk->n);
    bdModExp(c1, pk->g, y, pk->n);
    bdModMult(c2, ptxt, s, pk->n);

    bdFree(&y);
    bdFree(&s);
    bdFree(&ptxt);
}

void elgamal_bd_encrypt_pre(BIGD c1, BIGD c2, int msg, elg_bd_pk *pk) {

    BIGD ptxt = bdNew();
    int_to_bd(ptxt, msg);

    bdSetEqual(c1, pk->c1Pre);
    bdModMult(c2, ptxt, pk->sPre, pk->n);

    bdFree(&ptxt);
}

void elgamal_bd_decrypt(long* msg, BIGD c1, BIGD c2, elg_bd_sk *sk) {
    BIGD s = bdNew();
    BIGD inv_s = bdNew();

    // s = c1^x
    bdModExp(s, c1, sk->x, sk->n);

    // inv_s = s^{-1}
    bdModInv(inv_s, s, sk->n);

    // msg = c2 inv_s
    BIGD ptxt = bdNew();
    bdModMult(ptxt, c2, inv_s, sk->n);

    bd_to_long(msg, ptxt);

    bdFree(&s);
    bdFree(&inv_s);
}
