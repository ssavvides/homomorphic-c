#include "pk.h"
#include "bd-ops.h"
#include "elgamal-bd.h"

void elgamal_bd_ctxt_init(elgamal_bd_ctxt *ctxt) {
    ctxt->packed_ops = 0;
    ctxt->c1 = bdNew();
    ctxt->c2 = bdNew();
}

void elgamal_bd_init(elgamal_bd_pk *pk, elgamal_bd_sk *sk) {
    sk->n = bdNew();
    sk->g = bdNew();
    sk->h = bdNew();
    sk->x = bdNew();
    pk->n = bdNew();
    pk->g = bdNew();
    pk->h = bdNew();

    bd_prime(sk->n, DEFAULT_KEY_LEN / 2);
    bd_rand(sk->x, DEFAULT_KEY_LEN, false);
    bd_prime(sk->g, DEFAULT_KEY_LEN / 2);

    // h = g^x (mod n)
    bdModExp(sk->h, sk->g, sk->x, sk->n);

    bdSetEqual(pk->n, sk->n);
    bdSetEqual(pk->g, sk->g);
    bdSetEqual(pk->h, sk->h);

    // pre-computation
    BIGD y = bdNew();
    bd_rand(y, DEFAULT_KEY_LEN, false);

    pk->sPre = bdNew();
    pk->c1Pre = bdNew();
    bdModExp(pk->sPre, pk->h, y, pk->n);
    bdModExp(pk->c1Pre, pk->g, y, pk->n);

    bdFree(&y);
}

void elgamal_bd_encrypt(elgamal_bd_ctxt *ctxt, int msg, elgamal_bd_pk *pk,
        bool precomptation) {
    BIGD ptxt = bdNew();
    int_to_bd(ptxt, msg);
    elgamal_bd_encrypt_bd(ctxt, ptxt, pk, precomptation);
    bdFree(&ptxt);
}
void elgamal_bd_encrypt_packed(elgamal_bd_ctxt *ctxt, int* messages, int len,
        elgamal_bd_pk *pk, bool precomptation) {
    BIGD ptxt = bdNew();
    bd_pack(ptxt, DEFAULT_KEY_LEN, messages, len, false);
    elgamal_bd_encrypt_bd(ctxt, ptxt, pk, precomptation);
    bdFree(&ptxt);
}
void elgamal_bd_encrypt_bd(elgamal_bd_ctxt *ctxt, BIGD ptxt, elgamal_bd_pk *pk,
        bool precomptation) {
    if (precomptation) {
        bdSetEqual(ctxt->c1, pk->c1Pre);
        bdModMult(ctxt->c2, ptxt, pk->sPre, pk->n);
    } else {
        BIGD rnd = bdNew();
        bd_rand(rnd, DEFAULT_KEY_LEN, false);
        bdModExp(ctxt->c1, pk->g, rnd, pk->n);
        BIGD s = bdNew();
        bdModExp(s, pk->h, rnd, pk->n);
        bdModMult(ctxt->c2, ptxt, s, pk->n);
        bdFree(&rnd);
        bdFree(&s);
    }
}

void elgamal_bd_decrypt(long* msg, elgamal_bd_ctxt *ctxt, elgamal_bd_sk *sk) {
    BIGD ptxt = bdNew();
    elgamal_bd_decrypt_bd(ptxt, ctxt, sk);
    bd_to_long(msg, ptxt);
    bdFree(&ptxt);
}
void elgamal_bd_decrypt_packed(long* messages, elgamal_bd_ctxt *ctxt, elgamal_bd_sk *sk) {
    BIGD ptxt = bdNew();
    elgamal_bd_decrypt_bd(ptxt, ctxt, sk);
    bd_unpack(messages, DEFAULT_KEY_LEN, ptxt, false, ctxt->packed_ops);
    bdFree(&ptxt);
}
void elgamal_bd_decrypt_bd(BIGD ptxt, elgamal_bd_ctxt *ctxt, elgamal_bd_sk *sk) {
    BIGD s = bdNew();
    BIGD inv_s = bdNew();
    bdModExp(s, ctxt->c1, sk->x, sk->n);
    bdModInv(inv_s, s, sk->n);
    bdModMult(ptxt, ctxt->c2, inv_s, sk->n);
    bdFree(&s);
    bdFree(&inv_s);
}
