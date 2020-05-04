#include "pk.h"
#include "gmp-ops.h"
#include "elgamal-gmp.h"

static mpz_t threshold;
static gmp_randstate_t seed;
static mpz_t preS;
static mpz_t preC1;

void elgamal_gmp_ctxt_init(elgamal_gmp_ctxt *ctxt) {
    ctxt->packed_ops = 0;
    mpz_init(ctxt->c1);
    mpz_init(ctxt->c2);
}

void elgamal_gmp_init(elgamal_gmp_pk *pk, elgamal_gmp_sk *sk) {

    mpz_init(threshold);
    mpz_setbit(threshold, DECRYPTION_THRESHOLD);

    // initialize seed
    gmp_randinit_default(seed);

    mpz_init(sk->n);
    mpz_init(sk->g);
    mpz_init(sk->h);
    mpz_init(sk->x);

    mpz_init(pk->n);
    mpz_init(pk->g);
    mpz_init(pk->h);

    gmp_prime(sk->n, seed, DEFAULT_KEY_LEN);
    gmp_rand(sk->x, seed, sk->n, false);
    gmp_prime(sk->g, seed, DEFAULT_KEY_LEN);

    /* h = g^x (mod n) */
    mpz_powm(sk->h, sk->g, sk->x, sk->n);

    mpz_set(pk->n, sk->n);
    mpz_set(pk->g, sk->g);
    mpz_set(pk->h, sk->h);

    // pre-computation
    mpz_t y;
    mpz_init(y);
    gmp_rand(y, seed, pk->n, false);

    // s = h^y (mod n)
    mpz_init(preS);
    mpz_powm(preS, pk->h, y, pk->n);

    // c1 = g^y (mod n)
    mpz_init(preC1);
    mpz_powm(preC1, pk->g, y, pk->n);

    mpz_clear(y);
}

void elgamal_gmp_encrypt(elgamal_gmp_ctxt *ctxt, int msg, elgamal_gmp_pk *pk,
        bool precomptation) {
    mpz_t ptxt;
    mpz_init(ptxt);
    mpz_set_si(ptxt, msg);
    elgamal_gmp_encrypt_mpz(ctxt, ptxt, pk, precomptation);
    mpz_clear(ptxt);
}
void elgamal_gmp_encrypt_packed(elgamal_gmp_ctxt *ctxt, int* messages, int len,
        elgamal_gmp_pk *pk, bool precomptation) {
    mpz_t ptxt;
    mpz_init(ptxt);
    gmp_pack(ptxt, DEFAULT_KEY_LEN, messages, len, false);
    elgamal_gmp_encrypt_mpz(ctxt, ptxt, pk, precomptation);
    mpz_clear(ptxt);
}
void elgamal_gmp_encrypt_mpz(elgamal_gmp_ctxt *ctxt, mpz_t ptxt,
        elgamal_gmp_pk *pk, bool precomptation) {
    if (precomptation) {
        mpz_set(ctxt->c1, preC1);
        mpz_mul(ctxt->c2, ptxt, preS);
        mpz_mod(ctxt->c2, ctxt->c2, pk->n);
    } else {
        mpz_t rnd, s;
        mpz_init(rnd);
        gmp_rand(rnd, seed, pk->n, false);
        mpz_powm(ctxt->c1, pk->g, rnd, pk->n);
        mpz_init(s);
        mpz_powm(s, pk->h, rnd, pk->n);
        mpz_mul(ctxt->c2, ptxt, s);
        mpz_mod(ctxt->c2, ctxt->c2, pk->n);
        mpz_clear(rnd);
        mpz_clear(s);
    }
}

void elgamal_gmp_decrypt(long* msg, elgamal_gmp_ctxt *ctxt, elgamal_gmp_sk *sk) {
    mpz_t ptxt;
    mpz_init(ptxt);
    elgamal_gmp_decrypt_mpz(ptxt, ctxt, sk);

    // handle negative numbers
    if (mpz_cmp(ptxt, threshold) > 0)
        mpz_sub(ptxt, ptxt, sk->n);

    *msg = mpz_get_si(ptxt);
    mpz_clear(ptxt);
}
void elgamal_gmp_decrypt_packed(long* messages, elgamal_gmp_ctxt *ctxt, elgamal_gmp_sk *sk) {
    mpz_t packed_messages;
    mpz_init(packed_messages);
    elgamal_gmp_decrypt_mpz(packed_messages, ctxt, sk);
    gmp_unpack(messages, DEFAULT_KEY_LEN, packed_messages, false, ctxt->packed_ops);
    mpz_clear(packed_messages);
}
void elgamal_gmp_decrypt_mpz(mpz_t ptxt, elgamal_gmp_ctxt *ctxt, elgamal_gmp_sk *sk) {
    mpz_t s, inv_s;
    mpz_init(s);
    mpz_init(inv_s);
    mpz_powm(s, ctxt->c1, sk->x, sk->n);
    mpz_invert(inv_s, s, sk->n);
    mpz_mul(ptxt, ctxt->c2, inv_s);
    mpz_mod(ptxt, ptxt, sk->n);
    mpz_clear(s);
    mpz_clear(inv_s);
}
