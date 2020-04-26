#include "pk.h"
#include "gmp-utils.h"
#include "elgamal-gmp.h"


static mpz_t threshold;
static gmp_randstate_t seed;
static mpz_t preS;
static mpz_t preC1;

void elgamal_gmp_init(elg_gmp_pk *pk, elg_gmp_sk *sk) {

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

    // PRECOMPUTATION
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

void elgamal_gmp_encrypt(mpz_t c1, mpz_t c2, int msg, elg_gmp_pk *pk) {
    mpz_t y, s, ptxt;

    mpz_init(ptxt);
    mpz_set_si(ptxt, msg);

    mpz_init(y);
    gmp_rand(y, seed, pk->n, false);


    mpz_init(s);
    mpz_powm(s, pk->h, y, pk->n);

    // c1 = g^y (mod n)
    mpz_powm(c1, pk->g, y, pk->n);

    // c2 = msg * s mod n
    mpz_mul(c2, ptxt, s);
    mpz_mod(c2, c2, pk->n);

    mpz_clear(y);
    mpz_clear(s);
    mpz_clear(ptxt);
}

void elgamal_gmp_encrypt_pre(mpz_t c1, mpz_t c2, int msg, elg_gmp_pk *pk) {
    mpz_t ptxt;
    mpz_init(ptxt);
    mpz_set_si(ptxt, msg);

    mpz_set(c1, preC1);
    mpz_mul(c2, ptxt, preS);
    mpz_mod(c2, c2, pk->n);

    mpz_clear(ptxt);
}

void elgamal_gmp_decrypt(long* msg, mpz_t c1, mpz_t c2, elg_gmp_sk *sk) {
    mpz_t s, inv_s, ptxt;
    mpz_init(s);
    mpz_init(inv_s);
    mpz_init(ptxt);

    mpz_powm(s, c1, sk->x, sk->n);
    mpz_invert(inv_s, s, sk->n);
    mpz_mul(ptxt, c2, inv_s);
    mpz_mod(ptxt, ptxt, sk->n);

    // handle negative numbers
    if (mpz_cmp(ptxt, threshold) > 0)
        mpz_sub(ptxt, ptxt, sk->n);

    *msg = mpz_get_si(ptxt);

    mpz_clear(s);
    mpz_clear(inv_s);
    mpz_clear(ptxt);
}
