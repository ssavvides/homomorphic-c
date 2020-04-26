#include "gmp-utils.h"
#include "paillier-gmp.h"
#include "pk.h"

void paillier_gmp_init(paillier_gmp_pk *pubKey, paillier_gmp_sk *privKey) {

    mpz_init(threshold_gmp);
    mpz_setbit(threshold_gmp, DECRYPTION_THRESHOLD);
    // mpz_ui_pow_ui(threshold_gmp, 2, DECRYPTION_THRESHOLD);

    // initialize seed
    gmp_randinit_default(s);

    // initialize L2 mask
    mpz_init(mask);
    mpz_setbit(mask, DEFAULT_KEY_LEN);
    mpz_sub_ui(mask, mask, 1);

    // generate p and q
    mpz_t p, q, tmp;
    mpz_init(p);
    mpz_init(q);
    mpz_init(tmp);

    do {
        gmp_prime(p, s, DEFAULT_KEY_LEN / 2);
        gmp_prime(q, s, DEFAULT_KEY_LEN / 2);

        // set n
        mpz_init(pubKey->n);
        mpz_mul(pubKey->n, p, q);
        mpz_init(privKey->n);
        mpz_mul(privKey->n, p, q);

        // set ninv
        mpz_setbit(tmp, DEFAULT_KEY_LEN);
        mpz_init(privKey->ninv);
        mpz_invert(privKey->ninv, pubKey->n, tmp);

        //compute p^2 and q^2
        mpz_init(privKey->p2);
        mpz_init(privKey->q2);
        mpz_mul(privKey->p2, p, p);
        mpz_mul(privKey->q2, q, q);

        //generate CRT parameter
        mpz_init(privKey->p2invq2);
        mpz_invert(privKey->p2invq2, privKey->p2, privKey->q2);

        // p-1, q-1
        mpz_sub_ui(p, p, 1);
        mpz_sub_ui(q, q, 1);

        mpz_mul(tmp, p, q);
        mpz_gcd(tmp, tmp, pubKey->n);
    } while (mpz_cmp(p, q) == 0 || mpz_cmp_ui(tmp, 1) != 0);

    // calculate lambda
    mpz_init(privKey->lambda);
    mpz_lcm(privKey->lambda, p, q);

    // calculate n^2
    mpz_init(pubKey->n2);
    mpz_mul(pubKey->n2, pubKey->n, pubKey->n);
    mpz_init(privKey->n2);
    mpz_mul(privKey->n2, pubKey->n, pubKey->n);

    mpz_init(pubKey->g);
    mpz_init(privKey->mu);
    do {
        gmp_rand(pubKey->g, s, pubKey->n2, false);

        mpz_add_ui(pubKey->g, pubKey->n, 1);

        // Ensure n divides the order of g
        mpz_powm(tmp, pubKey->g, privKey->lambda, pubKey->n2);

        gmp_L(tmp, tmp, pubKey->n);

    } while (!mpz_invert(privKey->mu, tmp, pubKey->n));

    // PRECOMPUTATION FOR ENCRYPTION: Select random r where r E Zn*
    mpz_t rand;
    mpz_init(rand);
    gmp_rand(rand, s, pubKey->n2, false);

    mpz_init(tmp1Pre);
    mpz_powm(tmp1Pre, rand, pubKey->n, pubKey->n2);

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(rand);
}

void paillier_gmp_encrypt1(mpz_t ctxt, int msg, const paillier_gmp_pk *pubKey) {

    mpz_t ptxt;
    mpz_init(ptxt);
    mpz_set_si(ptxt, msg);

    mpz_t rnd;
    mpz_init(rnd);
    gmp_rand(rnd, s, pubKey->n2, false);

    //  Compute ciphertext as c = g^m * r^n mod n^2
    mpz_t tmp1;
    mpz_init(tmp1);
    mpz_powm(tmp1, pubKey->g, ptxt, pubKey->n2);

    mpz_t tmp2;
    mpz_init(tmp2);
    mpz_powm(tmp2, rnd, pubKey->n, pubKey->n2);

    // set ciphertext
    mpz_mul(ctxt, tmp1, tmp2);
    mpz_mod(ctxt, ctxt, pubKey->n2);

    mpz_clear(tmp1);
    mpz_clear(tmp2);
    mpz_clear(rnd);
    mpz_clear(ptxt);
}

/**
 * Use g = n+1 to replace 1 exponentiation with a multiplication
 */
void paillier_gmp_encrypt(mpz_t ctxt, int msg, const paillier_gmp_pk *pubKey) {
    mpz_t ptxt;
    mpz_init(ptxt);
    mpz_set_si(ptxt, msg);

    mpz_t rnd;
    mpz_init(rnd);
    gmp_rand(rnd, s, pubKey->n2, false);

    mpz_t tmp1;
    mpz_init(tmp1);
    mpz_powm(tmp1, rnd, pubKey->n, pubKey->n2);

    // OPTIMIZATION g=n+1
    mpz_t tmp2;
    mpz_init(tmp2);
    mpz_mul(tmp2, ptxt, pubKey->n);
    mpz_add_ui(tmp2, tmp2, 1);

    // set ciphertext
    mpz_mul(ctxt, tmp1, tmp2);
    mpz_mod(ctxt, ctxt, pubKey->n2);

    mpz_clear(tmp1);
    mpz_clear(tmp2);
    // mpz_clear(rnd);
    mpz_clear(ptxt);
}

/**
 * No random
 */
void paillier_gmp_encrypt_pre1(mpz_t ctxt, int msg, const paillier_gmp_pk *pubKey) {
    mpz_t ptxt;
    mpz_init(ptxt);
    mpz_set_si(ptxt, msg);

    mpz_t tmp2;
    mpz_init(tmp2);
    mpz_powm(tmp2, pubKey->g, ptxt, pubKey->n2);

    // set ciphertext
    mpz_mul(ctxt, tmp1Pre, tmp2);
    mpz_mod(ctxt, ctxt, pubKey->n2);

    //mpz_clear(tmp2);
    mpz_clear(ptxt);
}

/**
 * Optimizations 2+3: No random and g=n+1
 */
void paillier_gmp_encrypt_pre(mpz_t ctxt, int msg, const paillier_gmp_pk *pubKey) {
    mpz_t ptxt;
    mpz_init(ptxt);
    mpz_set_si(ptxt, msg);

    mpz_t tmp2;
    mpz_init(tmp2);
    mpz_mul(tmp2, ptxt, pubKey->n);
    mpz_add_ui(tmp2, tmp2, 1);

    // set ciphertext
    mpz_mul(ctxt, tmp1Pre, tmp2);
    mpz_mod(ctxt, ctxt, pubKey->n2);

    // mpz_clear(tmp2);
    mpz_clear(ptxt);
}

void paillier_gmp_decrypt1(long* msg, const mpz_t ctxt, const paillier_gmp_sk *key) {
    // Compute the plaintext message as: m = L(c^lamda mod n2)*mu mod n
    mpz_t tmp;
    mpz_init(tmp);
    mpz_powm(tmp, ctxt, key->lambda, key->n2);
    gmp_L(tmp, tmp, key->n);

    mpz_t ptxt;
    mpz_mul(ptxt, tmp, key->mu);
    mpz_mod(ptxt, ptxt, key->n);

    // handle negative numbers
    if (mpz_cmp(ptxt, threshold_gmp) > 0)
        mpz_sub(ptxt, ptxt, key->n);

    *msg = mpz_get_si(ptxt);

    mpz_clear(tmp);
}

/**
 * Using CRT for exponentiation
 */
void paillier_gmp_decrypt_crt1(long* msg, const mpz_t ctxt, const paillier_gmp_sk *key) {
    mpz_t ptxt;
    gmp_crt_exponentiation(ptxt, ctxt, key->lambda, key->lambda, key->p2invq2, key->p2, key->q2);
    gmp_L(ptxt, ptxt, key->n);
    mpz_mul(ptxt, ptxt, key->mu);
    mpz_mod(ptxt, ptxt, key->n);

    // handle negative numbers
    if (mpz_cmp(ptxt, threshold_gmp) > 0)
        mpz_sub(ptxt, ptxt, key->n);

    *msg = mpz_get_si(ptxt);

    mpz_clear(ptxt);
}

/**
 * Using pre-computed n inverted for L function
 */
void paillier_gmp_decrypt(long* msg, const mpz_t ctxt, const paillier_gmp_sk *key) {
    // Compute the plaintext message as: m = L(c^lamda mod n2)*mu mod n
    mpz_t tmp;
    mpz_init(tmp);
    mpz_powm(tmp, ctxt, key->lambda, key->n2);

    // use precomputed n
    gmp_L2(tmp, tmp, key->ninv, mask);

    mpz_t ptxt;
    mpz_mul(ptxt, tmp, key->mu);
    mpz_mod(ptxt, ptxt, key->n);

    // handle negative numbers
    if (mpz_cmp(ptxt, threshold_gmp) > 0)
        mpz_sub(ptxt, ptxt, key->n);

    *msg = mpz_get_si(ptxt);

    mpz_clear(ptxt);
    mpz_clear(tmp);
}

/**
 * Using CRT for exponentiation and precomputed ninv
 */
void paillier_gmp_decrypt_crt(long* msg, const mpz_t ctxt, const paillier_gmp_sk *key) {

    mpz_t ptxt;
    mpz_init(ptxt);
    gmp_crt_exponentiation(ptxt, ctxt, key->lambda,
        key->lambda, key->p2invq2, key->p2, key->q2);

    gmp_L2(ptxt, ptxt, key->ninv, mask);
    mpz_mul(ptxt, ptxt, key->mu);
    mpz_mod(ptxt, ptxt, key->n);

    // handle negative numbers
    if (mpz_cmp(ptxt, threshold_gmp) > 0)
        mpz_sub(ptxt, ptxt, key->n);

    *msg = mpz_get_si(ptxt);

    mpz_clear(ptxt);
}

void add_paillier_gmp(mpz_t result, const mpz_t a, const mpz_t b, const mpz_t n2) {
    mpz_mul(result, a, b);
    mpz_mod(result, result, n2);
}

void sub_paillier_gmp(mpz_t result, const mpz_t a, const mpz_t b, const mpz_t n2) {
    mpz_t b_inv;
    mpz_init(b_inv);
    mpz_invert(b_inv, b, n2);

    mpz_mul(result, a, b_inv);
    mpz_mod(result, result, n2);

    mpz_clear(b_inv);
}

void mul_paillier_gmp(mpz_t result, const mpz_t a, const mpz_t plain, const mpz_t n2) {
    mpz_powm(result, a, plain, n2);
}


