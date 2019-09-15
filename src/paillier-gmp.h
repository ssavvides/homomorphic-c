#ifndef PAILLIER_GMP_H
#define PAILLIER_GMP_H

typedef struct {
    mpz_t n, n2;
    mpz_t lambda;
    mpz_t mu;
    // optimizations
    mpz_t ninv;
    mpz_t p2invq2;
    mpz_t p2;
    mpz_t q2;
} paillier_gmp_sk;

typedef struct {
    mpz_t n, n2;
    mpz_t g;
} paillier_gmp_pk;

static mpz_t threshold_gmp;
mpz_t tmp1Pre;
gmp_randstate_t s;
mpz_t mask;

void paillier_gmp_init(paillier_gmp_pk *pubKey, paillier_gmp_sk *privKey);

void paillier_gmp_encrypt(mpz_t ctxt, const mpz_t ptxt, const paillier_gmp_pk *pubKey);

void paillier_gmp_encrypt1(mpz_t ctxt, const mpz_t ptxt, const paillier_gmp_pk *pubKey);

void paillier_gmp_encrypt_pre(mpz_t ctxt, const mpz_t ptxt, const paillier_gmp_pk *pubKey);

void paillier_gmp_encrypt_pre1(mpz_t ctxt, const mpz_t ptxt, const paillier_gmp_pk *pubKey);

void paillier_gmp_decrypt(mpz_t ptxt, const mpz_t ctxt, const paillier_gmp_sk *key);

void paillier_gmp_decrypt1(mpz_t ptxt, const mpz_t ctxt, const paillier_gmp_sk *key);

void paillier_gmp_decrypt_crt(mpz_t ptxt, const mpz_t ctxt, const paillier_gmp_sk *key);

void paillier_gmp_decrypt_crt1(mpz_t ptxt, const mpz_t ctxt, const paillier_gmp_sk *key);

void add_paillier_gmp(mpz_t result, const mpz_t a, const mpz_t b, const mpz_t n2);

void sub_paillier_gmp(mpz_t result, const mpz_t a, const mpz_t b, const mpz_t n2);

void mul_paillier_gmp(mpz_t result, const mpz_t a, const mpz_t plain, const mpz_t n2);

#endif
