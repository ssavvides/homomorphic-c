#ifndef ELGAMAL_GMP_H
#define ELGAMAL_GMP_H

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>

typedef struct {
    mpz_t n;
    mpz_t g;
    mpz_t h;
} elg_gmp_pk;

typedef struct {
    mpz_t n;
    mpz_t g;
    mpz_t h;
    mpz_t x;
} elg_gmp_sk;

void elgamal_gmp_init(elg_gmp_pk *pk, elg_gmp_sk *sk);

void elgamal_gmp_encrypt(mpz_t c1, mpz_t c2, mpz_t msg, elg_gmp_pk *pk);

void elgamal_gmp_encrypt_pre(mpz_t c1, mpz_t c2, mpz_t msg, elg_gmp_pk *pk);

void elgamal_gmp_decrypt(mpz_t msg, mpz_t c1, mpz_t c2, elg_gmp_sk *sk);

#endif
