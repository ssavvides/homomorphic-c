#ifndef GMP_UTILS_H
#define GMP_UTILS_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include <gmp.h>

void gmp_prime(mpz_t prime, gmp_randstate_t seed, mp_bitcnt_t len);
void gmp_rand(mpz_t rnd, gmp_randstate_t seed, const mpz_t range, bool can_be_zero);

int gmp_crt_exponentiation(mpz_t result, const mpz_t base, const mpz_t exp_p,
                       const mpz_t exp_q, const mpz_t pinvq, const mpz_t p, const mpz_t q);
void gmp_L(mpz_t res, const mpz_t u, const mpz_t n);
void gmp_L2(mpz_t result, const mpz_t input, const mpz_t ninv, mpz_t mask);

#endif
