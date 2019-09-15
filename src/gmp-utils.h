#ifndef GMP_UTILS_H
#define GMP_UTILS_H

#include <stdlib.h>
#include <gmp.h>

void gen_prime(mpz_t prime, gmp_randstate_t seed, mp_bitcnt_t len);

int crt_exponentiation(mpz_t result, const mpz_t base, const mpz_t exp_p,
                       const mpz_t exp_q, const mpz_t pinvq, const mpz_t p, const mpz_t q);

void L(mpz_t res, const mpz_t u, const mpz_t n);

void L2(mpz_t result, const mpz_t input, const mpz_t ninv, mpz_t mask);

#endif
