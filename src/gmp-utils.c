#include "gmp-utils.h"

void gen_prime(mpz_t prime, gmp_randstate_t seed, mp_bitcnt_t len) {
	mpz_t rnd;
	mpz_init(rnd);

	mpz_urandomb(rnd, seed, len);

	//set most significant bit to 1
	mpz_setbit(rnd, len - 1);
	//look for next prime
	mpz_nextprime(prime, rnd);

	mpz_clear(rnd);
}

int crt_exponentiation(mpz_t result, const mpz_t base, const mpz_t exp_p, const mpz_t exp_q,
		const mpz_t pinvq, const mpz_t p, const mpz_t q) {
	//compute exponentiation modulo p
	mpz_t result_p;
	mpz_init(result_p);
	mpz_mod(result_p, base, p);
	mpz_powm(result_p, result_p, exp_p, p);

	//compute exponentiation modulo q
	mpz_t result_q;
	mpz_init(result_q);
	mpz_mod(result_q, base, q);
	mpz_powm(result_q, result_q, exp_q, q);

	//recombination
	mpz_sub(result, result_q, result_p);
	mpz_mul(result, result, p);
	mpz_mul(result, result, pinvq);
	mpz_add(result, result, result_p);

	mpz_t pq;
	mpz_init(pq);
	mpz_mul(pq, p, q);
	mpz_mod(result, result, pq);

	return 0;
}

void L(mpz_t res, const mpz_t u, const mpz_t n) {
	mpz_sub_ui(res, u, 1);
	mpz_div(res, res, n);
}

void L2(mpz_t result, const mpz_t input, const mpz_t ninv, mpz_t mask) {
	mpz_sub_ui(result, input, 1);
	mpz_mul(result, result, ninv);
	mpz_and(result, result, mask);
}
