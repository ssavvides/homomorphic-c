#include "elgamal-gmp.h"
#include "gmp-utils.h"
#include "pk.h"

static mpz_t threshold;
static gmp_randstate_t seed;
static mpz_t preS;
static mpz_t preC1;

void init_elgamal_gmp(elg_gmp_pk *pk, elg_gmp_sk *sk) {

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

	// n is a large prime
	gen_prime(sk->n, seed, DEFAULT_KEY_LEN);

	// Get some random x < n
	do {
		mpz_urandomm(sk->x, seed, sk->n);
	} while (mpz_cmp_si(sk->x, 0) == 0);

	// g is the generator
	gen_prime(sk->g, seed, DEFAULT_KEY_LEN);

	/* h = g^x (mod n) */
	mpz_powm(sk->h, sk->g, sk->x, sk->n);

	mpz_set(pk->n, sk->n);
	mpz_set(pk->g, sk->g);
	mpz_set(pk->h, sk->h);

	// PRECOMPUTATION
	mpz_t y;
	mpz_init(y);
	do {
		mpz_urandomm(y, seed, pk->n);
	} while (mpz_cmp_si(y, 0) == 0);

	// s = h^y (mod n)
	mpz_init(preS);
	mpz_powm(preS, pk->h, y, pk->n);

	// c1 = g^y (mod n)
	mpz_init(preC1);
	mpz_powm(preC1, pk->g, y, pk->n);
}

void encrypt_elgamal_gmp(mpz_t c1, mpz_t c2, mpz_t msg, elg_gmp_pk *pk) {
	encrypt1_elgamal_gmp(c1, c2, msg, pk);
}

void encrypt1_elgamal_gmp(mpz_t c1, mpz_t c2, mpz_t msg, elg_gmp_pk *pk) {
	mpz_t y, s;
	mpz_init(y);
	mpz_init(c1);
	mpz_init(c2);
	mpz_init(s);

	do {
		mpz_urandomm(y, seed, pk->n);
	} while (mpz_cmp_si(y, 0) == 0);

	// s = h^y (mod n)
	mpz_powm(s, pk->h, y, pk->n);

	// c1 = g^y (mod n)
	mpz_powm(c1, pk->g, y, pk->n);

	// c2 = msg * s mod n
	mpz_mul(c2, msg, s);
	mpz_mod(c2, c2, pk->n);
}

/*
 * Pre-computation
 */
void encrypt2_elgamal_gmp(mpz_t c1, mpz_t c2, mpz_t msg, elg_gmp_pk *pk) {
	mpz_init(c1);
	mpz_init(c2);

	mpz_set(c1, preC1);

	// c2 = msg * s mod n
	mpz_mul(c2, msg, preS);
	mpz_mod(c2, c2, pk->n);
}

void decrypt_elgamal_gmp(mpz_t msg, mpz_t c1, mpz_t c2, elg_gmp_sk *sk) {
	mpz_t s, inv_s;
	mpz_init(s);
	mpz_init(inv_s);

	// s = c1^x
	mpz_powm(s, c1, sk->x, sk->n);

	// inv_s = s^{-1}
	mpz_invert(inv_s, s, sk->n);

	// msg = c2 inv_s
	mpz_mul(msg, c2, inv_s);

	// Take msg modulo n
	mpz_mod(msg, msg, sk->n);

	// handle negative numbers
	if (mpz_cmp(msg, threshold) > 0)
		mpz_sub(msg, msg, sk->n);
}





