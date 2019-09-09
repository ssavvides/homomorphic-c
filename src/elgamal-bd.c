#include "elgamal-bd.h"
#include "pk.h"

void init_elgamal_bd(elg_bd_pk *pk, elg_bd_sk *sk) {
	sk->n = bdNew();
	sk->g = bdNew();
	sk->h = bdNew();
	sk->x = bdNew();

	pk->n = bdNew();
	pk->g = bdNew();
	pk->h = bdNew();

	// n is a large prime
    bdGeneratePrime(sk->n, DEFAULT_KEY_LEN, 1, (const unsigned char*) "1", 1, bdRandomOctets);

	do {
		bdQuickRandBits(sk->x, DEFAULT_KEY_LEN);
	} while (bdIsZero(sk->x));

	// g is the generator
    bdGeneratePrime(sk->g, DEFAULT_KEY_LEN, 1, (const unsigned char*) "1", 1, bdRandomOctets);

	// h = g^x (mod n)
	bdModExp(sk->h, sk->g, sk->x, sk->n);

	bdSetEqual(pk->n, sk->n);
	bdSetEqual(pk->g, sk->g);
	bdSetEqual(pk->h, sk->h);

	// PRECOMPUTATION
	BIGD y = bdNew();

	do {
		bdQuickRandBits(y, DEFAULT_KEY_LEN);
	} while (bdIsZero(y));

	pk->sPre = bdNew();
	pk->c1Pre = bdNew();
	bdModExp(pk->sPre, pk->h, y, pk->n);
	bdModExp(pk->c1Pre, pk->g, y, pk->n);
}

void encrypt_elgamal_bd(BIGD c1, BIGD c2, BIGD msg, elg_bd_pk *pk) {

	BIGD y = bdNew();
	BIGD s = bdNew();

	do {
		bdQuickRandBits(y, DEFAULT_KEY_LEN);
	} while (bdIsZero(y));

	// s = h^y (mod n)
	bdModExp(s, pk->h, y, pk->n);

	// c1 = g^y (mod n)
	bdModExp(c1, pk->g, y, pk->n);

	// c2 = msg * s mod n
	bdModMult(c2, msg, s, pk->n);
}

/**
 * Pre-computation
 */
void encrypt_pre_elgamal_bd(BIGD  c1, BIGD  c2, BIGD  msg, elg_bd_pk *pk) {

	bdSetEqual(c1, pk->c1Pre);

	// c2 = msg * s mod n
	bdModMult(c2, msg, pk->sPre, pk->n);
}

void decrypt_elgamal_bd(BIGD  msg, BIGD  c1, BIGD  c2, elg_bd_sk *sk) {
	BIGD s = bdNew();
	BIGD inv_s = bdNew();

	// s = c1^x
	bdModExp(s, c1, sk->x, sk->n);

	// inv_s = s^{-1}
	bdModInv(inv_s, s, sk->n);

	// msg = c2 inv_s
	bdModMult(msg, c2, inv_s, sk->n);
}
