#ifndef ELGAMAL_BN_H
#define ELGAMAL_BN_H

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

typedef struct {
	BIGNUM * n;
	BIGNUM * g;
	BIGNUM * h;
} elg_pk;

typedef struct {
	BIGNUM * n;
	BIGNUM * g;
	BIGNUM * h;
	BIGNUM * x;
} elg_sk;


void init_elgamal_bn(elg_pk *pk, elg_sk *sk, BN_CTX *ctx);
void encrypt_elgamal_bn(BIGNUM * c1, BIGNUM * c2, BIGNUM * msg, elg_pk *pk, BN_CTX *ctx);
void encrypt1_elgamal_bn(BIGNUM * c1, BIGNUM * c2, BIGNUM * msg, elg_pk *pk, BN_CTX *ctx);
void encrypt2_elgamal_bn(BIGNUM * c1, BIGNUM * c2, BIGNUM * msg, elg_pk *pk, BN_CTX *ctx);
void decrypt_elgamal_bn(BIGNUM * msg, BIGNUM * c1, BIGNUM * c2, elg_sk *sk, BN_CTX *ctx);

#endif
