#ifndef ELGAMAL_BN_H
#define ELGAMAL_BN_H

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

typedef struct {
    BIGNUM *n;
    BIGNUM *g;
    BIGNUM *h;
} elg_pk;

typedef struct {
    BIGNUM *n;
    BIGNUM *g;
    BIGNUM *h;
    BIGNUM *x;
} elg_sk;


void elgamal_bn_init(elg_pk *pk, elg_sk *sk, BN_CTX *ctx);

void elgamal_bn_encrypt(BIGNUM *c1, BIGNUM *c2, BIGNUM *msg, elg_pk *pk, BN_CTX *ctx);

void elgamal_bn_encrypt_pre(BIGNUM *c1, BIGNUM *c2, BIGNUM *msg, elg_pk *pk, BN_CTX *ctx);

void elgamal_bn_decrypt(BIGNUM *msg, BIGNUM *c1, BIGNUM *c2, elg_sk *sk, BN_CTX *ctx);

#endif
