#ifndef ELGAMAL_BN_H
#define ELGAMAL_BN_H

#include <stdbool.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

typedef struct {
    BIGNUM *n;
    BIGNUM *g;
    BIGNUM *h;
} elgamal_bn_pk;

typedef struct {
    BIGNUM *n;
    BIGNUM *g;
    BIGNUM *h;
    BIGNUM *x;
} elgamal_bn_sk;

typedef struct {
	int packed_ops;
    BIGNUM *c1;
    BIGNUM *c2;
} elgamal_bn_ctxt;

void elgamal_bn_ctxt_init(elgamal_bn_ctxt* ctxt, BN_CTX *ctx);
void elgamal_bn_init(elgamal_bn_pk *pk, elgamal_bn_sk *sk, BN_CTX *ctx);

void elgamal_bn_encrypt(elgamal_bn_ctxt* ctxt, int msg, elgamal_bn_pk *pk,
    bool precomptation, BN_CTX *ctx);
void elgamal_bn_encrypt_bn(elgamal_bn_ctxt* ctxt, BIGNUM *ptxt,
    elgamal_bn_pk *pk, bool precomptation, BN_CTX *ctx);
void elgamal_bn_encrypt_packed(elgamal_bn_ctxt* ctxt, int* messages, int len,
    elgamal_bn_pk *pk, bool precomptation, BN_CTX *ctx);

void elgamal_bn_decrypt(long* msg, elgamal_bn_ctxt* ctxt, elgamal_bn_sk *sk,
        BN_CTX *ctx);
void elgamal_bn_decrypt_packed(long* messages, elgamal_bn_ctxt* ctxt,
        elgamal_bn_sk *sk, BN_CTX *ctx);
void elgamal_bn_decrypt_bn(BIGNUM* ptxt, elgamal_bn_ctxt* ctxt,
        elgamal_bn_sk *sk, BN_CTX *ctx);

#endif
