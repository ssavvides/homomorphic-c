#ifndef PAILLIER_BN_H
#define PAILLIER_BN_H

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdbool.h>

typedef struct {
    BIGNUM *n, *n2;
    BIGNUM *g;
} paillier_bn_pk;

typedef struct {
    BIGNUM *n, *n2;
    BIGNUM *lamda, *mu;
    // optimizations
    BIGNUM *p2invq2, *p2, *q2;
} paillier_bn_sk;

static BIGNUM *threshold_bn;
static BIGNUM *tmp2Pre;

void crt_exponentiation_bn(BIGNUM *result, const BIGNUM *base,
	const BIGNUM *exp_p, const BIGNUM *exp_q, const BIGNUM *pinvq,
	const BIGNUM *p, const BIGNUM *q, BN_CTX *ctx);

void paillier_bn_init(paillier_bn_pk *pubKey, paillier_bn_sk *privKey, BN_CTX *ctx);

void paillier_bn_encrypt1(BIGNUM *ctxt, int ptxt, const paillier_bn_pk *pubKey, BN_CTX *ctx);

void paillier_bn_encrypt(BIGNUM *ctxt, int ptxt, const paillier_bn_pk *pubKey,
	bool precomputation, BN_CTX *ctx);
void paillier_bn_encrypt_bn(BIGNUM *ctxt, const BIGNUM *ptxt,
	const paillier_bn_pk *pubKey, bool precomputation, BN_CTX *ctx);
void paillier_bn_encrypt_packed(BIGNUM *ctxt, int* messages, int len,
	const paillier_bn_pk *pubKey, bool precomputation, BN_CTX *ctx);

void paillier_bn_encrypt_pre1(BIGNUM *ctxt, int ptxt, const paillier_bn_pk *pubKey, BN_CTX *ctx);

void paillier_bn_decrypt(long* msg, const BIGNUM *ctxt, const paillier_bn_sk *key, BN_CTX *ctx);
void paillier_bn_decrypt_bn(BIGNUM* ptxt, const BIGNUM *ctxt, const paillier_bn_sk *key, BN_CTX *ctx);
void paillier_bn_decrypt_packed(long* messages, const BIGNUM *ctxt, const paillier_bn_sk *key, BN_CTX *ctx);

void paillier_bn_decrypt_crt(long *ptxt, const BIGNUM *ctxt, const paillier_bn_sk *key, BN_CTX *ctx);

void add_paillier_bn(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx);

void sub_paillier_bn(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx);

void mul_paillier_bn(BIGNUM *result, const BIGNUM *a, const BIGNUM *plain, const BIGNUM *n2, BN_CTX *ctx);

#endif
