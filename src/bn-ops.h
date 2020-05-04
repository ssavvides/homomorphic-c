#ifndef _BN_OP_H_
#define _BN_OP_H_

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>


// LCM for BIGNUMs
void bn_lcm(BIGNUM *lambda, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
void bn_L(BIGNUM *res, const BIGNUM *u, const BIGNUM *n, BN_CTX *ctx);
void bn_mod_exp_neg(
	BIGNUM *res, const BIGNUM *base, const BIGNUM *exp, const BIGNUM *m,
    BN_CTX *ctx);
void bn_crt_exponentiation(
    BIGNUM *result, const BIGNUM *base, const BIGNUM *exp_p,
    const BIGNUM *exp_q, const BIGNUM *pinvq, const BIGNUM *p, const BIGNUM *q,
    BN_CTX *ctx);

void bn_prime(BIGNUM* prime, int len);
void bn_rand(BIGNUM* rnd, int bits, bool can_be_zero);

void int_to_bn(BIGNUM* res, int number);
void bn_to_long(long* res, BIGNUM * number);

void bn_pack(BIGNUM* packed_messages, int ctxt_bits, int* messages, int len,
	bool ahe, BN_CTX *ctx);
void bn_unpack(long* messages, int ctxt_bits, BIGNUM* packed_messages, bool ahe,
	int mhe_ops, BN_CTX *ctx);

#endif
