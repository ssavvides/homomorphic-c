#ifndef PK_H
#define PK_H

#define DEFAULT_KEY_LEN 1024
#define DECRYPTION_THRESHOLD DEFAULT_KEY_LEN / 2

#include <stdbool.h>

#include "elgamal-bd.h"
#include "elgamal-bn.h"
#include "elgamal-gmp.h"

#include "paillier-bd.h"
#include "paillier-bn.h"
#include "paillier-gmp.h"

typedef enum {elgamal_scheme, paillier_scheme} scheme_t;
static inline char *scheme_string(scheme_t s) {
    static char *strings[] = {"ElGamal", "Paillier"};
    return strings[s];
}

typedef enum {bigdigits_lib, ssl_lib, gmp_lib} library_t;
static inline char *library_string(library_t l) {
    static char *strings[] = {"BigDigits", "SSL", "GMP"};
    return strings[l];
}

static paillier_bd_pk pail_bd_pk;
static paillier_bd_sk pail_bd_sk;
static BIGD pail_bd_ctxt;

static paillier_bn_pk pail_bn_pk;
static paillier_bn_sk pail_bn_sk;
static BIGNUM* pail_bn_ctxt;

static paillier_gmp_pk pail_gmp_pk;
static paillier_gmp_sk pail_gmp_sk;
static mpz_t pail_gmp_ctxt;

static elgamal_bd_pk elg_bd_pk;
static elgamal_bd_sk elg_bd_sk;
static elgamal_bd_ctxt elg_bd_ctxt;

static elgamal_bn_pk elg_bn_pk;
static elgamal_bn_sk elg_bn_sk;
static elgamal_bn_ctxt elg_bn_ctxt;

static elgamal_gmp_pk elg_gmp_pk;
static elgamal_gmp_sk elg_gmp_sk;
static elgamal_gmp_ctxt elg_gmp_ctxt;

bool is_ahe(scheme_t scheme);
void init_schemes(BN_CTX *ctx);

void encrypt(scheme_t scheme, library_t library, int ptxt,
	bool precomputation, BN_CTX *ctx);
void encrypt_packed(scheme_t scheme, library_t library, int* ptxts, int items,
	bool precomputation, BN_CTX *ctx);

void decrypt(scheme_t scheme, library_t library, long* decr, BN_CTX *ctx);
void decrypt_packed(scheme_t scheme, library_t library, long* decrs, BN_CTX *ctx);


#endif
