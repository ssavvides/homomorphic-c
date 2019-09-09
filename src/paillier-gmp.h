#ifndef PAILLIER_GMP_H
#define PAILLIER_GMP_H

typedef struct {
	mpz_t n, n2;
	mpz_t lambda;
	mpz_t mu;
	// optimizations
	mpz_t ninv;
	mpz_t p2invq2;
	mpz_t p2;
	mpz_t q2;
} paillier_gmp_sk;

typedef struct {
	mpz_t n, n2;
	mpz_t g;
} paillier_gmp_pk;

static mpz_t threshold_gmp;
mpz_t tmp1Pre;
gmp_randstate_t s;
mpz_t mask;

void init_paillier_gmp(paillier_gmp_pk *pubKey, paillier_gmp_sk *privKey);
void encrypt_paillier_gmp(mpz_t ctxt, const mpz_t ptxt, const paillier_gmp_pk *pubKey);
void decrypt_paillier_gmp(mpz_t ptxt, const mpz_t ctxt, const paillier_gmp_sk *key);
void encrypt1_paillier_gmp(mpz_t ctxt, const mpz_t ptxt, const paillier_gmp_pk *pubKey);
void encrypt2_paillier_gmp(mpz_t ctxt, const mpz_t ptxt, const paillier_gmp_pk *pubKey);
void encrypt3_paillier_gmp(mpz_t ctxt, const mpz_t ptxt, const paillier_gmp_pk *pubKey);
void encrypt4_paillier_gmp(mpz_t ctxt, const mpz_t ptxt, const paillier_gmp_pk *pubKey);
void decrypt1_paillier_gmp(mpz_t ptxt, const mpz_t ctxt, const paillier_gmp_sk *key);
void decrypt2_paillier_gmp(mpz_t ptxt, const mpz_t ctxt, const paillier_gmp_sk *key);
void decrypt3_paillier_gmp(mpz_t ptxt, const mpz_t ctxt, const paillier_gmp_sk *key);
void decrypt4_paillier_gmp(mpz_t ptxt, const mpz_t ctxt, const paillier_gmp_sk *key);
void add_paillier_gmp(mpz_t result, const mpz_t a, const mpz_t b, const mpz_t n2);
void sub_paillier_gmp(mpz_t result, const mpz_t a, const mpz_t b, const mpz_t n2);
void mul_paillier_gmp(mpz_t result, const mpz_t a, const mpz_t plain, const mpz_t n2);

#endif
