#ifndef ELGAMAL_GMP_H
#define ELGAMAL_GMP_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>

typedef struct {
    mpz_t n;
    mpz_t g;
    mpz_t h;
} elgamal_gmp_pk;

typedef struct {
    mpz_t n;
    mpz_t g;
    mpz_t h;
    mpz_t x;
} elgamal_gmp_sk;

typedef struct {
	int packed_ops;
    mpz_t c1;
    mpz_t c2;
} elgamal_gmp_ctxt;

void elgamal_gmp_ctxt_init(elgamal_gmp_ctxt *ctxt);
void elgamal_gmp_init(elgamal_gmp_pk *pk, elgamal_gmp_sk *sk);

void elgamal_gmp_encrypt(elgamal_gmp_ctxt *ctxt, int msg, elgamal_gmp_pk *pk,
    bool precomptation);
void elgamal_gmp_encrypt_mpz(elgamal_gmp_ctxt *ctxt, mpz_t ptxt,
    elgamal_gmp_pk *pk, bool precomptation);
void elgamal_gmp_encrypt_packed(elgamal_gmp_ctxt *ctxt, int* messages, int len,
    elgamal_gmp_pk *pk, bool precomptation);

void elgamal_gmp_decrypt(long* msg, elgamal_gmp_ctxt *ctxt, elgamal_gmp_sk *sk);
void elgamal_gmp_decrypt_packed(long* messages, elgamal_gmp_ctxt *ctxt, elgamal_gmp_sk *sk);
void elgamal_gmp_decrypt_mpz(mpz_t ptxt, elgamal_gmp_ctxt *ctxt, elgamal_gmp_sk *sk);

#endif
