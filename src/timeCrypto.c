#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "time.h"
#include "aes.h"
#include "aes-ssl.h"
#include "elgamal-bd.h"
#include "elgamal-bn.h"
#include "elgamal-gmp.h"
#include "paillier-bd.h"
#include "paillier-bn.h"
#include "paillier-gmp.h"

void time_aes() {
    uint8_t key[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t iv[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t ptxt[] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    uint8_t ptxt_copy[64];
    memcpy(ptxt_copy, ptxt, sizeof(ptxt));
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    int N = 1000;
    int W = 100;
    unsigned long start = 0;
    unsigned long elapsed = 0;
    unsigned long time_enc[N];
    unsigned long time_dec[N];

    for (int i = 0; i < N + W; i++) {
        AES_ctx_set_iv(&ctx, iv);
        start = time_micros();
        AES_CBC_encrypt_buffer(&ctx, ptxt, 32);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;
        AES_ctx_set_iv(&ctx, iv);
        start = time_micros();
        AES_CBC_decrypt_buffer(&ctx, ptxt, 32);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }
    printf("AES\n");
    printf("------------\n");
    printf("Encrypt\n");
    print_stats(time_enc, N);
    printf("Decrypt\n");
    print_stats(time_dec, N);
}

void time_aes_ssl() {
    char *key = "test";
    unsigned char text[32] = "12345678901234567890123456789012";
    unsigned char enc_out[32];
    unsigned char dec_out[32];
    aes_ssl_init(key);

    int N = 1000;
    int W = 100;
    unsigned long start = 0;
    unsigned long elapsed = 0;
    unsigned long time_enc[N];
    unsigned long time_dec[N];
    for (int i = 0; i < N + W; i++) {
        start = time_micros();
        aes_ssl_encrypt(text, enc_out);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;
        start = time_micros();
        aes_ssl_decrypt(enc_out, dec_out);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }
    printf("AES-SSL\n");
    printf("------------\n");
    printf("Encrypt\n");
    print_stats(time_enc, N);
    printf("Decrypt\n");
    print_stats(time_dec, N);
}

void time_elgamal_bd() {
    elg_bd_pk pubKey;
    elg_bd_sk privKey;
    elgamal_bd_init(&pubKey, &privKey);

    int N = 20;
    int W = 2;
    unsigned long start = 0;
    unsigned long elapsed = 0;
    unsigned long time_enc[N];
    unsigned long time_enc2[N];
    unsigned long time_dec[N];

    BIGD ptxt = bdNew();
    BIGD c1 = bdNew();
    BIGD c2 = bdNew();
    BIGD decr = bdNew();
    char str[10];
    for (int i = 0; i < N + W; i++) {
        int r = rand() % 1000 - 500;
        sprintf(str, "%d", r);
        bdConvFromDecimal(ptxt, str);

        start = time_micros();
        elgamal_bd_encrypt(c1, c2, ptxt, &pubKey);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;

        start = time_micros();
        elgamal_bd_encrypt_pre(c1, c2, ptxt, &pubKey);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc2[i - W] = elapsed;

        start = time_micros();
        elgamal_bd_decrypt(decr, c1, c2, &privKey);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }

    printf("ELGAMAL-BD\n");
    printf("------------\n");
    printf("Encrypt\n");
    print_stats(time_enc, N);
    printf("Encrypt Pre-computation\n");
    print_stats(time_enc2, N);
    printf("Decrypt\n");
    print_stats(time_dec, N);
}

void time_elgamal_bn() {
    char str[10];
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *ptxt = BN_CTX_get(ctx);
    BIGNUM *c1 = BN_CTX_get(ctx);
    BIGNUM *c2 = BN_CTX_get(ctx);
    BIGNUM *decr = BN_CTX_get(ctx);
    elg_pk pubKey;
    elg_sk privKey;
    elgamal_bn_init(&pubKey, &privKey, ctx);

    int N = 1000;
    int W = 100;
    unsigned long start = 0;
    unsigned long elapsed = 0;
    unsigned long time_enc[N];
    unsigned long time_enc2[N];
    unsigned long time_dec[N];

    for (int i = 0; i < N + W; i++) {
        int r = rand() % 1000 - 500;
        sprintf(str, "%d", r);
        BN_dec2bn(&ptxt, str);

        start = time_micros();
        elgamal_bn_encrypt(c1, c2, ptxt, &pubKey, ctx);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;

        start = time_micros();
        elgamal_bn_encrypt_pre(c1, c2, ptxt, &pubKey, ctx);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc2[i - W] = elapsed;

        start = time_micros();
        elgamal_bn_decrypt(decr, c1, c2, &privKey, ctx);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }
    printf("ELGAMAL-BN\n");
    printf("------------\n");
    printf("Encrypt\n");
    print_stats(time_enc, N);
    printf("Encrypt Pre-computation\n");
    print_stats(time_enc2, N);
    printf("Decrypt\n");
    print_stats(time_dec, N);
}

void time_elgamal_gmp() {
    elg_gmp_pk pk;
    elg_gmp_sk sk;
    elgamal_gmp_init(&pk, &sk);
    char str[10];
    mpz_t ptxt;
    mpz_init(ptxt);
    mpz_t c1;
    mpz_init(c1);
    mpz_t c2;
    mpz_init(c2);
    mpz_t decr;
    mpz_init(decr);

    int N = 1000;
    int W = 100;
    unsigned long start = 0;
    unsigned long elapsed = 0;
    unsigned long time_enc[N];
    unsigned long time_enc2[N];
    unsigned long time_dec[N];
    for (int i = 0; i < N + W; i++) {
        int r = rand() % 1000 - 500;
        sprintf(str, "%d", r);
        mpz_set_si(ptxt, i);

        start = time_micros();
        elgamal_gmp_encrypt(c1, c2, ptxt, &pk);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;

        start = time_micros();
        elgamal_gmp_encrypt_pre(c1, c2, ptxt, &pk);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc2[i - W] = elapsed;

        start = time_micros();
        elgamal_gmp_decrypt(decr, c1, c2, &sk);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }
    printf("Elgamal-GMP\n");
    printf("------------\n");
    printf("Encrypt\n");
    print_stats(time_enc, N);
    printf("Encrypt Pre-computation\n");
    print_stats(time_enc2, N);
    printf("Decrypt\n");
    print_stats(time_dec, N);
}

void time_paillier_bd() {
    char str[10];
    paillier_bd_pk pubKey;
    paillier_bd_sk privKey;
    paillier_bd_init(&pubKey, &privKey);
    BIGD ptxt = bdNew();
    BIGD ctxt = bdNew();
    BIGD decr = bdNew();

    int N = 20;
    int W = 2;
    unsigned long start = 0;
    unsigned long elapsed = 0;
    unsigned long time_enc[N];
    unsigned long time_enc2[N];
    unsigned long time_dec[N];
    for (int i = 0; i < N + W; i++) {
        int r = rand() % 1000 - 500;
        sprintf(str, "%d", r);
        bdConvFromDecimal(ptxt, str);

        start = time_micros();
        paillier_bd_encrypt(ctxt, ptxt, &pubKey);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;

        start = time_micros();
        paillier_bd_encrypt_pre(ctxt, ptxt, &pubKey);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc2[i - W] = elapsed;

        start = time_micros();
        paillier_bd_decrypt_crt(decr, ctxt, &privKey);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }
    printf("Paillier-BD\n");
    printf("------------\n");
    printf("Encrypt\n");
    print_stats(time_enc, N);
    printf("Encrypt Pre-computation\n");
    print_stats(time_enc2, N);
    printf("Decrypt\n");
    print_stats(time_dec, N);
}


void time_paillier_bn() {
    BN_CTX *ctx = BN_CTX_new();
    char str[10];
    BIGNUM *ptxt = BN_CTX_get(ctx);
    BIGNUM *ctxt = BN_CTX_get(ctx);
    BIGNUM *decr = BN_CTX_get(ctx);
    paillier_bn_pk pubKey;
    paillier_bn_sk privKey;
    paillier_bn_init(&pubKey, &privKey, ctx);

    int N = 1000;
    int W = 100;
    unsigned long start = 0;
    unsigned long elapsed = 0;
    unsigned long time_enc[N];
    unsigned long time_enc2[N];
    unsigned long time_dec[N];
    for (int i = 0; i < N + W; i++) {
        int r = rand() % 1000 - 500;
        sprintf(str, "%d", r);
        BN_dec2bn(&ptxt, str);

        start = time_micros();
        paillier_bn_encrypt(ctxt, ptxt, &pubKey, ctx);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;

        start = time_micros();
        paillier_bn_encrypt_pre(ctxt, ptxt, &pubKey, ctx);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc2[i - W] = elapsed;

        start = time_micros();
        paillier_bn_decrypt_crt(decr, ctxt, &privKey, ctx);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }
    printf("Paillier-BN\n");
    printf("------------\n");
    printf("Encrypt\n");
    print_stats(time_enc, N);
    printf("Encrypt Pre-computation\n");
    print_stats(time_enc2, N);
    printf("Decrypt\n");
    print_stats(time_dec, N);
}

void time_paillier_gmp() {
    char str[10];
    paillier_gmp_pk pk;
    paillier_gmp_sk sk;
    paillier_gmp_init(&pk, &sk);
    mpz_t ptxt;
    mpz_init(ptxt);
    mpz_t ctxt;
    mpz_init(ctxt);
    mpz_t decr;
    mpz_init(decr);

    int N = 1000;
    int W = 100;
    unsigned long start = 0;
    unsigned long elapsed = 0;
    unsigned long time_enc[N];
    unsigned long time_enc2[N];
    unsigned long time_dec[N];
    for (int i = 0; i < N + W; i++) {
        int r = rand() % 1000 - 500;
        sprintf(str, "%d", r);
        mpz_set_si(ptxt, i);

        start = time_micros();
        paillier_gmp_encrypt(ctxt, ptxt, &pk);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;

        start = time_micros();
        paillier_gmp_encrypt_pre(ctxt, ptxt, &pk);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc2[i - W] = elapsed;

        start = time_micros();
        paillier_gmp_decrypt_crt(decr, ctxt, &sk);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }

    printf("Paillier-GMP\n");
    printf("------------\n");
    printf("Encrypt\n");
    print_stats(time_enc, N);
    printf("Encrypt Pre-computation\n");
    print_stats(time_enc2, N);
    printf("Decrypt\n");
    print_stats(time_dec, N);
}

int main(int argc, char **argv) {
   time_aes();
   printf("\n");
   time_aes_ssl();
   printf("\n");
   time_elgamal_bd();
   printf("\n");
   time_elgamal_bn();
   printf("\n");
   time_elgamal_gmp();
   printf("\n");
    time_paillier_bd();
   printf("\n");
   time_paillier_bn();
   printf("\n");
   time_paillier_gmp();
   printf("\n");
   exit(EXIT_SUCCESS);
}
