#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "aes.h"
#include "aes-ssl.h"
#include "elgamal-bd.h"
#include "elgamal-bn.h"
#include "elgamal-gmp.h"
#include "paillier-bd.h"
#include "paillier-bn.h"
#include "paillier-gmp.h"

void test_aes() {
    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t iv[]  = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t ptxt[]  = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    uint8_t ptxt_copy[64];
    memcpy (ptxt_copy, ptxt, sizeof(ptxt));

    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, ptxt, 64);

    AES_ctx_set_iv(&ctx, iv);
    AES_CBC_decrypt_buffer(&ctx, ptxt, 64);

    printf("AES: ");
    if (0 == memcmp((char*) ptxt, (char*) ptxt_copy, 64))
        printf("SUCCESS!\n");
    else{
        printf("FAILURE!\n");
        exit(EXIT_FAILURE);
    }
}

void test_aes_ssl() {
    char * key = "test";
    unsigned char text[80] = "hello world!";
    unsigned char enc_out[80];
    unsigned char dec_out[80];

    init_aes_ssl(key);
    encrypt_aes_ssl(text, enc_out);
    decrypt_aes_ssl(enc_out, dec_out);


    printf("AES-SSL: ");
    if (0 == memcmp((char*) text, (char*) dec_out, 12))
        printf("SUCCESS!\n");
    else {
        printf("FAILURE!\n");
        exit(EXIT_FAILURE);
    }
    // printf("plaintext= %s\n", text);
    // printf("decrypted= %s\n", dec_out);
    // printf("\n");
}

void test_elgamal_bd() {

    elg_bd_pk pubKey;
    elg_bd_sk privKey;
    init_elgamal_bd(&pubKey, &privKey);

    BIGD ptxt = bdNew();
    BIGD c1 = bdNew();
    BIGD c2 = bdNew();
    BIGD decr = bdNew();

    char str[10];

    for (int i = 1; i < 5; i++) {
        sprintf(str, "%d", i);
        bdConvFromDecimal(ptxt, str);

        encrypt_elgamal_bd(c1, c2, ptxt, &pubKey);
        decrypt_elgamal_bd(decr, c1, c2, &privKey);

        if (bdCompare(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("ELGAMAL-BD: SUCCESS!\n");

    for (int i = 1; i < 5; i++) {
        sprintf(str, "%d", i);
        bdConvFromDecimal(ptxt, str);

        encrypt_pre_elgamal_bd(c1, c2, ptxt, &pubKey);
        decrypt_elgamal_bd(decr, c1, c2, &privKey);

        if (bdCompare(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("ELGAMAL-BD (PRE): SUCCESS!\n");
}

void test_elgamal_bn() {
    BN_CTX *ctx = BN_CTX_new();

    elg_pk pubKey;
    elg_sk privKey;
    init_elgamal_bn(&pubKey, &privKey, ctx);

    BIGNUM * ptxt = BN_CTX_get(ctx);
    BIGNUM * c1 = BN_CTX_get(ctx);
    BIGNUM * c2 = BN_CTX_get(ctx);
    BIGNUM * decr = BN_CTX_get(ctx);

    char str[10];

    for (int i = -100; i < 100; i++) {
        sprintf(str, "%d", i);
        BN_dec2bn(&ptxt, str);

        encrypt_elgamal_bn(c1, c2, ptxt, &pubKey, ctx);
        decrypt_elgamal_bn(decr, c1, c2, &privKey, ctx);

        // char* a = BN_bn2dec(ptxt);
        // char* b = BN_bn2dec(c1);
        // char* c = BN_bn2dec(c2);
        // char* d = BN_bn2dec(decr);
        // printf("ptxt: %s \nc1: %s \nc2: %s \ndecr: %s\n", a, b, c, d);

        if (BN_cmp(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("ELGAMAL-BN: SUCCESS!\n");

    for (int i = -100; i < 100; i++) {
        sprintf(str, "%d", i);
        BN_dec2bn(&ptxt, str);

        encrypt2_elgamal_bn(c1, c2, ptxt, &pubKey, ctx);
        decrypt_elgamal_bn(decr, c1, c2, &privKey, ctx);

        // char* a = BN_bn2dec(ptxt);
        // char* b = BN_bn2dec(c1);
        // char* c = BN_bn2dec(c2);
        // char* d = BN_bn2dec(decr);
        // printf("ptxt: %s \nc1: %s \nc2: %s \ndecr: %s\n", a, b, c, d);

        if (BN_cmp(decr, ptxt) != 0) {
            printf("Pre-computation Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("ELGAMAL-BN (PRE): SUCCESS!\n");
}

void test_elgamal_gmp() {
    elg_gmp_pk pk;
    elg_gmp_sk sk;
    init_elgamal_gmp(&pk, &sk);

    mpz_t ptxt;
    mpz_init(ptxt);

    mpz_t c1;
    mpz_init(c1);
    mpz_t c2;
    mpz_init(c2);

    mpz_t decr;
    mpz_init(decr);

    for (int i = -100; i < 100; i++) {
        mpz_set_si(ptxt, i);

        encrypt_elgamal_gmp(c1, c2, ptxt, &pk);
        decrypt_elgamal_gmp(decr, c1, c2, &sk);

        // char* a = mpz_get_str(NULL, 10, ptxt);
        // char* b = mpz_get_str(NULL, 10, c1);
        // char* c = mpz_get_str(NULL, 10, c2);
        // char* d = mpz_get_str(NULL, 10, decr);
        // printf("ptxt: %s \nc1: %s \nc2: %s \ndecr: %s\n", a, b, c, d);

        if (mpz_cmp(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("ELGAMAL-GMP: SUCCESS!\n");

    for (int i = -100; i < 100; i++) {
        mpz_set_si(ptxt, i);

        encrypt2_elgamal_gmp(c1, c2, ptxt, &pk);
        decrypt_elgamal_gmp(decr, c1, c2, &sk);
        if (mpz_cmp(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("ELGAMAL-GMP (PRE): SUCCESS!\n");
}

void test_paillier_bd() {
    paillier_bd_pk pubKey;
    paillier_bd_sk privKey;
    init_paillier_bd(&pubKey, &privKey);

    BIGD ptxt = bdNew();
    BIGD ctxt = bdNew();
    BIGD decr = bdNew();

    char str[10];

    for (int i = 1; i < 5; i++) {
        sprintf(str, "%d", i);
        bdConvFromDecimal(ptxt, str);

        encrypt_paillier_bd(ctxt, ptxt, &pubKey);
        decrypt_paillier_bd(decr, ctxt, &privKey);

        if (bdCompare(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("Paillier-BD: SUCCESS!\n");

    for (int i = 1; i < 5; i++) {
        sprintf(str, "%d", i);
        bdConvFromDecimal(ptxt, str);

        encrypt_pre_paillier_bd(ctxt, ptxt, &pubKey);
        decrypt_paillier_bd(decr, ctxt, &privKey);

        if (bdCompare(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("Paillier-BD (PRE): SUCCESS!\n");
}

void test_paillier_bn() {
    BN_CTX *ctx = BN_CTX_new();

    paillier_bn_pk pubKey;
    paillier_bn_sk privKey;
    init_paillier_bn(&pubKey, &privKey, ctx);

    BIGNUM * ptxt = BN_CTX_get(ctx);
    BIGNUM * ctxt = BN_CTX_get(ctx);
    BIGNUM * decr = BN_CTX_get(ctx);

    char str[10];

    for (int i = -100; i < 100; i++) {
        sprintf(str, "%d", i);
        BN_dec2bn(&ptxt, str);

        encrypt_paillier_bn(ctxt, ptxt, &pubKey, ctx);
        decrypt_paillier_bn(decr, ctxt, &privKey, ctx);

        if (BN_cmp(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("Paillier-BN: SUCCESS!\n");

    for (int i = -100; i < 100; i++) {
        sprintf(str, "%d", i);
        BN_dec2bn(&ptxt, str);

        encrypt2_paillier_bn(ctxt, ptxt, &pubKey, ctx);
        decrypt_paillier_bn(decr, ctxt, &privKey, ctx);

        if (BN_cmp(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("Paillier-BN (PRE): SUCCESS!\n");
}

void test_paillier_gmp() {
    paillier_gmp_pk pk;
    paillier_gmp_sk sk;
    init_paillier_gmp(&pk, &sk);

    mpz_t ptxt;
    mpz_init(ptxt);

    mpz_t ctxt;
    mpz_init(ctxt);

    mpz_t decr;
    mpz_init(decr);

    for (int i = -100; i < 100; i++) {
        mpz_set_si(ptxt, i);

        encrypt_paillier_gmp(ctxt, ptxt, &pk);
        decrypt_paillier_gmp(decr, ctxt, &sk);

        if (mpz_cmp(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("PAILLIER-GMP: SUCCESS!\n");

    for (int i = -100; i < 100; i++) {
        mpz_set_si(ptxt, i);

        encrypt4_paillier_gmp(ctxt, ptxt, &pk);
        decrypt_paillier_gmp(decr, ctxt, &sk);

        if (mpz_cmp(decr, ptxt) != 0) {
            printf("Decryption ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("PAILLIER-GMP (PRE): SUCCESS!\n");
}

int main(int argc, char **argv) {
    // test_aes();
    // test_aes_ssl();
    test_elgamal_bd();
    test_elgamal_bn();
    test_elgamal_gmp();
    // test_paillier_bd();
    // test_paillier_bn();
    // test_paillier_gmp();
    exit(EXIT_SUCCESS);
}
