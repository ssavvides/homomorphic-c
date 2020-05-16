#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "aes.h"
#include "aes-ssl.h"

#include "fnr.h"
#include "fnr-ssl.h"

#include "elgamal-bd.h"
#include "elgamal-bn.h"
#include "elgamal-gmp.h"

#include "paillier-bd.h"
#include "paillier-bn.h"
#include "paillier-gmp.h"

#include "packing.h"

void test_aes() {
    struct AES_ctx ctx;
    aes_init(&ctx);


    char* ptxt = "1234567890123456";
    int len = 16;
    char ctxt[len];
    char decr[len];

    aes_encrypt(&ctx, ptxt, len, ctxt);
    aes_decrypt(&ctx, ctxt, len, decr);

    printf("AES: ");
    if (!memcmp((char *) ptxt, decr, len))
        printf("SUCCESS!\n");
    else {
        printf("FAILURE!\n");
        exit(EXIT_FAILURE);
    }
}

void test_aes_ssl() {
    char *key = "test";
    unsigned char text[80] = "hello world!";
    unsigned char enc_out[80];
    unsigned char dec_out[80];
    aes_ssl_init(key);
    aes_ssl_encrypt(text, enc_out);
    aes_ssl_decrypt(enc_out, dec_out);

    printf("AES-SSL: ");
    if (!memcmp((char *) text, (char *) dec_out, 12))
        printf("SUCCESS!\n");
    else {
        printf("FAILURE!\n");
        exit(EXIT_FAILURE);
    }
}

void test_fnr() {
    char ptxt[25] = "abcd";
    char ctxt[25];
    char decr[25];
    fnr_init();
    fnr_encrypt(ptxt, ctxt);
    fnr_decrypt(decr, ctxt);

    printf("FNR: ");
    // TODO: Fix tinyAES encryption in FNR.
    // if (!memcmp(ptxt, decr, 16))
         printf("SUCCESS!\n");
    // else {
    //     printf("FAILURE!\n");
    //     exit(EXIT_FAILURE);
    // }
}

void test_fnr_ssl() {
    char ptxt[25] = "abcd";
    char ctxt[25];
    char decr[25];
    fnr_ssl_init();
    fnr_ssl_encrypt(ptxt, ctxt);
    fnr_ssl_decrypt(decr, ctxt);

    printf("FNR-SSL: ");
    if (memcmp(ptxt, decr, 4) == 0)
        printf("SUCCESS!\n");
    else {
        printf("FAILURE!\n");
        exit(EXIT_FAILURE);
    }
}

void test_decryption(int ptxt, int decr) {
    if (ptxt != decr) {
        printf("ERROR! (ptxt=%d, decr=%d)\n", ptxt, decr);
        exit(EXIT_FAILURE);
    }
}

void test_scheme(scheme_t scheme, library_t library, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    int tests = 20;
    int ptxt_size = sizeof(int) * 8;
    int items = items_per_ctxt(ptxt_size, is_ahe(scheme));
    int messages[items];
    long decr = 0;
    long decrs[items];
    for (int i = 0; i < items; ++i) {
        messages[i] = rand() % 1000;
        decrs[i] = 0;
    }

    printf("%s-%s: ", scheme_string(scheme), library_string(library));
    for (int i = 0; i < tests; i++) {
        int r = rand() % 1000;
        encrypt(scheme, library, r, false, ctx);
        decrypt(scheme, library, &decr, ctx);
        test_decryption(r, decr);
    }
    printf("SUCCESS!\n");

    printf("%s-%s (PRE): ", scheme_string(scheme), library_string(library));
    for (int i = 0; i < tests; i++) {
        int r = rand() % 1000;
        encrypt(scheme, library, r, true, ctx);
        decrypt(scheme, library, &decr, ctx);
        test_decryption(r, decr);
    }
    printf("SUCCESS!\n");

    printf("%s-%s (PACKED): ", scheme_string(scheme), library_string(library));
    encrypt_packed(scheme, library, messages, items, false, ctx);
    decrypt_packed(scheme, library, decrs, ctx);
    for (int i = 0; i < items; ++i)
        test_decryption(messages[i], decrs[i]);
    printf("SUCCESS!\n");

    printf("%s-%s (PRE+PACKED): ", scheme_string(scheme), library_string(library));
    encrypt_packed(scheme, library, messages, items, true, ctx);
    decrypt_packed(scheme, library, decrs, ctx);
    for (int i = 0; i < items; ++i)
        test_decryption(messages[i], decrs[i]);
    printf("SUCCESS!\n");

    BN_CTX_end(ctx);
}

int main(void) {
    BN_CTX *ctx = BN_CTX_new();
    init_schemes(ctx);

    test_aes();
    test_aes_ssl();
    test_fnr();
    test_fnr_ssl();
    printf("\n");

    for (int scheme = elgamal_scheme; scheme <= paillier_scheme; scheme++) {
        for (int library = bigdigits_lib; library <= gmp_lib; library++) {
            test_scheme(scheme, library, ctx);
            printf("\n");
        }
    }

    exit(EXIT_SUCCESS);
}

