#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "time.h"
#include "packing.h"

#include "pk.h"

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

void print_one(unsigned long* times, int N) {
    double mean, std;
    get_stats(&mean, &std, times, N);
    printf("%.4f\t%.4f\t", mean, std);
}

void print_one_packed(unsigned long* times, int N, int items) {
    double mean, std;
    get_stats(&mean, &std, times, N);
    printf("%.4f\t%.4f\t", mean / items, std);
}

void print_all(
        scheme_t scheme, library_t library,
        unsigned long* time_enc, unsigned long* time_enc_pre,
        unsigned long* time_enc_packed, unsigned long* time_enc_pre_packed,
        unsigned long* time_dec, unsigned long* time_dec_packed,
        int N, int items) {

    printf("%s-%s\n", scheme_string(scheme), library_string(library));

    printf("Encrypt\tEncrypt-pre\tEncrypt-packed(%d)\tEncrypt-pre+packed(%d) (all times in milliseconds)\n", items, items);
    print_one(time_enc, N);
    print_one(time_enc_pre, N);
    print_one_packed(time_enc_packed, N, items);
    print_one_packed(time_enc_pre_packed, N, items);
    printf("\n");

    printf("Decrypt\tDecrypt-packed(%d)\n", items);
    print_one(time_dec, N);
    print_one_packed(time_dec_packed, N, items);
    printf("\n");
}

void time_aes() {
    struct AES_ctx ctx;
    aes_init(&ctx);


    char* ptxt = "1234567890123456";
    int len = 16;
    char ctxt[len];
    char decr[len];

    int N = 1000, W = 100;
    unsigned long start = 0, elapsed = 0;
    unsigned long time_enc[N], time_dec[N];

    for (int i = 0; i < N + W; i++) {
        start = time_micros();
        aes_encrypt(&ctx, ptxt, len, ctxt);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;
        start = time_micros();
        aes_decrypt(&ctx, ctxt, len, decr);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }
    printf("AES\n------------\nEncrypt\n");
    print_one(time_enc, N);
    printf("\nDecrypt\n");
    print_one(time_dec, N);
    printf("\n");
}

void time_aes_ssl() {
    char *key = "test";
    unsigned char text[32] = "12345678901234567890123456789012";
    unsigned char enc_out[32], dec_out[32];
    aes_ssl_init(key);

    int N = 1000, W = 100;
    unsigned long start = 0, elapsed = 0;
    unsigned long time_enc[N], time_dec[N];

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
    printf("AES-SSL\n------------\nEncrypt\n");
    print_one(time_enc, N);
    printf("\nDecrypt\n");
    print_one(time_dec, N);
    printf("\n");
}

void time_fnr() {
    unsigned char ptxt[32] = "aaaa";
    unsigned char ctxt[32], decr[32];
    fnr_init();

    int N = 1000, W = 100;
    unsigned long start = 0, elapsed = 0;
    unsigned long time_enc[N], time_dec[N];

    for (int i = 0; i < N + W; i++) {
        start = time_micros();
        fnr_encrypt(ptxt, ctxt);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;
        start = time_micros();
        fnr_decrypt(decr, ctxt);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }
    printf("FNR\n------------\nEncrypt\n");
    print_one(time_enc, N);
    printf("\nDecrypt\n");
    print_one(time_dec, N);
    printf("\n");
}

void time_fnr_ssl() {
    unsigned char ptxt[32] = "aaaa";
    unsigned char ctxt[32], decr[32];
    fnr_ssl_init();

    int N = 1000, W = 100;
    unsigned long start = 0, elapsed = 0;
    unsigned long time_enc[N], time_dec[N];

    for (int i = 0; i < N + W; i++) {
        start = time_micros();
        fnr_ssl_encrypt(ptxt, ctxt);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;
        start = time_micros();
        fnr_ssl_decrypt(decr, ctxt);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;
    }
    printf("FNR-SSL\n------------\nEncrypt\n");
    print_one(time_enc, N);
    printf("\nDecrypt\n");
    print_one(time_dec, N);
    printf("\n");
}

void time_scheme(scheme_t scheme, library_t library, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    int ptxt_size = sizeof(int) * 8;
    int items = items_per_ctxt(ptxt_size, is_ahe(scheme));
    int messages[items];
    long decr, decrs[items];

    int N = 5, W = 1;
    unsigned long start = 0, elapsed = 0;
    unsigned long time_enc[N], time_enc_pre[N];
    unsigned long time_enc_packed[N], time_enc_pre_packed[N];
    unsigned long time_dec[N], time_dec_packed[N];

    for (int i = 0; i < N + W; i++) {
        int r = rand() % 1000;

        start = time_micros();
        encrypt(scheme, library, r, false, ctx);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc[i - W] = elapsed;

        start = time_micros();
        encrypt(scheme, library, r, true, ctx);
        elapsed = time_micros() - start;
        if (i >= W)
            time_enc_pre[i - W] = elapsed;

        start = time_micros();
        decrypt(scheme, library, &decr, ctx);
        elapsed = time_micros() - start;
        if (i >= W)
            time_dec[i - W] = elapsed;

        for (int i = 0; i < items; ++i)
            messages[i] = rand() % 1000;

        start = time_micros();
        encrypt_packed(scheme, library, messages, items, false, ctx);
        elapsed = (time_micros() - start);
        if (i >= W)
            time_enc_packed[i - W] = elapsed;

        start = time_micros();
        encrypt_packed(scheme, library, messages, items, true, ctx);
        elapsed = (time_micros() - start);
        if (i >= W)
            time_enc_pre_packed[i - W] = elapsed;

        start = time_micros();
        decrypt(scheme, library, decrs, ctx);
        elapsed = (time_micros() - start);
        if (i >= W)
            time_dec_packed[i - W] = elapsed;
    }

    print_all(scheme, library, time_enc, time_enc_pre, time_enc_packed,
        time_enc_pre_packed, time_dec, time_dec_packed, N, items);

    BN_CTX_end(ctx);
}

int main(void) {
    BN_CTX *ctx = BN_CTX_new();
    //init_schemes(ctx);

    // time_aes();
    // printf("\n");
    // time_aes_ssl();
    // printf("\n");
    // time_fnr();
    // printf("\n");
    // time_fnr_ssl();
    // printf("\n");

    printf("Initializing Paillier BN\n");
    paillier_bn_init(&pail_bn_pk, &pail_bn_sk, ctx);
    pail_bn_ctxt = BN_CTX_get(ctx);

    time_scheme(paillier_scheme, ssl_lib, ctx);


    exit(EXIT_SUCCESS);
}
