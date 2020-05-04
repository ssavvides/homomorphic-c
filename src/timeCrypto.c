#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "time.h"
#include "packing.h"

#include "pk.h"

#include "aes.h"
#include "aes-ssl.h"

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

    int N = 1000, W = 100;
    unsigned long start = 0, elapsed = 0;
    unsigned long time_enc[N], time_dec[N];

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
    init_schemes(ctx);

    time_aes();
    printf("\n");
    time_aes_ssl();
    printf("\n");

    for (int scheme = elgamal_scheme; scheme <= paillier_scheme; scheme++) {
        for (int library = bigdigits_lib; library <= gmp_lib; library++) {
            time_scheme(scheme, library, ctx);
            printf("\n");
        }
    }

    exit(EXIT_SUCCESS);
}
