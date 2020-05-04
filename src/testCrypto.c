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

#include "packing.h"

void test_aes() {
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
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };
    uint8_t ptxt_copy[64];
    memcpy(ptxt_copy, ptxt, sizeof(ptxt));
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, ptxt, 64);
    AES_ctx_set_iv(&ctx, iv);
    AES_CBC_decrypt_buffer(&ctx, ptxt, 64);

    printf("AES: ");
    if (0 == memcmp((char *) ptxt, (char *) ptxt_copy, 64))
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
    if (0 == memcmp((char *) text, (char *) dec_out, 12))
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

    for (int scheme = elgamal_scheme; scheme <= paillier_scheme; scheme++) {
        for (int library = bigdigits_lib; library <= gmp_lib; library++) {
            test_scheme(scheme, library, ctx);
            printf("\n");
        }
    }

    exit(EXIT_SUCCESS);
}
