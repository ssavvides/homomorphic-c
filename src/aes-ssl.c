#include <openssl/aes.h>
#include "aes-ssl.h"

static AES_KEY enc;
static AES_KEY dec;

void aes_ssl_init(const char *key) {
    AES_set_encrypt_key((unsigned char *) key, 128, &enc);
    AES_set_decrypt_key((unsigned char *) key, 128, &dec);
}

void aes_ssl_encrypt(const void *ptxt, void *ctxt) {
    AES_encrypt((unsigned char *) ptxt, (unsigned char *) ctxt, &enc);
}

void aes_ssl_decrypt(const void *ctxt, void *ptxt) {
    AES_decrypt((unsigned char *) ctxt, (unsigned char *) ptxt, &dec);
}
