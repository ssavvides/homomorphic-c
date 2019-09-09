/**
 * savvas@purdue.edu
 * 31/07/2019
 */
#include <openssl/aes.h>
#include "aes-ssl.h"

static AES_KEY enc;
static AES_KEY dec;

void init_aes_ssl(const char *key) {
	AES_set_encrypt_key((unsigned char*) key, 128, &enc);
	AES_set_decrypt_key((unsigned char*) key, 128, &dec);
}

void encrypt_aes_ssl(const void *ptxt, void *ctxt) {
	AES_encrypt((unsigned char*) ptxt, (unsigned char*) ctxt, &enc);
}

void decrypt_aes_ssl(const void *ctxt, void *ptxt) {
	AES_decrypt((unsigned char*) ctxt, (unsigned char*) ptxt, &dec);
}

