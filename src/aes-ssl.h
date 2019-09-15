#ifndef AES_SSL_H
#define AES_SSL_H

void aes_ssl_init(const char *key);

void aes_ssl_encrypt(const void *ptxt, void *ctxt);

void aes_ssl_decrypt(const void *ctxt, void *ptxt);

#endif
