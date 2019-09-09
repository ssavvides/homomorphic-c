#ifndef AES_SSL_H
#define AES_SSL_H

void init_aes_ssl(const char *key);
void encrypt_aes_ssl(const void *ptxt, void *ctxt);
void decrypt_aes_ssl(const void *ctxt, void *ptxt);

#endif


