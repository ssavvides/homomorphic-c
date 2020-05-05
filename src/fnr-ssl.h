/*
 * libFNR - A reference implementation library for FNR encryption .
 *
 * See https://github.com/cisco/libfnr for original implementation
 *
 **/
#ifndef FNR_SSL_H_
#define FNR_SSL_H_

typedef struct fnr_ssl_expanded_key_st fnr_ssl_expanded_key;
typedef struct fnr_ssl_expanded_tweak_st {
    unsigned char tweak[15];
} fnr_ssl_expanded_tweak;

fnr_ssl_expanded_key *FNR_SSL_expand_key(const void *aes_key, unsigned int aes_key_size,
                                size_t num_text_bits);
void FNR_SSL_release_key(fnr_ssl_expanded_key *key);
void FNR_SSL_expand_tweak(fnr_ssl_expanded_tweak *expanded_tweak,
                      const fnr_ssl_expanded_key *key,
                      const void *tweak, size_t len_tweak );
void FNR_SSL_init(void);
void FNR_SSL_shut(void);
void FNR_SSL_encrypt(const fnr_ssl_expanded_key *key,const fnr_ssl_expanded_tweak *tweak,
                 const void *plaintext, void *ciphertext);
void FNR_SSL_decrypt(const fnr_ssl_expanded_key *key, const fnr_ssl_expanded_tweak *tweak,
                 const void *ciphertext, void *plaintext);
void FNR_SSL_handle_errors(void);
void FNR_SSL_burn( void *v, size_t n );

void fnr_ssl_init();
void fnr_ssl_encrypt(void *ptxt, void *ctxt);
void fnr_ssl_decrypt(void *ptxt, void *ctxt);

#endif
