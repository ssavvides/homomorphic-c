/*
 * libFNR - A reference implementation library for FNR encryption .
 *
 * See https://github.com/cisco/libfnr for original implementation
 *
 **/
#ifndef FNR_H_
#define FNR_H_

typedef struct fnr_expanded_key_st fnr_expanded_key;
typedef struct fnr_expanded_tweak_st{
    unsigned char tweak[15];
} fnr_expanded_tweak;

fnr_expanded_key *FNR_expand_key(const void *aes_key, unsigned int aes_key_size,
                                size_t num_text_bits);
void FNR_release_key(fnr_expanded_key *key);
void FNR_expand_tweak(fnr_expanded_tweak *expanded_tweak,
                      fnr_expanded_key *key,
                      const void *tweak, size_t len_tweak );
void FNR_init(void);
void FNR_shut(void);
void FNR_encrypt(fnr_expanded_key *key,const fnr_expanded_tweak *tweak,
                 const void *plaintext, void *ciphertext);
void FNR_decrypt(fnr_expanded_key *key, const fnr_expanded_tweak *tweak,
                 const void *ciphertext, void *plaintext);
void FNR_handle_errors(void);
void FNR_burn( void *v, size_t n );

void fnr_init();
void fnr_encrypt(void *ptxt, void *ctxt);
void fnr_decrypt(void *ptxt, void *ctxt);

#endif
