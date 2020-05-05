/*
 * libFNR - A reference implementation library for FNR encryption .
 *
 * See https://github.com/cisco/libfnr for original implementation
 *
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "fnr-ssl.h"

#define N_ROUND  7
#define BLOCKSIZE 16
typedef unsigned char element;
#define BITS_PER_ELEMENT 8
#define ELEMENTS_PER_ROW(N) (((unsigned)N + BITS_PER_ELEMENT - 1) / BITS_PER_ELEMENT)

#define TWEAK_MARKER 0xff
#define RND_MARKER 0xc0

#define SWAP 0
#define XOR 1

struct fnr_ssl_expanded_key_st {
    unsigned full_bytes;
    unsigned char final_mask;
    unsigned full_elements;
    element final_element_mask;

    unsigned num_bits;
    size_t size;
    AES_KEY expanded_aes_key;
    unsigned char *aes_key;
    element  *green;
    element  red[1];
};

void FNR_SSL_burn( void *v, size_t n )
{
  volatile unsigned char *p = ( volatile unsigned char * )v;
  while( n-- ) *p++ = 0;
}

void FNR_SSL_handle_errors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

struct pwip_stream {
    fnr_ssl_expanded_key *key;
    size_t num_bits;
    unsigned count;
    unsigned index;
    unsigned bit_count;
    unsigned char buffer[BLOCKSIZE];
};

static const unsigned char round_const[7] = { 0x00, 0x03, 0x0c, 0x0f, 0x30, 0x33, 0x3c };

static void pwip(const fnr_ssl_expanded_key *key, const element  *m, const void *in, void *out);

static int next_bit(struct pwip_stream *ctx) {
    if (ctx->index == BLOCKSIZE) {
        unsigned char block[BLOCKSIZE] = { 0 };
        unsigned count = ctx->count++;
        block[0] = (count      ) & 0xff;
        block[1] = (count >>  8) & 0xff;
        block[2] = (count >> 16) & 0xff;
        block[3] = (count >> 24) & 0xff;
        block[BLOCKSIZE-2] = ctx->num_bits;
        block[BLOCKSIZE-1] = RND_MARKER;
        AES_encrypt(block, ctx->buffer, &ctx->key->expanded_aes_key);

        ctx->index = 0; ctx->bit_count = 0;
    }

    int bit = (ctx->buffer[ ctx->index ] >> ctx->bit_count) & 0x01;

    ctx->bit_count++;
    if (ctx->bit_count == 8) {
        ctx->index++;
        ctx->bit_count = 0;
    }

    return bit;
}

static unsigned next_bits(struct pwip_stream *ctx, int n) {
    unsigned result = 0;
    int i;
    for (i=0; i<n; i++) {
        result += next_bit(ctx) << i;
    }
    return result;
}

static int next_bits_not_all_zero(struct pwip_stream *ctx, unsigned char *bits, int n_bits) {
    if (n_bits == 1) {
        bits[0] = 1;
        return 0;
    }

    int first_nonzero = -1;
    do {
        int i;
        for (i=0; i<n_bits; i++) {
            bits[i] = next_bit(ctx);
            if (first_nonzero < 0 && bits[i] != 0) {
                first_nonzero = i;
            }
        }
    } while (first_nonzero < 0);

    return first_nonzero;
}

struct gen_matrix {
    unsigned char type;
    unsigned char a;
    unsigned char b;
};

static void multiply_gen_matrix( int N, element *A, struct gen_matrix *sub) {
    int elements_per_row = ELEMENTS_PER_ROW(N);
    int a_row = elements_per_row * (sub->a + 1);
    int b_row = elements_per_row * (sub->b + 1);
    int i;

    switch (sub->type) {
    case SWAP:
        for (i=0; i<elements_per_row; i++, a_row++, b_row++) {
           element  t = A[ a_row ]; A[ a_row ] = A[ b_row ]; A[ b_row ] = t;
        }
        break;
    case XOR:
        for (i=0; i<elements_per_row; i++, a_row++, b_row++) {
            A[ b_row ] ^= A[ a_row ];
        }
        break;
    default:
    break;
    }
}

static int expand_red_green(struct pwip_stream *stream,element  *A,element  *B,
                            unsigned n) {
    size_t array_byte_size = n * (n - 1) * sizeof (struct gen_matrix) + 1;
    struct gen_matrix *array = malloc( array_byte_size );
    if (!array) return 0;
    int index = 0;
#define SET(x, y, z)  (void)( array[index].type = x, array[index].a = y, array[index].b = z, index++ )

    unsigned i;
    unsigned char bits[128];
    for (i=0; i<n; i++) {
        int j;

        int first_nonzero = next_bits_not_all_zero(stream, bits, n-i);

        if (first_nonzero > 0) {
            SET(SWAP, i, i+first_nonzero);
            bits[first_nonzero] = 0;
        }

        for (j=1; j<n-i; j++) {
            if (bits[j]) {
                SET(XOR, i, i+j);
            }
        }

        for (j=0; j<i; j++) {
            if (next_bit(stream)) {
                SET(XOR, i, j);
            }
        }

    }
    FNR_SSL_burn( bits, sizeof bits );

    int elements_per_row = ELEMENTS_PER_ROW(n);

    FNR_SSL_burn( &A[elements_per_row],  n * elements_per_row );
    FNR_SSL_burn( &B[elements_per_row],  n * elements_per_row );
    unsigned char bit = 0;
    int column = -1;
    for (i=0; i<n; i++) {
        if (i % 8 == 0) {
            bit = 1;
            column++;
        }
        A[elements_per_row + i*elements_per_row + column] =
        B[elements_per_row + i*elements_per_row + column] = bit;
        bit <<= 1;
    }

    for (i=index; i>0; i--) {
        multiply_gen_matrix( n, A, &array[i-1] );
    }

    for (i=0; i<index; i++) {
        multiply_gen_matrix( n, B, &array[i] );
    }

    FNR_SSL_burn(array,  array_byte_size );
    free(array);

    column = -1;
    for (i=0; i<n; i+=8) {
        int bits_this_time = n-i; if (bits_this_time > 8) bits_this_time = 8;
        A[i/8] = next_bits(stream, bits_this_time);
    }

    FNR_SSL_burn( &B[0],  elements_per_row * sizeof(element) );
    pwip(stream->key, B, A, B);
    return 1;
}

fnr_ssl_expanded_key *FNR_SSL_expand_key(const void *aes_key, unsigned int aes_key_size,
                                 size_t num_bits) {
    if (num_bits < 1 || num_bits > 128) {
        return NULL;
    }

    int elements_per_row = ELEMENTS_PER_ROW(num_bits);
    size_t size = sizeof(fnr_ssl_expanded_key) + 2 * elements_per_row * (num_bits + 1);
    fnr_ssl_expanded_key *key = malloc( size );
    if (!key) {
        return NULL;
    }

    key->full_bytes = (num_bits-1)/8;
    key->full_elements = key->full_bytes;
    key->final_mask = 0xff & ((1<<((num_bits+7)%8 + 1)) - 1);
    key->final_element_mask = key->final_mask;
    key->num_bits = num_bits;
    key->size = size;
    key->green = key->red + elements_per_row * (num_bits + 1);

    if (AES_set_encrypt_key(aes_key, aes_key_size, &key->expanded_aes_key) != 0) {
        free(key);
        return NULL;
    }

    key->aes_key = calloc(1, aes_key_size + 1);
    memcpy(key->aes_key, aes_key, aes_key_size);

    struct pwip_stream stream;
    stream.key = key;
    stream.num_bits = num_bits;
    stream.count = 0;
    stream.index = BLOCKSIZE;

    if (!expand_red_green( &stream, key->red, key->green, num_bits )) {
        free(key);
        return NULL;
    }

    FNR_SSL_burn( &stream, sizeof stream );
    return key;
}

void FNR_SSL_release_key(fnr_ssl_expanded_key *key) {
    if (!key) return;
    FNR_SSL_burn( key, key->size );
    free(key);
}

void FNR_SSL_expand_tweak(fnr_ssl_expanded_tweak *expanded_tweak,
                    const fnr_ssl_expanded_key *key,
                    const void *tweak, size_t len_tweak) {
    unsigned char block[BLOCKSIZE] = { 0 };

    block[0] = len_tweak & 0xff;
    block[1] = len_tweak >> 8;
    block[2] = len_tweak >> 16;
    block[3] = len_tweak >> 24;
    block[4] = key->num_bits;
    unsigned n = 5;
    const unsigned char *input = tweak;

    do {
        for (; n<BLOCKSIZE-1 && len_tweak; n++) {
            block[n] ^= *input++;
            len_tweak--;
        }
        block[BLOCKSIZE-1] = TWEAK_MARKER;
    AES_encrypt(block, block, &key->expanded_aes_key);
        n = 0;

    } while (len_tweak > 0);

    memcpy( expanded_tweak, block, BLOCKSIZE-1 );
    FNR_SSL_burn( block, sizeof block );
}

static void pwip(const fnr_ssl_expanded_key *key, const element *m,
                 const void *in, void *out) {
    unsigned i, j;
    const unsigned char *input = in;
    element *result = out;

    unsigned elements_per_row = key->full_elements;
    for (i=0; i<elements_per_row; i++)
        result[i] = *m++;

    unsigned final_mask = key->final_element_mask;
    result[i] = (result[i] & ~final_mask) | *m++;

    unsigned char a = 0;
    unsigned num_bits = key->num_bits;
    for (i=0; i<num_bits; i++) {
        if (i % BITS_PER_ELEMENT == 0) a = *input++;
        element mask = -(a&1);
        a >>= 1;
        for (j=0; j<=elements_per_row; j++) {
            result[j] ^= mask & *m++;
        }
    }
}

static void FNR_SSL_operate(const fnr_ssl_expanded_key *key,const fnr_ssl_expanded_tweak *tweak,
                        const void *in, void *out, int round, int round_inc ) {
    unsigned char text[BLOCKSIZE] = { 0 };
    pwip( key, key->red, in, text );
    unsigned char block[BLOCKSIZE];
    unsigned mask = 0x55;
    unsigned full_bytes = key->full_bytes;
    unsigned final_mask = key->final_mask;

    for (int i=0; i<N_ROUND; i++, round += round_inc) {
        memcpy( block, tweak, BLOCKSIZE-1 );
        block[BLOCKSIZE-1] = round_const[round];

        unsigned j;
        for (j=0; j<full_bytes; j++) {
            block[j] ^= text[j] & mask;
        }
        block[j] ^= text[j] & mask & final_mask;

        AES_encrypt(block, block, &key->expanded_aes_key);

        mask ^= 0xff;

        for (j=0; j<=full_bytes; j++) {
            text[j] ^= block[j] & mask;
        }
    }

    pwip( key, key->green, text, out );
    FNR_SSL_burn( block, sizeof block );
    FNR_SSL_burn( text,  sizeof text );
}

void FNR_SSL_init(void){
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

void FNR_SSL_shut(void) {
  EVP_cleanup();
  ERR_free_strings();
}

void FNR_SSL_encrypt(const fnr_ssl_expanded_key *key,const fnr_ssl_expanded_tweak *tweak,
        const void *plaintext, void *ciphertext) {
    FNR_SSL_operate( key, tweak, plaintext, ciphertext, 0, 1 );
}

void FNR_SSL_decrypt(const fnr_ssl_expanded_key *key,const fnr_ssl_expanded_tweak *tweak,
        const void *ciphertext, void *plaintext) {
    FNR_SSL_operate( key, tweak, ciphertext, plaintext, N_ROUND-1, -1 );
}

static fnr_ssl_expanded_key *fnr_ssl_key;
static fnr_ssl_expanded_tweak tweak;

void fnr_ssl_init() {
    unsigned char orig_key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
    char *tweak_str = "tweak";
    FNR_SSL_init();
    fnr_ssl_key = FNR_SSL_expand_key(orig_key, 128, 32);
    FNR_SSL_expand_tweak(&tweak, fnr_ssl_key, (void*)tweak_str, strlen(tweak_str));
}

void fnr_ssl_encrypt(void *ptxt, void *ctxt) {
    FNR_SSL_encrypt(fnr_ssl_key, &tweak, ptxt, ctxt);
}

void fnr_ssl_decrypt(void *ctxt, void *ptxt) {
    FNR_SSL_decrypt(fnr_ssl_key, &tweak, ptxt, ctxt);
}
