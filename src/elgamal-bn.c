#include "pk.h"
#include "bn-ops.h"
#include "elgamal-bn.h"

static BIGNUM *sPre;
static BIGNUM *c1Pre;
static BIGNUM *threshold;

void elgamal_bn_init(elg_pk *pk, elg_sk *sk, BN_CTX *ctx) {

    BIGNUM *twoBN = BN_new();
    BN_set_word(twoBN, 2);

    BIGNUM *halfKeyBN = BN_new();
    BN_set_word(halfKeyBN, DECRYPTION_THRESHOLD);

    threshold = BN_new();
    BN_exp(threshold, twoBN, halfKeyBN, ctx);

    // init seed rand
    unsigned char buffer;
    RAND_bytes(&buffer, sizeof(buffer));
    srandom((int) buffer);

    BN_CTX_start(ctx);

    sk->n = BN_new();
    sk->g = BN_new();
    sk->h = BN_new();
    sk->x = BN_new();

    pk->n = BN_new();
    pk->g = BN_new();
    pk->h = BN_new();

    bn_prime(sk->n, DEFAULT_KEY_LEN);
    bn_rand(sk->x, DEFAULT_KEY_LEN, false);
    bn_prime(sk->g, DEFAULT_KEY_LEN);

    // h = g^x (mod n)
    bn_mod_exp_neg(sk->h, sk->g, sk->x, sk->n, ctx);

    pk->n = BN_dup(sk->n);
    pk->g = BN_dup(sk->g);
    pk->h = BN_dup(sk->h);

    // PRECOMPUTATION
    BIGNUM *y = BN_CTX_get(ctx);
    bn_rand(y, DEFAULT_KEY_LEN, false);

    sPre = BN_new();
    c1Pre = BN_new();
    bn_mod_exp_neg(sPre, pk->h, y, pk->n, ctx);
    bn_mod_exp_neg(c1Pre, pk->g, y, pk->n, ctx);

    BN_CTX_end(ctx);

    BN_free(twoBN);
    BN_free(halfKeyBN);
}

void elgamal_bn_encrypt(BIGNUM *c1, BIGNUM *c2, int msg, elg_pk *pk, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *y, *s, *ptxt;

    ptxt = BN_CTX_get(ctx);
    int_to_bn(ptxt, msg);

    y = BN_CTX_get(ctx);
    bn_rand(y, DEFAULT_KEY_LEN, false);

    s = BN_CTX_get(ctx);
    bn_mod_exp_neg(s, pk->h, y, pk->n, ctx);
    bn_mod_exp_neg(c1, pk->g, y, pk->n, ctx);
    BN_mod_mul(c2, ptxt, s, pk->n, ctx);

    BN_CTX_end(ctx);
}

/**
 * Pre-computation
 */
void elgamal_bn_encrypt_pre(BIGNUM *c1, BIGNUM *c2, int msg, elg_pk *pk, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    BIGNUM *ptxt;
    ptxt = BN_CTX_get(ctx);
    int_to_bn(ptxt, msg);

    BN_copy(c1, c1Pre);
    BN_mod_mul(c2, ptxt, sPre, pk->n, ctx);

    BN_CTX_end(ctx);
}

void elgamal_bn_decrypt(long* msg, BIGNUM *c1, BIGNUM *c2, elg_sk *sk, BN_CTX *ctx) {

    BN_CTX_start(ctx);
    BIGNUM *s, *inv_s, *ptxt;

    s = BN_CTX_get(ctx);
    bn_mod_exp_neg(s, c1, sk->x, sk->n, ctx);

    inv_s = BN_CTX_get(ctx);
    BN_mod_inverse(inv_s, s, sk->n, ctx);

    ptxt = BN_CTX_get(ctx);
    BN_mod_mul(ptxt, c2, inv_s, sk->n, ctx);

    // handle negative numbers
    if (BN_cmp(ptxt, threshold) > 0)
        BN_sub(ptxt, ptxt, sk->n);

    bn_to_long(msg, ptxt);

    BN_CTX_end(ctx);
}
