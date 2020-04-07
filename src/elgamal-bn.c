#include "elgamal-bn.h"
#include "pk.h"

static BIGNUM *sPre;
static BIGNUM *c1Pre;
static BIGNUM *threshold;

static void BN_mod_exp_neg(BIGNUM *res, const BIGNUM *base, const BIGNUM *exp, const BIGNUM *m,
                           BN_CTX *ctx) {

    BN_mod_exp(res, base, exp, m, ctx);

    if (BN_is_negative(exp))
        BN_mod_inverse(res, res, m, ctx);
}

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

    // n is a large prime
    BN_generate_prime_ex(sk->n, DEFAULT_KEY_LEN, 0, NULL, NULL, NULL);

    do {
        BN_rand_range(sk->x, sk->n);
    } while (BN_is_zero(sk->x));

    // g is the generator
    BN_generate_prime_ex(sk->g, DEFAULT_KEY_LEN, 0, NULL, NULL, NULL);

    // h = g^x (mod n)
    BN_mod_exp_neg(sk->h, sk->g, sk->x, sk->n, ctx);

    pk->n = BN_dup(sk->n);
    pk->g = BN_dup(sk->g);
    pk->h = BN_dup(sk->h);

    // PRECOMPUTATION
    BIGNUM *y = BN_CTX_get(ctx);

    do {
        BN_rand_range(y, pk->n);
    } while (BN_is_zero(y));

    sPre = BN_new();
    c1Pre = BN_new();
    BN_mod_exp_neg(sPre, pk->h, y, pk->n, ctx);
    BN_mod_exp_neg(c1Pre, pk->g, y, pk->n, ctx);

    BN_CTX_end(ctx);
}

void elgamal_bn_encrypt(BIGNUM *c1, BIGNUM *c2, BIGNUM *msg, elg_pk *pk, BN_CTX *ctx) {

    BN_CTX_start(ctx);

    BIGNUM *y, *s;
    y = BN_CTX_get(ctx);
    s = BN_CTX_get(ctx);

    do {
        BN_rand_range(y, pk->n);
    } while (BN_is_zero(y));

    // s = h^y (mod n)
    BN_mod_exp_neg(s, pk->h, y, pk->n, ctx);

    // c1 = g^y (mod n)
    BN_mod_exp_neg(c1, pk->g, y, pk->n, ctx);

    // c2 = msg * s mod n
    BN_mod_mul(c2, msg, s, pk->n, ctx);

    BN_CTX_end(ctx);
}

/**
 * Pre-computation
 */
void elgamal_bn_encrypt_pre(BIGNUM *c1, BIGNUM *c2, BIGNUM *msg, elg_pk *pk, BN_CTX *ctx) {

    BN_CTX_start(ctx);

    BN_copy(c1, c1Pre);

    // c2 = msg * s mod n
    BN_mod_mul(c2, msg, sPre, pk->n, ctx);

    BN_CTX_end(ctx);
}

void elgamal_bn_decrypt(BIGNUM *msg, BIGNUM *c1, BIGNUM *c2, elg_sk *sk, BN_CTX *ctx) {

    BN_CTX_start(ctx);

    BIGNUM *s, *inv_s;
    s = BN_CTX_get(ctx);
    inv_s = BN_CTX_get(ctx);

    // s = c1^x
    BN_mod_exp_neg(s, c1, sk->x, sk->n, ctx);

    // inv_s = s^{-1}
    BN_mod_inverse(inv_s, s, sk->n, ctx);

    // msg = c2 inv_s
    BN_mod_mul(msg, c2, inv_s, sk->n, ctx);

    // handle negative numbers
    if (BN_cmp(msg, threshold) > 0)
        BN_sub(msg, msg, sk->n);

    BN_CTX_end(ctx);
}
