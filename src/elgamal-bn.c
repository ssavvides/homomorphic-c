#include "pk.h"
#include "bn-ops.h"
#include "elgamal-bn.h"

static BIGNUM *sPre;
static BIGNUM *c1Pre;
static BIGNUM *threshold;

void elgamal_bn_ctxt_init(elgamal_bn_ctxt* ctxt, BN_CTX *ctx) {
    ctxt->packed_ops = 0;
    ctxt->c1 = BN_CTX_get(ctx);
    ctxt->c2 = BN_CTX_get(ctx);
}

void elgamal_bn_init(elgamal_bn_pk *pk, elgamal_bn_sk *sk, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    BIGNUM *twoBN = BN_CTX_get(ctx);
    BN_set_word(twoBN, 2);

    BIGNUM *halfKeyBN = BN_CTX_get(ctx);
    BN_set_word(halfKeyBN, DECRYPTION_THRESHOLD);

    threshold = BN_new();
    BN_exp(threshold, twoBN, halfKeyBN, ctx);

    // init seed rand
    unsigned char buffer;
    RAND_bytes(&buffer, sizeof(buffer));
    srandom((int) buffer);


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

    // pre-computation
    BIGNUM *y = BN_CTX_get(ctx);
    bn_rand(y, DEFAULT_KEY_LEN, false);

    sPre = BN_new();
    c1Pre = BN_new();
    bn_mod_exp_neg(sPre, pk->h, y, pk->n, ctx);
    bn_mod_exp_neg(c1Pre, pk->g, y, pk->n, ctx);

    BN_CTX_end(ctx);
}

void elgamal_bn_encrypt(elgamal_bn_ctxt* ctxt, int msg, elgamal_bn_pk *pk,
        bool precomptation, BN_CTX *ctx) {
    BIGNUM *ptxt = BN_new();
    int_to_bn(ptxt, msg);
    elgamal_bn_encrypt_bn(ctxt, ptxt, pk, precomptation, ctx);
    BN_free(ptxt);
}
void elgamal_bn_encrypt_packed(elgamal_bn_ctxt* ctxt, int* messages, int len,
        elgamal_bn_pk *pk, bool precomptation, BN_CTX *ctx) {
    BIGNUM *ptxt = BN_new();
    bn_pack(ptxt, DEFAULT_KEY_LEN, messages, len, false, ctx);
    elgamal_bn_encrypt_bn(ctxt, ptxt, pk, precomptation, ctx);
    BN_free(ptxt);
}
void elgamal_bn_encrypt_bn(elgamal_bn_ctxt* ctxt, BIGNUM *ptxt,
        elgamal_bn_pk *pk, bool precomptation, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    if (precomptation) {
        BN_copy(ctxt->c1, c1Pre);
        BN_mod_mul(ctxt->c2, ptxt, sPre, pk->n, ctx);
    } else {
        BIGNUM *rnd = BN_CTX_get(ctx);
        bn_rand(rnd, DEFAULT_KEY_LEN, false);
        bn_mod_exp_neg(ctxt->c1, pk->g, rnd, pk->n, ctx);
        BIGNUM *s = BN_CTX_get(ctx);
        bn_mod_exp_neg(s, pk->h, rnd, pk->n, ctx);
        BN_mod_mul(ctxt->c2, ptxt, s, pk->n, ctx);
    }
    BN_CTX_end(ctx);
}

void elgamal_bn_decrypt(long* msg, elgamal_bn_ctxt* ctxt, elgamal_bn_sk *sk,
        BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *ptxt = BN_CTX_get(ctx);
    elgamal_bn_decrypt_bn(ptxt, ctxt, sk, ctx);

    // handle negative numbers
    if (BN_cmp(ptxt, threshold) > 0)
        BN_sub(ptxt, ptxt, sk->n);

    bn_to_long(msg, ptxt);
    BN_CTX_end(ctx);
}
void elgamal_bn_decrypt_packed(long* messages, elgamal_bn_ctxt* ctxt,
        elgamal_bn_sk *sk, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *packed_messages = BN_CTX_get(ctx);
    elgamal_bn_decrypt_bn(packed_messages, ctxt, sk, ctx);
    bn_unpack(messages, DEFAULT_KEY_LEN, packed_messages, false,
        ctxt->packed_ops, ctx);
    BN_CTX_end(ctx);
}
void elgamal_bn_decrypt_bn(BIGNUM* ptxt, elgamal_bn_ctxt* ctxt,
        elgamal_bn_sk *sk, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *s, *inv_s;
    s = BN_CTX_get(ctx);
    bn_mod_exp_neg(s, ctxt->c1, sk->x, sk->n, ctx);
    inv_s = BN_CTX_get(ctx);
    BN_mod_inverse(inv_s, s, sk->n, ctx);
    BN_mod_mul(ptxt, ctxt->c2, inv_s, sk->n, ctx);
    BN_CTX_end(ctx);
}
