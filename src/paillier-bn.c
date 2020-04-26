#include "pk.h"
#include "bn-ops.h"
#include "paillier-bn.h"


void paillier_bn_init(paillier_bn_pk *pubKey, paillier_bn_sk *privKey, BN_CTX *ctx) {
    BIGNUM *twoBN = BN_new();
    BN_set_word(twoBN, 2);

    BIGNUM *halfKeyBN = BN_new();
    BN_set_word(halfKeyBN, DECRYPTION_THRESHOLD);

    threshold_bn = BN_new();
    BN_exp(threshold_bn, twoBN, halfKeyBN, ctx);

    // init seed rand
    unsigned char buffer;
    RAND_bytes(&buffer, sizeof(buffer));
    srandom((int) buffer);

    BN_CTX_start(ctx);
    BIGNUM *p = BN_CTX_get(ctx);
    BIGNUM *q = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);

    BIGNUM *n = BN_new();

    // loop until gcd(pq, (p-1)(q-1)) = 1
    do {
        // generate p and q
        bn_prime(p, DEFAULT_KEY_LEN / 2);
        bn_prime(q, DEFAULT_KEY_LEN / 2);

        // 2. Compute n = pq
        BN_mul(n, p, q, ctx);

        privKey->p2 = BN_new();
        BN_mul(privKey->p2, p, p, ctx);

        privKey->q2 = BN_new();
        BN_mul(privKey->q2, q, q, ctx);

        privKey->p2invq2 = BN_new();
        BN_mod_inverse(privKey->p2invq2, privKey->p2, privKey->q2, ctx);

        // p-1, q-1
        BN_sub_word(p, 1);
        BN_sub_word(q, 1);

        // (p-1)(q-1)
        BN_mul(tmp, p, q, ctx);

        // gcd(pq, (p-1)(q-1))
        BN_gcd(tmp, tmp, n, ctx);

    } while (BN_cmp(p, q) == 0 || !BN_is_one(tmp));

    //  lamda = lcm(p-1,q-1)
    BIGNUM *lamda = BN_new();
    bn_lcm(lamda, p, q, ctx);

    // n^2
    BIGNUM *n2 = BN_new();
    BN_mul(n2, n, n, ctx);

    BIGNUM *g;
    BIGNUM *mu = BN_new();

    do {
        // Select a random integer g mod n2 and greater than 0
        //do {
        //	if (!BN_rand_range(g, n2)) {
        //		ERR_load_crypto_strings();
        //		fprintf(stderr, "Error generating keys: %s",
        //				ERR_error_string(ERR_get_error(), NULL));
        //		exit (EXIT_FAILURE);
        //	}
        //} while (BN_is_zero(g));

        // set g = n+1
        g = BN_dup(n);
        BN_add_word(g, 1);

        // Ensure n divides the order of g
        bn_mod_exp_neg(tmp, g, lamda, n2, ctx);

        bn_L(tmp, tmp, n, ctx);

        BN_mod_inverse(mu, tmp, n, ctx);
    } while (mu == NULL);

    pubKey->n = n;
    pubKey->n2 = n2;
    pubKey->g = g;

    privKey->n = BN_dup(n);
    privKey->n2 = BN_dup(n2);
    privKey->lamda = lamda;
    privKey->mu = mu;

    // PRECOMPUTATION FOR ENCRYPTION: Select random r where r E Zn*
    BIGNUM *rand = BN_CTX_get(ctx);
    bn_rand(rand, DEFAULT_KEY_LEN, false);

    tmp2Pre = BN_new();
    bn_mod_exp_neg(tmp2Pre, rand, pubKey->n, pubKey->n2, ctx);
    BN_CTX_end(ctx);
}

void paillier_bn_encrypt1(BIGNUM *ctxt, int msg, const paillier_bn_pk *pubKey, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    BIGNUM * ptxt = BN_CTX_get(ctx);
    int_to_bn(ptxt, msg);

    // Select random r where r E Zn*
    BIGNUM *rand = BN_CTX_get(ctx);
    bn_rand(rand, DEFAULT_KEY_LEN, false);

    //  Compute ciphertext as c = g^m * r^n mod n^2
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    bn_mod_exp_neg(tmp1, pubKey->g, ptxt, pubKey->n2, ctx);

    BIGNUM *tmp2 = BN_CTX_get(ctx);
    bn_mod_exp_neg(tmp2, rand, pubKey->n, pubKey->n2, ctx);

    // set ciphertext
    BN_mod_mul(ctxt, tmp1, tmp2, pubKey->n2, ctx);

    BN_CTX_end(ctx);
}

/**
 * Use g = n+1 to replace 1 exponentiation with a multiplication
 */
void paillier_bn_encrypt(BIGNUM *ctxt, int msg, const paillier_bn_pk *pubKey, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    BIGNUM * ptxt = BN_CTX_get(ctx);
    int_to_bn(ptxt, msg);

    // Select random r where r E Zn*
    BIGNUM *rand = BN_CTX_get(ctx);
    bn_rand(rand, DEFAULT_KEY_LEN, false);

    //  OPTIMIZATION g=n+1
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BN_mul(tmp1, ptxt, pubKey->n, ctx);
    BN_add_word(tmp1, 1);

    BIGNUM *tmp2 = BN_CTX_get(ctx);
    bn_mod_exp_neg(tmp2, rand, pubKey->n, pubKey->n2, ctx);

    // set ciphertext
    BN_mod_mul(ctxt, tmp1, tmp2, pubKey->n2, ctx);

    BN_CTX_end(ctx);
}

/**
 * No random
 */
void paillier_bn_encrypt_pre1(BIGNUM *ctxt, int msg, const paillier_bn_pk *pubKey, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    BIGNUM * ptxt = BN_CTX_get(ctx);
    int_to_bn(ptxt, msg);

    BIGNUM *tmp1 = BN_CTX_get(ctx);
    bn_mod_exp_neg(tmp1, pubKey->g, ptxt, pubKey->n2, ctx);

    // set ciphertext
    BN_mod_mul(ctxt, tmp1, tmp2Pre, pubKey->n2, ctx);

    BN_CTX_end(ctx);
}

/**
 * Optimizations 2+3: No random and g=n+1
 */
void paillier_bn_encrypt_pre(BIGNUM *ctxt, int msg, const paillier_bn_pk *pubKey, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    BIGNUM * ptxt = BN_CTX_get(ctx);
    int_to_bn(ptxt, msg);

    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BN_mul(tmp1, ptxt, pubKey->n, ctx);
    BN_add_word(tmp1, 1);

    // set ciphertext
    BN_mod_mul(ctxt, tmp1, tmp2Pre, pubKey->n2, ctx);

    BN_CTX_end(ctx);
}

void paillier_bn_decrypt(long* msg, const BIGNUM *ctxt, const paillier_bn_sk *key, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    // Compute the plaintext message as: m = L(c^lamda mod n2)*mu mod n
    BIGNUM *tmp = BN_CTX_get(ctx);
    bn_mod_exp_neg(tmp, ctxt, key->lamda, key->n2, ctx);
    bn_L(tmp, tmp, key->n, ctx);

    BIGNUM *ptxt = BN_CTX_get(ctx);
    BN_mod_mul(ptxt, tmp, key->mu, key->n, ctx);

    // handle negative numbers
    if (BN_cmp(ptxt, threshold_bn) > 0)
        BN_sub(ptxt, ptxt, key->n);

    bn_to_long(msg, ptxt);

    BN_CTX_end(ctx);
}

/**
 * Using pre-computed n inverted for L function
 */
void paillier_bn_decrypt_crt(long *msg, const BIGNUM *ctxt, const paillier_bn_sk *key, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    // Compute the plaintext message as: m = L(c^lamda mod n2)*mu mod n
    BIGNUM *tmp = BN_CTX_get(ctx);
    bn_crt_exponentiation(tmp, ctxt, key->lamda, key->lamda, key->p2invq2, key->p2, key->q2, ctx);
    bn_L(tmp, tmp, key->n, ctx);

    BIGNUM *ptxt = BN_CTX_get(ctx);
    BN_mod_mul(ptxt, tmp, key->mu, key->n, ctx);

    // handle negative numbers
    if (BN_cmp(ptxt, threshold_bn) > 0)
        BN_sub(ptxt, ptxt, key->n);

    bn_to_long(msg, ptxt);

    BN_CTX_end(ctx);
}

void add_paillier_bn(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    if (!BN_mod_mul(result, a, b, n2, ctx)) {
        ERR_load_crypto_strings();
        fprintf(stderr, "add: %s", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }
    BN_CTX_end(ctx);
}

void sub_paillier_bn(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *b_inv = BN_CTX_get(ctx);
    if (!BN_mod_inverse(b_inv, b, n2, ctx)) {
        ERR_load_crypto_strings();
        fprintf(stderr, "sub: %s", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }
    if (!BN_mod_mul(result, a, b_inv, n2, ctx)) {
        ERR_load_crypto_strings();
        fprintf(stderr, "sub: %s", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }
    BN_CTX_end(ctx);
}

void mul_paillier_bn(BIGNUM *result, const BIGNUM *a, const BIGNUM *plain, const BIGNUM *n2, BN_CTX *ctx) {
    bn_mod_exp_neg(result, a, plain, n2, ctx);
}
