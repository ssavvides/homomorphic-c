#include "bn-ops.h"
#include "packing.h"


// LCM for BIGNUMs
void bn_lcm(BIGNUM *lambda, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    // get greatest common divisor
    BIGNUM *gcd = BN_CTX_get(ctx);
    if (!BN_gcd(gcd, a, b, ctx)) {
        ERR_load_crypto_strings();
        fprintf(stderr, "Error calculating lcm: %s", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    // perform a / gcd. pass NULL as second argument since we don't care about the remainder.
    BIGNUM *aOverGcd = BN_CTX_get(ctx);
    if (!BN_div(aOverGcd, NULL, a, gcd, ctx)) {
        ERR_load_crypto_strings();
        fprintf(stderr, "Error calculating lcm: %s", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    // set lambda
    if (!BN_mul(lambda, b, aOverGcd, ctx)) {
        ERR_load_crypto_strings();
        fprintf(stderr, "Error calculating lcm: %s", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    BN_CTX_end(ctx);
}

void bn_L(BIGNUM *res, const BIGNUM *u, const BIGNUM *n, BN_CTX *ctx) {
    BIGNUM *u_cp = BN_dup(u);
    BN_sub_word(u_cp, 1);
    BN_div(res, NULL, u_cp, n, ctx);
    BN_free(u_cp);
}

void bn_mod_exp_neg(BIGNUM *res, const BIGNUM *base, const BIGNUM *exp, const BIGNUM *m,
                           BN_CTX *ctx) {
    BN_mod_exp(res, base, exp, m, ctx);
    if (BN_is_negative(exp))
        BN_mod_inverse(res, res, m, ctx);
}

void bn_crt_exponentiation(BIGNUM *result, const BIGNUM *base, const BIGNUM *exp_p,
                           const BIGNUM *exp_q, const BIGNUM *pinvq, const BIGNUM *p, const BIGNUM *q,
                           BN_CTX *ctx) {
    // compute exponentiation modulo p
    BIGNUM *result_p = BN_CTX_get(ctx);
    BN_mod(result_p, base, p, ctx);
    bn_mod_exp_neg(result_p, result_p, exp_p, p, ctx);

    // compute exponentiation modulo q
    BIGNUM *result_q = BN_CTX_get(ctx);
    BN_mod(result_q, base, q, ctx);
    bn_mod_exp_neg(result_q, result_q, exp_q, q, ctx);

    // recombination
    BN_sub(result, result_q, result_p);
    BN_mul(result, result, p, ctx);
    BN_mul(result, result, pinvq, ctx);
    BN_add(result, result, result_p);


    BIGNUM *pq = BN_CTX_get(ctx);
    BN_mul(pq, p, q, ctx);
    BN_mod(result, result, pq, ctx);
    // mod can return negative in BIGNUM
    if (BN_is_negative(result))
        BN_add(result, result, pq);
}

void bn_prime(BIGNUM* prime, int len) {
    BN_generate_prime_ex(prime, len, 0, NULL, NULL, NULL);
}

void bn_rand(BIGNUM* rnd, int bits, bool can_be_zero) {
    do {
        BN_rand(rnd, bits, 0, 0);
        if (can_be_zero)
            break;
    } while (BN_is_zero(rnd));
}

void int_to_bn(BIGNUM* res, int number) {
    char str[10];
    sprintf(str, "%d", number);
    BN_dec2bn(&res, str);
}

void bn_to_long(long* res, BIGNUM* number) {
    char *s = BN_bn2dec(number);
    *res = strtol(s, (char **)NULL, 10);
}

void bn_pack(BIGNUM* packed_messages, int ctxt_bits, int* messages, int len,
        bool ahe, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    int ptxt_bits = sizeof(int) * 8;
    int total_bits = total_packing_bits(ptxt_bits, ahe);
    int items = items_per_ctxt(ptxt_bits, ahe);

    if (len > items) {
        printf("Too many items to pack.\n");
        exit(EXIT_FAILURE);
    }

    BIGNUM* two = BN_CTX_get(ctx);
    BN_set_word(two, 2);
    BIGNUM* bits = BN_CTX_get(ctx);
    BN_set_word(bits, total_bits);
    BIGNUM* shift = BN_CTX_get(ctx);
    BN_exp(shift, two, bits, ctx);

    BIGNUM* message = BN_CTX_get(ctx);
    BN_set_word(packed_messages, 0);
    for (int i = 0; i < len; i++) {
        BN_mul(packed_messages, packed_messages, shift, ctx);
        int_to_bn(message, messages[i]);
        BN_add(packed_messages, packed_messages, message);
    }

    BN_CTX_end(ctx);
}

void bn_unpack(long* messages, int ctxt_bits, BIGNUM* packed_messages,
        bool ahe, int mhe_ops, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    int ptxt_bits = sizeof(int) * 8;
    int total_bits = total_packing_bits(ptxt_bits, ahe);
    int items = items_per_ctxt(ptxt_bits, ahe);

    BIGNUM* two = BN_CTX_get(ctx);
    BN_set_word(two, 2);
    BIGNUM* bits = BN_CTX_get(ctx);
    BN_set_word(bits, total_bits);
    BIGNUM* shift = BN_CTX_get(ctx);
    BN_exp(shift, two, bits, ctx);

    BIGNUM* message = BN_CTX_get(ctx);
    for (int i = 0; i < items; i++) {
        BN_mod(message, packed_messages, shift, ctx);
        bn_to_long(&messages[items - i - 1], message);
        BN_div(packed_messages, NULL, packed_messages, shift, ctx);

        // skip MHE intermediate values
        for (int j = 0; !ahe && j < mhe_ops; j++)
            BN_div(packed_messages, NULL, packed_messages, shift, ctx);
    }
    BN_CTX_end(ctx);
}
