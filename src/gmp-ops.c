#include "gmp-ops.h"
#include "packing.h"

void gmp_prime(mpz_t prime, gmp_randstate_t seed, mp_bitcnt_t len) {
    mpz_t rnd;
    mpz_init(rnd);
    mpz_urandomb(rnd, seed, len);
    mpz_setbit(rnd, len - 1);
    mpz_nextprime(prime, rnd);
    mpz_clear(rnd);
}

void gmp_rand(mpz_t rnd, gmp_randstate_t seed, const mpz_t range, bool can_be_zero) {
    do {
        mpz_urandomm(rnd, seed, range);
        if (can_be_zero)
            break;
    } while (mpz_cmp_si(rnd, 0) == 0);
}

int gmp_crt_exponentiation(mpz_t result, const mpz_t base, const mpz_t exp_p, const mpz_t exp_q,
                       const mpz_t pinvq, const mpz_t p, const mpz_t q) {
    //compute exponentiation modulo p
    mpz_t result_p;
    mpz_init(result_p);
    mpz_mod(result_p, base, p);
    mpz_powm(result_p, result_p, exp_p, p);

    //compute exponentiation modulo q
    mpz_t result_q;
    mpz_init(result_q);
    mpz_mod(result_q, base, q);
    mpz_powm(result_q, result_q, exp_q, q);

    //recombination
    mpz_sub(result, result_q, result_p);
    mpz_mul(result, result, p);
    mpz_mul(result, result, pinvq);
    mpz_add(result, result, result_p);

    mpz_t pq;
    mpz_init(pq);
    mpz_mul(pq, p, q);
    mpz_mod(result, result, pq);

    return 0;
}

void gmp_L(mpz_t res, const mpz_t u, const mpz_t n) {
    mpz_sub_ui(res, u, 1);
    mpz_div(res, res, n);
}

void gmp_L2(mpz_t result, const mpz_t input, const mpz_t ninv, mpz_t mask) {
    mpz_sub_ui(result, input, 1);
    mpz_mul(result, result, ninv);
    mpz_and(result, result, mask);
}

void gmp_pack(mpz_t packed_messages, int ctxt_bits, int* messages, int len,
        bool ahe) {
    int ptxt_bits = sizeof(int) * 8;
    int total_bits = total_packing_bits(ptxt_bits, ahe);
    int items = items_per_ctxt(ptxt_bits, ahe);

    if (len > items) {
        printf("Too many items to pack.\n");
        exit(EXIT_FAILURE);
    }

    mpz_t shift;
    mpz_init(shift);
    mpz_ui_pow_ui(shift, 2, total_bits);

    mpz_set_si(packed_messages, 0);
    for (int i = 0; i < len; i++) {
        mpz_mul(packed_messages, packed_messages, shift);
        mpz_add_ui(packed_messages, packed_messages, messages[i]);
    }

    mpz_clear(shift);
}

void gmp_unpack(long* messages, int ctxt_bits, mpz_t packed_messages, bool ahe,
        int mhe_ops) {
    int ptxt_bits = sizeof(int) * 8;
    int total_bits = total_packing_bits(ptxt_bits, ahe);
    int items = items_per_ctxt(ptxt_bits, ahe);

    mpz_t shift;
    mpz_init(shift);
    mpz_ui_pow_ui(shift, 2, total_bits);

    mpz_t message;
    mpz_init(message);
    for (int i = 0; i < items; i++) {
        mpz_mod(message, packed_messages, shift);
        messages[items - i - 1] = mpz_get_si(message);
        mpz_div(packed_messages, packed_messages, shift);

        // skip MHE intermediate values
        for (int j = 0; !ahe && j < mhe_ops; j++)
            mpz_div(packed_messages, packed_messages, shift);
    }

    mpz_clear(shift);
    mpz_clear(message);
}
