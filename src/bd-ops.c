#include "bd-ops.h"
#include "packing.h"

void bd_L(BIGD res, const BIGD u, const BIGD n) {
    BIGD u_cp = bdNew();
    bdShortSub(u_cp, u, 1);
    BIGD r = bdNew();
    bdDivide(res, r, u_cp, n);

    bdFree(&u_cp);
    bdFree(&r);
}

void bd_crt_exponentiation(BIGD result, const BIGD base,
                           const BIGD exp_p, const BIGD exp_q, const BIGD pinvq,
                           const BIGD p, const BIGD q) {
    // compute exponentiation modulo p
    BIGD result_p = bdNew();
    bdModulo(result_p, base, p);
    bdModExp(result_p, result_p, exp_p, p);

    // compute exponentiation modulo q
    BIGD result_q = bdNew();
    bdModulo(result_q, base, q);
    bdModExp(result_q, result_q, exp_q, q);

    // recombination

    BIGD pq = bdNew();
    bdMultiply(pq, p, q);
    // BD does not handle negative
    if (bdCompare(result_p, result_q) > 0)
        bdAdd_s(result_q, result_q, pq);
    bdSubtract(result, result_q, result_p);
    bdMultiply_s(result, result, p);
    bdMultiply_s(result, result, pinvq);
    bdAdd_s(result, result, result_p);

    bdModulo(result, result, pq);

    bdFree(&result_p);
    bdFree(&result_q);
    bdFree(&pq);
}

void bd_prime(BIGD prime, int len) {
	bdGeneratePrime(prime, len, 1,
		(const unsigned char *) "1", 1, bdRandomOctets);
}

void bd_rand(BIGD rnd, int range, bool can_be_zero) {
	do {
        bdQuickRandBits(rnd, range);
        if (can_be_zero)
	        break;
    } while (bdIsZero(rnd));
}

void int_to_bd(BIGD res, int number) {
    char str[10];
    sprintf(str, "%d", number);
    bdConvFromDecimal(res, str);
}

void bd_to_long(long* res, BIGD number) {
    char *s;
    size_t nchars = bdConvToDecimal(number, NULL, 0);
    s = malloc(nchars + 1);
    nchars = bdConvToDecimal(number, s, nchars + 1);
    *res = strtol(s, (char **)NULL, 10);
}

void bd_pack(BIGD packed_messages, int ctxt_bits, int* messages, int len,
        bool ahe) {
    int ptxt_bits = sizeof(int) * 8;
    int total_bits = total_packing_bits(ptxt_bits, ahe);
    int items = items_per_ctxt(ptxt_bits, ahe);

    if (len > items) {
        printf("Too many items to pack.\n");
        exit(EXIT_FAILURE);
    }

    BIGD two = bdNew();
    bdSetShort(two, 2);
    BIGD shift = bdNew();
    bdPower(shift, two, total_bits);

    BIGD message = bdNew();
    bdSetShort(packed_messages, 0);
    for (int i = 0; i < len; i++) {
        bdMultiply_s(packed_messages, packed_messages, shift);
        int_to_bd(message, messages[i]);
        bdAdd_s(packed_messages, packed_messages, message);
    }

    bdFree(&two);
    bdFree(&shift);
    bdFree(&message);
}

void bd_unpack(long* messages, int ctxt_bits, BIGD packed_messages, bool ahe,
        int mhe_ops) {
    int ptxt_bits = sizeof(int) * 8;
    int total_bits = total_packing_bits(ptxt_bits, ahe);
    int items = items_per_ctxt(ptxt_bits, ahe);

    BIGD two = bdNew();
    bdSetShort(two, 2);
    BIGD shift = bdNew();
    bdPower(shift, two, total_bits);

    BIGD message = bdNew();
    BIGD r = bdNew();
    for (int i = 0; i < items; i++) {
        bdModulo(message, packed_messages, shift);
        bd_to_long(&messages[items - i - 1], message);
        bdDivide_s(packed_messages, r, packed_messages, shift);

        // skip MHE intermediate values
        for (int j = 0; !ahe && j < mhe_ops; j++)
            bdDivide_s(packed_messages, r, packed_messages, shift);
    }

    bdFree(&two);
    bdFree(&shift);
    bdFree(&message);
    bdFree(&r);
}
