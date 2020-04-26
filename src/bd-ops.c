#include "bd-ops.h"

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
