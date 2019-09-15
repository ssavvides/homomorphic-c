#include "paillier-bd.h"
#include "pk.h"

static void L_bd(BIGD res, const BIGD u, const BIGD n) {
    BIGD u_cp = bdNew();
    bdShortSub(u_cp, u, 1);
    BIGD r = bdNew();
    bdDivide(res, r, u_cp, n);
}

void crt_exponentiation_bd(BIGD result, const BIGD base,
                           const BIGD exp_p, const BIGD exp_q, const BIGD pinvq, const BIGD p, const BIGD q) {
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
}

void paillier_bd_init(paillier_bd_pk *pubKey, paillier_bd_sk *privKey) {
    BIGD two = bdNew();
    bdSetShort(two, 2);
    threshold_bd = bdNew();
    bdPower(threshold_bd, two, DECRYPTION_THRESHOLD);

    BIGD p = bdNew();
    BIGD q = bdNew();
    BIGD tmp = bdNew();
    BIGD n = bdNew();
    BIGD pqMult = bdNew(); // helper

    // loop until gcd(pq, (p-1)(q-1)) = 1
    do {
        // generate p and q
        bdGeneratePrime(p, DEFAULT_KEY_LEN / 2, 2, (const unsigned char *) "1", 1, bdRandomOctets);
        bdGeneratePrime(q, DEFAULT_KEY_LEN / 2, 2, (const unsigned char *) "1", 1, bdRandomOctets);

        // 2. Compute n = pq
        bdMultiply(n, p, q);

        privKey->p2 = bdNew();
        bdMultiply_s(privKey->p2, p, p);

        privKey->q2 = bdNew();
        bdMultiply_s(privKey->q2, q, q);

        privKey->p2invq2 = bdNew();
        bdModInv(privKey->p2invq2, privKey->p2, privKey->q2);

        // p-1, q-1
        bdShortSub(p, p, 1);
        bdShortSub(q, q, 1);
        bdMultiply_s(pqMult, p, q);
        bdGcd(tmp, pqMult, n);
        bdShortSub(tmp, tmp, 1);

    } while (bdCompare(p, q) == 0 || !bdIsZero(tmp));

    //  lamda = lcm(p-1,q-1)
    BIGD lamda = bdNew();

    // lcm(a, b) = ab/gcd(a, b)
    BIGD gcd = bdNew();
    bdGcd(gcd, p, q);
    BIGD r = bdNew();
    bdDivide(lamda, r, pqMult, gcd);

    // n^2
    BIGD n2 = bdNew();
    bdMultiply_s(n2, n, n);

    BIGD g = bdNew();
    BIGD mu = bdNew();

    int res = 0;
    do {

        // set g = n+1
        bdShortAdd(g, n, 1);

        // Ensure n divides the order of g
        bdModExp(tmp, g, lamda, n2);

        L_bd(tmp, tmp, n);

        res = bdModInv(mu, tmp, n);
    } while (res != 0);

    pubKey->n = n;
    pubKey->n2 = n2;
    pubKey->g = g;

    privKey->n = bdNew();
    privKey->n2 = bdNew();
    bdSetEqual(privKey->n, pubKey->n);
    bdSetEqual(privKey->n2, pubKey->n2);
    privKey->lamda = lamda;
    privKey->mu = mu;

    // PRECOMPUTATION FOR ENCRYPTION: Select random r where r E Zn*
    BIGD rand = bdNew();
    do {
        bdQuickRandBits(rand, DEFAULT_KEY_LEN);
    } while (bdIsZero(rand));

    pubKey->tmp2Pre = bdNew();
    bdModExp(pubKey->tmp2Pre, rand, pubKey->n, pubKey->n2);
}

void paillier_bd_encrypt(BIGD ctxt, const BIGD ptxt, const paillier_bd_pk *pubKey) {

    // OPT: g = n+1
    BIGD tmp1 = bdNew();
    bdMultiply(tmp1, ptxt, pubKey->n);
    bdShortAdd(tmp1, tmp1, 1);

    // generate random number
    BIGD randBN = bdNew();
    bdQuickRandBits(randBN, DEFAULT_KEY_LEN);

    BIGD tmp2 = bdNew();
    bdModExp(tmp2, randBN, pubKey->n, pubKey->n2);

    bdModMult(ctxt, tmp1, tmp2, pubKey->n2);
}

void paillier_bd_encrypt_pre(BIGD ctxt, const BIGD ptxt, const paillier_bd_pk *pubKey) {

    BIGD tmp1 = bdNew();
    bdMultiply(tmp1, ptxt, pubKey->n);
    bdShortAdd(tmp1, tmp1, 1);

    // set ciphertext
    bdModMult(ctxt, tmp1, pubKey->tmp2Pre, pubKey->n2);
}

void paillier_bd_decrypt(BIGD ptxt, const BIGD ctxt, const paillier_bd_sk *key) {
    // Compute the plaintext message as: m = L(c^lamda mod n2)*mu mod n
    BIGD tmp = bdNew();
    bdModExp(tmp, ctxt, key->lamda, key->n2);
    BIGD u_cp = bdNew();
    bdShortAdd(u_cp, tmp, 1);
    BIGD res = bdNew();
    BIGD r = bdNew();
    bdDivide(res, r, u_cp, key->n);
    bdModMult(ptxt, res, key->mu, key->n);
}

void paillier_bd_decrypt_crt(BIGD ptxt, const BIGD ctxt, const paillier_bd_sk *key) {
    // Compute the plaintext message as: m = L(c^lamda mod n2)*mu mod n
    BIGD tmp = bdNew();
    crt_exponentiation_bd(tmp, ctxt, key->lamda, key->lamda, key->p2invq2, key->p2, key->q2);
    L_bd(tmp, tmp, key->n);
    bdModMult(ptxt, tmp, key->mu, key->n);
}
