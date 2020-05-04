#include "pk.h"
#include "bd-ops.h"
#include "paillier-bd.h"

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
    privKey->p2 = bdNew();
    privKey->q2 = bdNew();
    privKey->p2invq2 = bdNew();
    do {
        // generate p and q
        bd_prime(p, DEFAULT_KEY_LEN / 2);
        bd_prime(q, DEFAULT_KEY_LEN / 2);

        bdMultiply(n, p, q);
        bdMultiply_s(privKey->p2, p, p);
        bdMultiply_s(privKey->q2, q, q);
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

        bd_L(tmp, tmp, n);

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
    bd_rand(rand, DEFAULT_KEY_LEN, false);

    pubKey->tmp2Pre = bdNew();
    bdModExp(pubKey->tmp2Pre, rand, pubKey->n, pubKey->n2);

    bdFree(&two);
    bdFree(&p);
    bdFree(&q);
    bdFree(&tmp);
    bdFree(&pqMult);
    bdFree(&gcd);
    bdFree(&rand);
}

void paillier_bd_encrypt(BIGD ctxt, int msg, const paillier_bd_pk *pubKey, bool precomputation) {
    BIGD ptxt = bdNew();
    int_to_bd(ptxt, msg);
    paillier_bd_encrypt_bd(ctxt, ptxt, pubKey, precomputation);
    bdFree(&ptxt);
}
void paillier_bd_encrypt_packed(BIGD ctxt, int* messages, int len,
        const paillier_bd_pk *pubKey, bool precomputation) {
    BIGD ptxt = bdNew();
    bd_pack(ptxt, DEFAULT_KEY_LEN, messages, len, true);
    paillier_bd_encrypt_bd(ctxt, ptxt, pubKey, precomputation);
    bdFree(&ptxt);
}
void paillier_bd_encrypt_bd(BIGD ctxt, BIGD ptxt, const paillier_bd_pk *pubKey,
        bool precomputation) {
    BIGD tmp1 = bdNew();
    bdMultiply(tmp1, ptxt, pubKey->n);
    bdShortAdd(tmp1, tmp1, 1);
    if (precomputation) {
        bdModMult(ctxt, tmp1, pubKey->tmp2Pre, pubKey->n2);
    } else {
        BIGD rnd = bdNew();
        bd_rand(rnd, DEFAULT_KEY_LEN, true);
        BIGD tmp2 = bdNew();
        bdModExp(tmp2, rnd, pubKey->n, pubKey->n2);
        bdModMult(ctxt, tmp1, tmp2, pubKey->n2);
        bdFree(&tmp2);
        bdFree(&rnd);
    }
    bdFree(&tmp1);
}

void paillier_bd_decrypt(long* msg, const BIGD ctxt, const paillier_bd_sk *key) {
    BIGD ptxt = bdNew();
    paillier_bd_decrypt_bd(ptxt, ctxt, key);
    bd_to_long(msg, ptxt);
    bdFree(&ptxt);
}
void paillier_bd_decrypt_packed(long* messages, const BIGD ctxt, const paillier_bd_sk *key) {
    BIGD ptxt = bdNew();
    paillier_bd_decrypt_bd(ptxt, ctxt, key);
    bd_unpack(messages, DEFAULT_KEY_LEN, ptxt, true, 0);
    bdFree(&ptxt);
}
void paillier_bd_decrypt_bd(BIGD ptxt, const BIGD ctxt, const paillier_bd_sk *key) {
    BIGD tmp = bdNew();
    bdModExp(tmp, ctxt, key->lamda, key->n2);
    BIGD u_cp = bdNew();
    bdShortAdd(u_cp, tmp, 1);
    BIGD res = bdNew();
    BIGD r = bdNew();
    bdDivide(res, r, u_cp, key->n);
    bdModMult(ptxt, res, key->mu, key->n);
    bdFree(&tmp);
    bdFree(&u_cp);
    bdFree(&res);
    bdFree(&r);
}

// this does not work
void paillier_bd_decrypt_crt(long* msg, const BIGD ctxt, const paillier_bd_sk *key) {
    // Compute the plaintext message as: m = L(c^lamda mod n2)*mu mod n
    BIGD tmp = bdNew();
    bd_crt_exponentiation(tmp, ctxt, key->lamda, key->lamda, key->p2invq2, key->p2, key->q2);
    bd_L(tmp, tmp, key->n);

    BIGD ptxt = bdNew();
    bdModMult(ptxt, tmp, key->mu, key->n);

    bd_to_long(msg, ptxt);

    bdFree(&tmp);
    bdFree(&ptxt);
}
