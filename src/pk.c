#include "pk.h"

bool is_ahe(scheme_t scheme) {
    return scheme == paillier_scheme;
}

void init_schemes(BN_CTX *ctx) {
    paillier_bd_init(&pail_bd_pk, &pail_bd_sk);
    pail_bd_ctxt = bdNew();

    paillier_bn_init(&pail_bn_pk, &pail_bn_sk, ctx);
    pail_bn_ctxt = BN_CTX_get(ctx);

    paillier_gmp_init(&pail_gmp_pk, &pail_gmp_sk);
    mpz_init(pail_gmp_ctxt);

    elgamal_bd_init(&elg_bd_pk, &elg_bd_sk);
    elgamal_bd_ctxt_init(&elg_bd_ctxt);

    elgamal_bn_init(&elg_bn_pk, &elg_bn_sk, ctx);
    elgamal_bn_ctxt_init(&elg_bn_ctxt, ctx);

    elgamal_gmp_init(&elg_gmp_pk, &elg_gmp_sk);
    elgamal_gmp_ctxt_init(&elg_gmp_ctxt);
}

void encrypt(scheme_t scheme, library_t library, int ptxt,
		bool precomputation, BN_CTX *ctx) {
	if(scheme == paillier_scheme) {
        if(library == bigdigits_lib) {
            paillier_bd_encrypt(pail_bd_ctxt, ptxt, &pail_bd_pk, precomputation);
        } else if(library == ssl_lib) {
            paillier_bn_encrypt(pail_bn_ctxt, ptxt, &pail_bn_pk, precomputation, ctx);
        } else if(library == gmp_lib) {
            paillier_gmp_encrypt(pail_gmp_ctxt, ptxt, &pail_gmp_pk, precomputation);
        }
    } else if(scheme == elgamal_scheme) {
        if(library == bigdigits_lib) {
            elgamal_bd_encrypt(&elg_bd_ctxt, ptxt, &elg_bd_pk, precomputation);
        } else if(library == ssl_lib) {
            elgamal_bn_encrypt(&elg_bn_ctxt, ptxt, &elg_bn_pk, precomputation, ctx);
        } else if(library == gmp_lib) {
            elgamal_gmp_encrypt(&elg_gmp_ctxt, ptxt, &elg_gmp_pk, precomputation);
        }
    }
}

void decrypt(scheme_t scheme, library_t library, long* decr, BN_CTX *ctx) {
	if(scheme == paillier_scheme) {
        if(library == bigdigits_lib) {
            paillier_bd_decrypt(decr, pail_bd_ctxt, &pail_bd_sk);
        } else if(library == ssl_lib) {
            paillier_bn_decrypt(decr, pail_bn_ctxt, &pail_bn_sk, ctx);
        } else if(library == gmp_lib) {
            paillier_gmp_decrypt(decr, pail_gmp_ctxt, &pail_gmp_sk);
        }
    } else if(scheme == elgamal_scheme) {
        if(library == bigdigits_lib) {
            elgamal_bd_decrypt(decr, &elg_bd_ctxt, &elg_bd_sk);
        } else if(library == ssl_lib) {
            elgamal_bn_decrypt(decr, &elg_bn_ctxt, &elg_bn_sk, ctx);
        } else if(library == gmp_lib) {
            elgamal_gmp_decrypt(decr, &elg_gmp_ctxt, &elg_gmp_sk);
        }
    }
}

void encrypt_packed(scheme_t scheme, library_t library, int* ptxts, int items,
		bool precomputation, BN_CTX *ctx) {
	if(scheme == paillier_scheme) {
        if(library == bigdigits_lib) {
            paillier_bd_encrypt_packed(pail_bd_ctxt, ptxts, items,
                &pail_bd_pk, precomputation);
        } else if(library == ssl_lib) {
            paillier_bn_encrypt_packed(pail_bn_ctxt, ptxts, items,
                &pail_bn_pk, precomputation, ctx);
        } else if(library == gmp_lib) {
            paillier_gmp_encrypt_packed(pail_gmp_ctxt, ptxts, items,
                &pail_gmp_pk, precomputation);
        }
    } else if(scheme == elgamal_scheme) {
        if(library == bigdigits_lib) {
            elgamal_bd_encrypt_packed(&elg_bd_ctxt, ptxts, items,
                &elg_bd_pk, precomputation);
        } else if(library == ssl_lib) {
            elgamal_bn_encrypt_packed(&elg_bn_ctxt, ptxts, items,
                &elg_bn_pk, precomputation, ctx);
        } else if(library == gmp_lib) {
            elgamal_gmp_encrypt_packed(&elg_gmp_ctxt, ptxts, items,
                &elg_gmp_pk, precomputation);
        }
    }
}

void decrypt_packed(scheme_t scheme, library_t library, long* decrs, BN_CTX *ctx) {
    if(scheme == paillier_scheme) {
        if(library == bigdigits_lib) {
            paillier_bd_decrypt_packed(decrs, pail_bd_ctxt, &pail_bd_sk);
        } else if(library == ssl_lib) {
            paillier_bn_decrypt_packed(decrs, pail_bn_ctxt, &pail_bn_sk, ctx);
        } else if(library == gmp_lib) {
            paillier_gmp_decrypt_packed(decrs, pail_gmp_ctxt, &pail_gmp_sk);
        }
    } else if(scheme == elgamal_scheme) {
        if(library == bigdigits_lib) {
            elgamal_bd_decrypt_packed(decrs, &elg_bd_ctxt, &elg_bd_sk);
        } else if(library == ssl_lib) {
            elgamal_bn_decrypt_packed(decrs, &elg_bn_ctxt, &elg_bn_sk, ctx);
        } else if(library == gmp_lib) {
            elgamal_gmp_decrypt_packed(decrs, &elg_gmp_ctxt, &elg_gmp_sk);
        }
    }
}

