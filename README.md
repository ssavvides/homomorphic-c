## PHE and PPE schemes

A collection of various Partially Homomorphic Encryption (PHE) schemes and Property-Preserving Encryption (PPE) schemes.

In some cases multiple implementations of the same encryption scheme are provided.

Currently the library contains

- AES
    - AES – using the [tiny-AES](https://github.com/kokke/tiny-AES-c/blob/master/aes.c) repo
    - AES-SSL  – using openSSL
- ElGamal
    - ElGamal-BD – using `BIGD` primitive of the [BigDigits library](https://www.di-mgt.com.au/bigdigits.html)
    - ElGamal-BN – using the `BIGNUM` library of openSSL
    - ElGamal-GMP – using the `mpz` primitive of the GMP library
- Paillier
    - Paillier-BD – using `BIGD` primitive of the [BigDigits library](https://www.di-mgt.com.au/bigdigits.html)
    - Paillier-BN – using `BIGNUM` library of openSSL
    - Paillier-GMP – using the `mpz` primitive of the GMP library and using [this](https://github.com/camillevuillaume/Paillier-GMP)
    repo as a reference

In some cases multiple encryption/decryption are explored.
- For both ElGamal and Paillier (all versions), we implement
`encrypt_pre` versions of encryption which assumes a random value has been pre-computed.
- For all versions of Paillier we alsi implement the `g = n + 1` optimization and the decryption
based on the Chinese Remainder Theorem `decreypt_crt`.
- For the `BN` and `GMP` versions of ElGamal and Paillier, support for negative numbers is
added. The BigDigits library does not support negative numbers.

Please note these are __Proof Of Concept__ implementations.
