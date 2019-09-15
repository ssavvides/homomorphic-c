## PHE and PPE schemes

A collection of various Partially Homomorphic Encryption (PHE) schemes and Property-Preserving Encryption (PPE) schemes.

In some cases multiple implementations of the same encryption scheme are provided.

Currently the library contains implementations of:

- AES
    - AES – using the [tiny-AES](https://github.com/kokke/tiny-AES-c/blob/master/aes.c) repo
    - AES-SSL  – using the openSSL implementation
- ElGamal
    - ElGamal-BD – using the `BIGD` primitive of the [BigDigits](https://www.di-mgt.com.au/bigdigits.html) library
    - ElGamal-BN – using the `BIGNUM` primitive of the [openSSL](https://www.openssl.org/) library
    - ElGamal-GMP – using the `mpz` primitive of the [GMP](https://gmplib.org/) library
- Paillier
    - Paillier-BD – using the `BIGD` primitive of the [BigDigits](https://www.di-mgt.com.au/bigdigits.html) library
    - Paillier-BN – using the `BIGNUM` primitive of the [openSSL](https://www.openssl.org/) library
    - Paillier-GMP – using the `mpz` primitive of the [GMP](https://gmplib.org/) library and using [this repo](https://github.com/camillevuillaume/Paillier-GMP) as a reference

In some cases multiple encryption/decryption are explored.
- For all versions of ElGamal and Paillier, we implement `encrypt_pre` versions of encryption which assumes a random value has been pre-computed.
- For all versions of Paillier we also implement the `g = n + 1` optimization and the decryption based on the Chinese Remainder Theorem `decrypt_crt`.
- For the `BN` and `GMP` versions of ElGamal and Paillier, support for negative numbers is added. The BigDigits library does not support negative numbers.

Please note these are **_Proof Of Concept_** implementations.
