# Underlying Sigma-Protocols
> Nhan_laptop
>---

> Resource: https://eprint.iacr.org/2021/060.pdf

## Motivation and overview 

In Viet Nam, there is exist a beautiful sentence: "Vạn sự tùy duyên". It means that everything is up to fate. In the world of cryptography, we can say that "Vạn sự tùy duyên" is the principle of "security by design". It means that the security of a cryptographic protocol should not rely on the secrecy of its design,

In this section, I will introduce the underlying Sigma-protocols that are used in the construction of the main protocol. These Sigma-protocols are the building blocks of the main protocol and are essential for its security.

This Project is very special to me because it is the first time I've code with Rust and the last time I've code by myself. 

Although I've can not almost finish the whole protocol, I've tried my best to implement the underlying Sigma-protocols. I hope that this implementation can be useful for other researchers who want to learn about Sigma-protocols and their applications in cryptography.

## Sigma-protocols implementation 

My implementation of the underlying Sigma-protocols is based on the paper "Sigma-Protocols for Proofs of Knowledge and their Applications to Cryptographic Protocols" by Shafi Goldwasser, Silvio Micali, and Charles Rackoff. The paper introduces a general framework for constructing Sigma-protocols and provides several examples of such protocols.


The Sigma-protocols that I have implemented:
```
.
├── Readme.md
└── SigmaProtocol
    ├── Cargo.toml
    └── src
        ├── crypto
        │   ├── ecdsa
        │   │   ├── EllipticCurve.rs
        │   │   ├── ecdsa.rs
        │   │   └── mod.rs
        │   ├── hash
        │   │   ├── mod.rs
        │   │   └── sha256.rs
        │   ├── mod.rs
        │   ├── paillier.rs
        │   └── pedersen.rs
        ├── main.rs
        ├── storage
        │   ├── Load_privkey_p_q.rs
        │   ├── Load_public_params.rs
        │   ├── mod.rs
        │   ├── public_params.json
        │   ├── public_prover_paillier.json
        │   ├── range_params.json
        │   ├── secret.rs
        │   ├── secret_params.json
        │   ├── secret_prover_paillier.json
        │   ├── setup.rs
        │   └── setup_paillier_secret.rs
        ├── utils
        │   ├── mod.rs
        │   ├── random.rs
        │   └── rustcryptodome
        │       ├── mod.rs
        │       └── number.rs
        └── zkproofs
            ├── mod.rs
            ├── modulus_zk_proof
            │   ├── challenge.rs
            │   ├── mod.rs
            │   ├── prover.rs
            │   └── verifier.rs
            ├── pederson_zk_proof
            │   ├── challenge.rs
            │   ├── mod.rs
            │   ├── prover.rs
            │   └── verifier.rs
            └── range_zk_proof
                ├── challenge.rs
                ├── mod.rs
                ├── prover.rs
                └── verifier.rs
```

The special thing about this implementation is that I have tried to recreate the utils and crypto modules by myself, without using any external libraries. This is because I want to understand the underlying mathematics and algorithms of the Sigma-protocols, rather than just using a library that abstracts away the details.