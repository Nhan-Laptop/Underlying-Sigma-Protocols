use num_bigint::BigUint;
use serde::{Serialize, Deserialize};
use std::fs;
use crate::utils::rustcryptodome::number;



use std::fs::File;
use std::io::Write;

pub struct PaillierProverSecret {
    pub p: BigUint,
    pub q: BigUint,
    pub N0: BigUint,
}

#[derive(Serialize, Deserialize)]
pub struct PaillierPublic {
    pub N0: BigUint,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct PaillierPrivate {
    pub p: BigUint,
    pub q: BigUint,
}

impl PaillierProverSecret {
    
    pub fn new(bits: Option<usize>) -> Self {
        let bit_length = bits.unwrap_or(3072) / 2;
        
        // Generate primes p, q ≡ 3 mod 4 for easy 4th root computation
        let p = Self::get_prime_3_mod_4(bit_length);
        let q = Self::get_prime_3_mod_4(bit_length);
        let N0 = &p * &q;

        PaillierProverSecret {
            p,
            q,
            N0,
        }
    }
    
    /// Generate a prime p such that p ≡ 3 mod 4
    /// This allows easy square root computation: sqrt(y) = y^((p+1)/4) mod p
    fn get_prime_3_mod_4(bit_length: usize) -> BigUint {
        loop {
            let p = number::get_prime(bit_length).to_biguint().unwrap();
            // Check if p ≡ 3 mod 4
            if &p % BigUint::from(4u32) == BigUint::from(3u32) {
                return p;
            }
        }
    }
    
    pub fn split(self) -> (PaillierPublic, PaillierPrivate) {
        (
            PaillierPublic {
                N0: self.N0.clone(),
            },
            PaillierPrivate {
                p: self.p,
                q: self.q,
            },
        )
    }
    pub fn save(self, base_path: &str) {
        let (public, secret) = self.split();

        save_to_file(
            &format!("{}/public_prover_paillier.json", base_path),
            &public,
        );

        save_to_file(
            &format!("{}/secret_prover_paillier.json", base_path),
            &secret,
        );
    }
}


fn save_to_file<T: Serialize>(path: &str, obj: &T) {
    let data = serde_json::to_vec_pretty(obj)
        .expect("serialize failed");
    let mut file = File::create(path)
        .expect("cannot create file");
    file.write_all(&data)
        .expect("write failed");
}

fn load_from_file<T: for<'a> Deserialize<'a>>(path: &str) -> T {
    let data = std::fs::read(path)
        .expect("cannot read file");
    serde_json::from_slice(&data)
        .expect("deserialize failed")
}

