
use core::panic;
use std::vec;

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num_traits::{One, Signed, Zero};
use crate::crypto::{paillier, pedersen};
use crate::utils::random::Random;
use crate::pow;
use crate::utils::rustcryptodome::number;
use crate::storage::{Load_public_params as load_params, PublicParams};
use crate::storage::Load_privkey_p_q as load_privkey;
use crate::crypto::{pedersen::PedersenCryptosystem, paillier::PaillierCryptosystem};


#[derive(Debug, Clone)]
pub struct ModulusZKProofVerifier {
    pub n: BigUint,
    pub w: BigUint,

    // Verifier samples
    pub m: u32, 
}

impl ModulusZKProofVerifier{
    pub fn new(n: &BigUint, w: &BigUint) -> Self {
        ModulusZKProofVerifier {
            n: n.clone(),
            w: w.clone(),
            m: 80,// rounds 
        }
    }

    /// Challenge from Verifier: y_i <- Z_n*
    pub fn verifier_challenge(&self) -> BigUint{
        let mut rng =Random::new(None);
        let y_i = rng.randint(BigUint::from(1u32)
                                    ,self.n.clone() );
        y_i
    }

    /// Check N is an odd composite number and gcd(w,N)=1
    pub fn initial_check(&self) -> bool {
        let mut gcd = number::gcd(&self.w, &self.n);
        if &self.n & BigUint::one() == BigUint::zero() || gcd != BigUint::one() {
            panic!("N is not odd composite or gcd(w,N) != 1");
        }
        true
    }

    /// Verification step  
    /// Inputs: (x_i,a_i,b_i,z_i) from Prover and y_i from Verifier
    /// Verification:
    /// Check: x_i^4 ≡ (-1)^a_i * w^b_i * y_i (mod n)
    pub fn verify_step(&self, x_i: &BigUint, a_i: u8, b_i: u8, z_i: &BigUint, y_i: &BigUint) -> bool {
        // Verify: x_i^4 = (-1)^a_i * w^b_i * y_i mod n
        let x_4 = pow!(x_i, BigUint::from(4u32), self.n.clone());
        
        // Compute (-1)^a_i mod n
        let a = match a_i {
            0 => BigUint::one(),
            1 => {
                // -1 mod n
                if self.n > BigUint::one() {
                    (&self.n - BigUint::one()) % &self.n
                } else {
                    BigUint::zero()
                }
            },
            _ => return false,
        };
        
        // Compute w^b_i
        let b = pow!(&self.w, BigUint::from(b_i as u32), self.n.clone());
        
        // Compute expected: (-1)^a_i * w^b_i * y_i mod n
        let tmp = (&a * &b) % &self.n;
        let cmp = (&tmp * y_i) % &self.n;
        
        if x_4 != cmp {
            println!("FAILED");
            return false;
        }
        
        true
    }

}

