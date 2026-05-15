
use std::vec;

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num_traits::{One, Signed, Zero};
use crate::crypto::{paillier, pedersen};
use crate::utils::random::Random;
use crate::pow;
use crate::utils::rustcryptodome::number;
use crate::storage::Load_public_params as load_params;
use crate::storage::Load_privkey_p_q as load_privkey;
use crate::crypto::{pedersen::PedersenCryptosystem, paillier::PaillierCryptosystem};






#[derive(Debug, Clone)]

pub struct ModulusZKProofProver {
    pub private_prover: load_privkey::SecretPaillierParams, 
    
    pub phi: BigUint,
    // common inputs
    pub n: BigUint,

    // Prover samples
    pub w: BigUint, // random w <- Z_n* of Jacobi symbol -1


}


impl ModulusZKProofProver{
    /// Generate a w that has Jacobi symbol -1 in Z_n*
    /// w must have (w/p) != (w/q) so that Jacobi(w, n) = -1
    pub fn gen_w(&mut self){
        let mut rng = Random::new(None);
        let p = &self.private_prover.p;
        let q = &self.private_prover.q;
        loop {
            let w = rng.randint(BigUint::from(1u32), self.n.clone());
            let leg_p = number::jacobi_symbol(&(&w % p), p);
            let leg_q = number::jacobi_symbol(&(&w % q), q);
            
            if leg_p != 0 && leg_q != 0 && leg_p != leg_q {
                self.w = w;
                break;
            }
        }
    }
    pub fn new() -> Self {
        let private_prover = load_privkey::SecretPaillierParams::load();
        let n: BigUint = &private_prover.p * &private_prover.q;
        let phi = (&private_prover.p - BigUint::one()) * (&private_prover.q - BigUint::one());  

        let mut prover = ModulusZKProofProver {
            private_prover,
            n,
            phi,
            w: BigUint::zero(),
        };
        prover.gen_w();
        prover
    }

    /// Check if y is a quadratic residue mod n (QR mod p AND QR mod q)
    fn is_quadratic_residue(&self, y: &BigUint) -> bool {
        let p = &self.private_prover.p;
        let q = &self.private_prover.q;
        
        // Reduce y mod p and mod q first
        let y_mod_p = y % p;
        let y_mod_q = y % q;
        
        // Euler's criterion: y is QR mod p iff y^((p-1)/2) ≡ 1 (mod p)
        let exp_p: BigUint = (p - BigUint::one()) >> 1u32;
        let exp_q: BigUint = (q - BigUint::one()) >> 1u32;
        
        let res_p = pow!(y_mod_p.clone(), exp_p.clone(), p.clone());
        let res_q = pow!(y_mod_q.clone(), exp_q.clone(), q.clone());
        
        res_p == BigUint::one() && res_q == BigUint::one()
    }

    /// find ALL square roots x such that x^2 = y mod n using CRT (assumes p,q ≡ 3 mod 4)
    /// Returns up to 4 square roots
    fn sqrt_mod_n_all(&self, y: &BigUint) -> Vec<BigUint> {
        // First check if y is a quadratic residue using Euler criterion
        if !self.is_quadratic_residue(y) {
            return vec![];
        }
        
        let n = &self.n;
        let p = &self.private_prover.p;
        let q = &self.private_prover.q;
        let dp = (p + BigUint::one()) >> 2; // dp = (p+1)/4
        let dq = (q + BigUint::one()) >> 2; // dq = (q+1)/4
        
        // sqrt mod p: r_p and -r_p
        let r_p = pow!(y.clone(), dp, p.clone());
        let neg_r_p = if r_p.is_zero() { BigUint::zero() } else { p - &r_p };
        
        // sqrt mod q: r_q and -r_q  
        let r_q = pow!(y.clone(), dq, q.clone());
        let neg_r_q = if r_q.is_zero() { BigUint::zero() } else { q - &r_q };
        
        // CRT to combine: 4 combinations
        let qinv = number::inverse(q, p).unwrap().to_biguint().unwrap();
        
        let mut roots = Vec::new();
        let combinations: Vec<(&BigUint, &BigUint)> = vec![
            (&r_p, &r_q), 
            (&r_p, &neg_r_q), 
            (&neg_r_p, &r_q), 
            (&neg_r_p, &neg_r_q)
        ];
        
        for (m1, m2) in combinations {
            // CRT: x = m2 + q * ((m1 - m2 mod p) * qinv mod p)
            let m2_mod_p = m2 % p;
            let diff = if m1 >= &m2_mod_p {
                m1 - &m2_mod_p
            } else {
                p - (&m2_mod_p - m1)
            };
            let h = (&qinv * &diff) % p;
            let root = (m2 + &h * q) % n;
            roots.push(root);
        }
        
        roots
    }
    
    /// find x such that x^2 = y mod n (returns first root found)
    fn sqrt_mod_n(&self, y: &BigUint) -> Option<BigUint> {
        let roots = self.sqrt_mod_n_all(y);
        roots.into_iter().next()
    }

    /// find x such that x^4 = y mod n (try all possible sqrt combinations)
    fn four_root(&self, y: &BigUint) -> Option<BigUint> {
        // Get all square roots of y
        let sqrt_y_all = self.sqrt_mod_n_all(y);
        
        // For each sqrt(y), try to get sqrt again
        for sqrt_y in sqrt_y_all.iter() {
            let sqrt_sqrt_y_all = self.sqrt_mod_n_all(sqrt_y);
            for fourth_root in sqrt_sqrt_y_all {
                // Verify: fourth_root^4 should equal y
                let check = pow!(&fourth_root, BigUint::from(4u32), self.n.clone());
                if &check == y {
                    return Some(fourth_root);
                }
            }
        }
        
        None
    }

    /// Get Legendre symbols of y mod p and mod q
    fn get_legendre_class(&self, y: &BigUint) -> (i8, i8) {
        let p = &self.private_prover.p;
        let q = &self.private_prover.q;
        let leg_p = number::jacobi_symbol(&(y % p), p);
        let leg_q = number::jacobi_symbol(&(y % q), q);
        (leg_p, leg_q)
    }

    /// Prover computes x_i, a_i, b_i, z_i and sends to Verifier 
    /// and receives y_i from Verifier
    /// Prover needs to find a_i, b_i such that (-1)^a_i * w^b_i * y_i is a 4th power mod n
    pub fn prover_step(&self, y_i: &BigUint) -> Option<(BigUint, u8, u8, BigUint)> {
        // Check gcd(y_i, n) = 1
        let gcd = number::gcd(y_i, &self.n);
        if gcd != BigUint::one() {
            return None;
        }
        
        for a_i in 0u8..=1 {
            for b_i in 0u8..=1 {
                let a = match a_i {
                    0 => BigUint::one(),
                    1 => {
                        if self.n > BigUint::one() {
                            (&self.n - BigUint::one()) % &self.n
                        } else {
                            BigUint::zero()
                        }
                    },
                    _ => continue,
                };
                let b = if b_i == 0 { BigUint::one() } else { self.w.clone() };
                
                let y_i_t = (&a * &b * y_i) % &self.n;
                let (yit_leg_p, yit_leg_q) = self.get_legendre_class(&y_i_t);
                
                // y_i_t is QR mod n iff (yit_leg_p, yit_leg_q) == (1, 1)
                let is_qr = yit_leg_p == 1 && yit_leg_q == 1;
                
                if !is_qr {
                    continue; // not QR, so not a 4th power
                }
                
                if let Some(x_i) = self.four_root(&y_i_t) {
                    let x_i_4 = pow!(&x_i, BigUint::from(4u32), self.n.clone());
                    if x_i_4 == y_i_t {
                        let n_inv_phi = number::inverse(&self.n, &self.phi)
                            .unwrap()
                            .to_biguint()
                            .unwrap();
                        let z_i = pow!(&x_i, n_inv_phi, self.n.clone());
                        
                        return Some((x_i, a_i, b_i, z_i));
                    }
                }
            }
        }
        
        None  
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_gen_w() {
        let prover = ModulusZKProofProver::new();
        let jacobi_p = number::jacobi_symbol(&(&prover.w % &prover.private_prover.p), &prover.private_prover.p);
        let jacobi_q = number::jacobi_symbol(&(&prover.w % &prover.private_prover.q), &prover.private_prover.q);
        // w should have Jacobi = -1, meaning leg_p != leg_q
        assert!(jacobi_p != 0 && jacobi_q != 0 && jacobi_p != jacobi_q, "w must have Jacobi symbol -1");
        
        let mut rng = Random::new(None);
        let y_i = rng.randint(BigUint::from(1u32), prover.n.clone());
        match prover.prover_step(&y_i) {
            Some((_x_i, _a_i, _b_i, _z_i)) => {
                // Success
            }
            None => {
                panic!("Prover failed to find valid a_i, b_i");
            }
        }
    }
}