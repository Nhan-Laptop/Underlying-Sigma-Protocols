

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};

use crate::pow;
use crate::utils::random::Random;
use crate::utils::rustcryptodome::number;
use crate::zkproofs::modulus_zk_proof::prover::ModulusZKProofProver;
use crate::zkproofs::modulus_zk_proof::verifier::ModulusZKProofVerifier;
use num_traits::{One, Signed, Zero};

#[derive(Debug, Clone)]
pub struct challenge{
    Prover:   ModulusZKProofProver,
    Verifier: ModulusZKProofVerifier,

   
   pub x_i: BigUint, // from Prover
   pub a_i: u8,      // from Prover
   pub b_i: u8,      // from Prover
   pub z_i: BigUint, // from Prover
   pub y_i: BigUint, // from Verifier
}



impl challenge {
    pub fn new() -> Self {
        let prover = ModulusZKProofProver::new();
        // ROUND1: Generate Verifier with n and w from Prover 
        // and send to Verifier
        let verifier 
            = ModulusZKProofVerifier::new(&prover.n, &prover.w);
        verifier.initial_check();
        eprintln!("Challenge: Prover n and w passed to Verifier");
        challenge{
            Prover: prover,
            Verifier: verifier,
            x_i: BigUint::zero(),
            a_i: 0,
            b_i: 0,
            z_i: BigUint::zero(),
            y_i: BigUint::zero(),
        }
    }
    
    /// ROUND2: Verifier samples challenge y_i and sends to Prover
    pub fn Round2(&mut self){
        let y_i = self.Verifier.verifier_challenge();
        self.y_i = y_i;
    }
    
    /// ROUND3: Prover computes (x_i,a_i,b_i,z_i) and sends to Verifier
    pub fn Round3(&mut self) -> bool {
        match self.Prover.prover_step(&self.y_i) {
            Some((x_i, a_i, b_i, z_i)) => {
                self.x_i = x_i.clone();
                self.a_i = a_i;
                self.b_i = b_i;
                self.z_i = z_i;
                let one_am = if a_i == 0 { BigUint::one() } else { &self.Prover.n - BigUint::one() };
                let w_bi = if b_i == 0 { BigUint::one() } else { self.Prover.w.clone() };
                let y_i_t = (&one_am * &w_bi * &self.y_i) % &self.Prover.n;
                let x_i_4 = pow!(&x_i, BigUint::from(4u32), self.Prover.n.clone());
                if x_i_4 == y_i_t {
                    println!("Prover: Step successful, sending (x_i,a_i,b_i,z_i) to Verifier");
                } else {
                    println!("Prover: Step failed, aborting protocol");
                    return false;
                }
                true
            }
            None => {
                println!("no valid a_i, b_i");
                false
            }
        }
    }

    /// Verification step
    pub fn verify(&self) -> bool {
        let result = self.Verifier.verify_step(&self.x_i, self.a_i, self.b_i, &self.z_i, &self.y_i);
        if result {
            println!("ACCEPTED");
        } else {
            println!("REJECTED");
        }
        result
    }   

    /// Full chain
    pub fn paillier_modulus_ZK_protocol_chain(&mut self) -> bool {
        // ROUND2: Verifier samples challenge y_i and sends to Prover
        self.Round2();
        // ROUND3: Prover computes (x_i,a_i,b_i,z_i) and sends to Verifier
        // Returns false if protocol aborts
        if !self.Round3() {
            return false;
        }
        // Verification step
        let result = self.verify();
        result
    }

    /// Full protocol chain
    pub fn paillier_modulus_ZK_protocol(&mut self) -> bool {
        let mut cnt = 0;
        for i in 0..self.Verifier.m {
            println!("--- Modulus ZK Proof Round {} ---", i + 1);
            cnt += match self.paillier_modulus_ZK_protocol_chain() {
                true => 1,
                _ => {
                    println!("Protocol aborted in round {}", i + 1);
                    0
                },
            }            
        }

        return cnt == 80; // at least 75% success rate
    }

}

#[cfg(test)]
mod tests {
    use std::result;

    use super::*;
    #[test]
    fn test_modulus_zk_proof_protocol() {
        let mut challenge = challenge::new();
        let result = challenge.paillier_modulus_ZK_protocol();
        assert!(result);        
        
    }
}
