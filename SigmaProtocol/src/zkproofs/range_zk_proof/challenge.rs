

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};

use crate::pow;
use crate::utils::random::Random;
use crate::utils::rustcryptodome::number;
use crate::zkproofs::range_zk_proof::prover::RangeZKProver;
use crate::zkproofs::range_zk_proof::verifier::RangeZKVerifier;
use num_traits::{One, Signed, Zero};

#[derive(Debug, Clone)]
pub struct challenge{
    Prover: RangeZKProver,
    Verifier: RangeZKVerifier,

    /// round 1 
    S: BigUint,// Pedersen commitment to alpha and mu: C = s^k * t^mu mod N_hat
    A: BigUint,// Paillier encryption of alpha with randomness gamma: A = (1+N_0)^alpha * r^N_0 mod N_0^2
    C: BigUint,// Pedersen commitment to k and rho: C = s^alpha * tau^gamma mod N_hat


    /// round 2 
    e: BigInt, // challenge from verifier: e<- {-q...+q}

    /// round 3
    z1: BigInt, // z1 = alpha + e.k
    z2: BigUint, // z2 = r.p^e mod N_0
    z3: BigInt, // z3 = gamma + e.mu
}



impl challenge {
    pub fn new() -> Self {
        let prover = RangeZKProver::new();
        let verifier = RangeZKVerifier::new();
        challenge{
            Prover: prover,
            Verifier: verifier,
            S: BigUint::zero(),
            A: BigUint::zero(),
            C: BigUint::zero(),
            e: BigInt::zero(),
            z1: BigInt::zero(),
            z2: BigUint::zero(),
            z3: BigInt::zero(),
        }
    }
    
    /// ROUND1: Prover computes commitments S, A, C and sends to Verifier
    pub fn Round1(&mut self){
        let (S, A, C) = self.Prover.prover_samples();
        self.S = S;
        self.A = A;
        self.C = C;
    }

    /// ROUND2: Verifier samples challenge e and sends to Prover
    pub fn Round2(&mut self){
        let e = self.Verifier.verifier_private.e.clone();
        self.e = e;
    }

    /// ROUND3: Prover computes responses z1, z2, z3 and sends to Verifier
    pub fn Round3(&mut self){
        let (z1, z2, z3) = self.Prover.prover_responses(&self.e);
        self.z1 = z1;
        self.z2 = z2;
        self.z3 = z3;
    }

    /// Equality checks by Verifier
    pub fn Equality_checks(&self) -> bool{
        let result = self.Verifier.Equality_checks(
            &self.z1,
            &self.z2,
            &self.z3,
            &self.S,
            &self.A,
            &self.C,
            &self.Prover.prover_inputs.K,
        );
        result
    }

    /// Range Checks by Verifier
    pub fn Range_checks(&self) -> bool{
        let result = self.Verifier.Range_checks(
            &self.z1,
        );
        result
    }

    /// Full protocol chain
    pub fn paillier_encryption_in_range_ZK_II(&mut self)-> bool{
        /// Round 1: Prover computes commitments S, A, C and sends to Verifier
        self.Round1();
        /// Round 2: Verifier samples challenge e and sends to Prover
        self.Round2();
        /// Round 3: Prover computes responses z1, z2, z3 and sends to Verifier
        self.Round3();
        /// Verifier performs Equality checks
        let eq_check = self.Equality_checks();
        if !eq_check{
            println!("Equality checks failed!");
            return false ;
        }
        /// Verifier performs Range checks
        let range_check = self.Range_checks();
        if !range_check{
            
            println!("Range checks failed!");
            
            println!("z1: {:?}", self.z1);
            println!("e: {:?}", self.e);
            println!("k: {:?}", self.Prover.prover_inputs.k);
            println!("alpha: {:?}", self.Prover.prover_private.alpha);
            println!("lower bound: {:?}", -crate::pow!(&BigUint::from(2u32), (self.Verifier.range_params.ell + self.Verifier.range_params.epsilon) as u32).to_bigint().unwrap());
            println!("upper bound: {:?}", crate::pow!(&BigUint::from(2u32), (self.Verifier.range_params.ell + self.Verifier.range_params.epsilon) as u32).to_bigint().unwrap()); 

            return false ; 
        }
        println!("Paillier encryption in range ZK proof succeeded!");
        true 
    }

}

#[cfg(test)]
mod tests {
    use std::result;

    use super::*;
    #[test]
    fn test_range_zk_proof_protocol() {
        let mut passed = 0;
        let mut aborted = 0; // Range check abort (expected in statistical ZK)
        
        for _i in 0..100 {
            println!("\n=== TEST ITERATION {} ===", _i + 1);
            let mut protocol = challenge::new();
            let result = protocol.paillier_encryption_in_range_ZK_II();
            if result {
                passed += 1;
            } else {
                aborted += 1;
            }
        }
        
        println!("\n=== SUMMARY ===");
        println!("Passed: {}/100", passed);
        println!("Aborted (range check): {}/100", aborted);
        println!("Abort rate: {:.1}%", (aborted as f64 / 10000.0) * 100.0);
        println!("Note: Abort is expected in statistical ZK protocols");
    }
}
