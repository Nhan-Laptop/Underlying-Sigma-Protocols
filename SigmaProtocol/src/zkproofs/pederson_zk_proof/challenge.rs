

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};

use crate::pow;
use crate::utils::random::Random;
use crate::utils::rustcryptodome::number;
use crate::zkproofs::pederson_zk_proof::prover::pedersenZKProver;
use crate::zkproofs::pederson_zk_proof::verifier::pedersenZKVerifier;
use num_traits::{One, Signed, Zero};

#[derive(Debug, Clone)]
pub struct challenge{
    Prover: pedersenZKProver,
    Verifier: pedersenZKVerifier,

    /// round 1 
    A_i: BigUint, // commitment A_i = t ^ a_i

    /// round 2 
    e: BigInt, // challenge from verifier: e<- {0,1}

    /// round 3
    z_i: BigUint, // response z_i = a_i + e*k_i

    m: usize, // number of messages
    
}



impl challenge {
    pub fn new() -> Self {
        let prover = pedersenZKProver::new();
        let verifier = pedersenZKVerifier::new();
        challenge{
            Prover: prover,
            Verifier: verifier,
            A_i: BigUint::zero(),
            e: BigInt::zero(),
            z_i: BigUint::zero(),
            m: 80,
        }
    }
    
    /// ROUND1: Prover computes commitments a_1 <- Z_phi ----> A_i = t ^ a_i mod N_hat
    /// and sends to Verifier
    pub fn Round1(&mut self){
        let A_i = self.Prover.prover_samples(); 
        self.A_i = A_i;
    }

    /// ROUND2: Verifier samples challenge e and sends to Prover
    pub fn Round2(&mut self){
        let e = self.Verifier.sample_e();
        self.e = e;
    }

    /// ROUND3: Prover computes responses z_i and sends to Verifier
    pub fn Round3(&mut self){
        let z_i = self.Prover.prover_responses(&self.e.to_biguint().unwrap());
        self.z_i = z_i;
    }

    /// Round4 Verification
    pub fn Verification(&self) -> bool{
        let verify = self.Verifier.verify_responses(
            &self.A_i,
            &self.z_i.to_bigint().unwrap(),
        );
        verify
    }
    /// Full protocol execution
    pub fn pedersen_ZK_II(&mut self) -> bool{
        self.Round1();
        self.Round2();
        self.Round3();
        let result = self.Verification();
        result
    }
    /// For each m
    pub fn full_m_protocol(&mut self) -> bool {
            let mut cnt: usize = 0;
            for _i in 0..self.m {
                println!("\n--- PEDERSEN ZK PROOF PROTOCOL ITERATION {} ---", _i + 1);
                let protocol = self.pedersen_ZK_II();
                if protocol {
                    cnt += 1;
                    println!("PASSED");
                } else {
                    println!("ABORTED");
                    return false; 
                }
            } 
            
            cnt == self.m 
        }
}

#[cfg(test)]

mod tests {
    use std::result;

    use super::*;
    #[test]
    fn test_pederson_protocol() {
        let mut challenge = challenge::new();
        let result = challenge.full_m_protocol();
        assert!(result);
    }
}
