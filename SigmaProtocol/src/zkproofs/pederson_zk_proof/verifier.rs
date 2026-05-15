
use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num_traits::{One, Signed, Zero};
use crate::crypto::{paillier, pedersen};
use crate::utils::random::Random;
use crate::pow;
use crate::utils::rustcryptodome::number;
use crate::storage::Load_public_params as load_params;
use crate::storage::Load_privkey_p_q as load_privkey;
use crate::crypto::{pedersen::PedersenCryptosystem, paillier::PaillierCryptosystem};
use crate::zkproofs::modulus_zk_proof::verifier;




#[derive(Debug, Clone)]
pub struct VerifierPrivate{
    pub e: BigInt, // challenge from verifier: e<- {0,1}
}

#[derive(Debug, Clone)] 
pub struct pedersenZKVerifier{
    pub pedersen: PedersenCryptosystem,
    pub paillier: PaillierCryptosystem,
    pub public_params: load_params::PublicParams,
    pub verifier_private: VerifierPrivate,
}


impl pedersenZKVerifier{
    pub fn new() -> Self{
        

        let public_params = load_params::PublicParams::load();
        let range_params = load_params::RangeParams::load();

        let pedersen =  PedersenCryptosystem::new(
            public_params.N_hat.clone(),
            public_params.s.clone(),
            public_params.t.clone(),
        );

        let paillier = PaillierCryptosystem::new(
            &range_params.N0.clone(),
        );
        let verifier: VerifierPrivate 
        = VerifierPrivate{
            e: BigInt::zero()
        };
        pedersenZKVerifier{
            pedersen,
            paillier,
            public_params,
            verifier_private: verifier,
            }

        
        }

    /// ROUND 2, Receive A_i = t ^ a_i and 
    /// sample challenge e from {0,1} send to Prover
    pub fn sample_e(&mut self)-> BigInt{
        let mut rng = Random::new(None);
        let e = rng.choice(&[BigInt::zero(), BigInt::one()]);
        self.verifier_private.e = e.clone();
        e 
    }

    /// ROUND 4: Receive z_i = a_i + e_i * d 
    /// and verify t^ z_i = A_i . s^e_i mod N_hat
    
    pub fn verify_responses(&self, A: &BigUint, z: &BigInt)-> bool{
        // left hand side: t^ z_i mod N_hat
        let lhs = self.pedersen.commit(&BigInt::zero(), &z);
        // right hand side: A_i . s^e_i mod N_hat
        let s_e = (self.pedersen.commit(&self.verifier_private.e, &BigInt::zero())) % &self.public_params.N_hat;

        let rhs = (A * &s_e) % &self.public_params.N_hat;
        lhs == rhs
    }

    
}


#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_verifier_initialization() {
        let verifier = pedersenZKVerifier::new();
        assert_eq!(verifier.verifier_private.e, BigInt::zero());
    }
}