
use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num_traits::{One, Signed, Zero};
use crate::crypto::{paillier, pedersen};
use crate::utils::random::Random;
use crate::pow;
use crate::utils::rustcryptodome::number;
use crate::storage::Load_public_params as load_params;
use crate::crypto::{pedersen::PedersenCryptosystem, paillier::PaillierCryptosystem};
use crate::zkproofs::range_zk_proof::challenge::challenge;


#[derive(Debug, Clone)] 

pub struct ProverInputs{
    
    pub k: BigInt,// secret
    pub rho: BigUint,//secret
    pub K: BigUint,// Public ciphertext
}


#[derive(Debug, Clone)] 
pub struct ProvePrivate{
    pub alpha: BigInt, // a<- +-2 ^ {ell + epsilon}
    pub mu: BigInt,// mu <- +-2^{ell} . N_hat
    pub gamma: BigInt, // gamma <- +-2^{ell + epsilon}. N_hat
    pub r: BigUint, // random for paillier encryption
}

#[derive(Debug, Clone)] 

pub struct PramRangeZKProof{
    pub challenge: challenge,
}


#[derive(Debug, Clone)] 
pub struct RangeZKProver{
    pub pedersen: PedersenCryptosystem,
    pub paillier: PaillierCryptosystem,
    pub public_params: load_params::PublicParams,
    pub range_params: load_params::RangeParams,
    pub prover_private: ProvePrivate,
    pub prover_inputs: ProverInputs,
}


impl RangeZKProver{
    pub fn new() -> Self{
        

        let public_params = load_params::PublicParams::load();
        let range_params = load_params::RangeParams::load();

        let pedersen =  PedersenCryptosystem::new(
            public_params.N_hat.clone(),
            public_params.s.clone(),
            public_params.t.clone(),
        );
        let paillier = PaillierCryptosystem::new(&range_params.N0);

        let mut rng = Random::new(None);

        let ell = range_params.ell.clone();
        let epsilon = range_params.epsilon.clone();

        let N_hat = public_params.N_hat.clone();
        let N0 = range_params.N0.clone();

        let alpha = rng.randint_signed(
            -pow!(BigInt::from(2),(ell + epsilon)as u32) ,
            pow!(BigInt::from(2),(ell + epsilon)as u32) ,
        );
        let mu = rng.randint_signed(
            -pow!(BigInt::from(2),ell as u32) * N_hat.clone().to_bigint().unwrap(),
            pow!(BigInt::from(2),ell as u32) * N_hat.clone().to_bigint().unwrap(),
        );
        let r = rng.randint( BigUint::from(1u32), N0.clone() - BigUint::from(1u32));

        let gamma = rng.randint_signed(
            -pow!(BigInt::from(2), (ell + epsilon)as u32) * N_hat.clone().to_bigint().unwrap(),
            pow!(BigInt::from(2), (ell + epsilon)as u32) * N_hat.clone().to_bigint().unwrap(),
        );

        let k =  rng.randint_signed(
            -pow!(BigInt::from(2), ell as u32),
            pow!(BigInt::from(2), ell as u32),
        );

        let rho = rng.randint(BigUint::one(), N0.clone() - BigUint::one());
        
        let K = paillier.encrypt_exp_k(&k, &rho);

        let prover_private = ProvePrivate{
            alpha,
            mu,
            gamma,
            r,
        };
        let prover_inputs = ProverInputs{
            k,
            rho,
            K,
        };
        RangeZKProver{
            pedersen,
            paillier,
            public_params,
            range_params,
            prover_private,
            prover_inputs,
        }
        
        
    }

    ///  ROUND 1: Prover computes the commitments
    pub fn prover_samples(&self)->  (BigUint, BigUint, BigUint){
        // S: Pedersen commitment to alpha and mu: C = s^k * t^mu mod N_hat

        let alpha = self.prover_private.alpha.clone();
        let mu = self.prover_private.mu.clone();

        let S = self.pedersen.commit(&self.prover_inputs.k, &self.prover_private.mu);


        // A: Paillier encryption of alpha with randomness gamma: A = (1+N_0)^alpha * r^N_0 mod N_0^2
        
        let A = self.paillier.encrypt_exp_k(
            &self.prover_private.alpha,
            &self.prover_private.r,
        );

        // C: Pedersen commitment to k and rho: C = s^alpha * tau^gamma mod N_hat

        let C = self.pedersen.commit(&self.prover_private.alpha, &self.prover_private.gamma);

        (S, A, C)
    }

    /// ROUND 3: Prover computes the responses
    /// z1 = alpha + e.k
    /// z2 = r.p^e mod N_0
    /// z3 = gamma + e.mu
    pub fn prover_responses(&self, e: &BigInt) -> (BigInt, BigUint, BigInt){
        // z1 = alpha + e.k
        let z1 = &self.prover_private.alpha + e * &self.prover_inputs.k;
        // z2 = r.p^e mod N_0
        let r = &self.prover_private.r;
        let p = &self.prover_inputs.rho;
        let N0 = &self.range_params.N0;
        let p_pow_e = number::pow_signed(&p.to_bigint().unwrap(), e, N0);
        let z2 = (r * p_pow_e.to_biguint().unwrap()) % N0;
        // z3 = gamma + e.mu
        let z3 = &self.prover_private.gamma + e * &self.prover_private.mu;
        (z1, z2, z3)

        
    }
    
}
#[cfg(test)]

mod tests {
    use super::*;
    #[test]
    fn test_range_zk_prover(){
        let prover = RangeZKProver::new();
        println!("Prover initialized: {:?}", prover);
        prover.prover_samples();
        
    }
}