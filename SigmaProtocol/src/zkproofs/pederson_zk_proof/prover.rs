
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
pub  struct ProvePrivate{
    pub prover_private: load_privkey::SecretPedersenParams,
    pub phi: BigUint,
    pub alpha: BigUint, // Z_phi
}







#[derive(Debug, Clone)] 
pub struct pedersenZKProver{
    pub pedersen: PedersenCryptosystem,
    pub paillier: PaillierCryptosystem,
    pub public_params: load_params::PublicParams,
    pub prover_private: ProvePrivate,
}


impl pedersenZKProver{
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

        let prover_pedersen = load_privkey::SecretPedersenParams::load();

        let phi = (prover_pedersen.p.clone() - BigUint::one()) * (prover_pedersen.q.clone() - BigUint::one());
        let prover_private = ProvePrivate{
            prover_private: prover_pedersen,
            phi: phi,
            alpha: BigUint::zero(),
        };
        pedersenZKProver{
            pedersen,
            paillier,
            public_params,
            prover_private,
        }
    }

    ///  ROUND 1: Prover samples
    pub fn prover_samples(&mut self)-> BigUint{
        let mut rng = Random::new(None);
        // sample alpha in Z_phi
        let mut alpha = rng._randbelow(&self.prover_private.phi);
        // Computes A = t ^ alpha mod N_hat
        self.prover_private.alpha = alpha.to_biguint().unwrap().clone();

        let A = self.pedersen.commit(&BigInt::from(0u32), &alpha.to_bigint().unwrap());
        A
    }

    ///Round3 Prover send z_i = a_i + e_i * d and e_i from verifier
    pub fn prover_responses(&self, e: &BigUint) -> BigUint{
        // z = alpha + e* d mod phi
        let d = &self.prover_private.prover_private.d;
        let alpha = &self.prover_private.alpha;
        let z = (alpha + (e * d).to_biguint().unwrap())
         % &self.prover_private.phi;
        z
    }   

}
#[cfg(test)]

mod tests {
    use super::*;
    #[test]
    fn test_range_zk_prover(){
        let prover = pedersenZKProver::new();
        println!("Prover initialized: {:?}", prover);

    }
}