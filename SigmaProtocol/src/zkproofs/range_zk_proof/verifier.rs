

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};

use crate::pow;
use crate::utils::random::Random;
use crate::utils::rustcryptodome::number;
use crate::storage::Load_public_params as load_params;
use crate::crypto::{pedersen::PedersenCryptosystem, paillier::PaillierCryptosystem};




#[derive(Debug, Clone)]
pub struct VerifierPrivate{
    pub e: BigInt, // challenge from verifier: e<- {-q...+q}
}
#[derive(Debug, Clone)] 
pub struct RangeZKVerifier{
    pub pedersen: PedersenCryptosystem,
    pub paillier: PaillierCryptosystem,
    pub public_params: load_params::PublicParams,
    pub range_params: load_params::RangeParams,
    pub verifier_private: VerifierPrivate,
}


impl RangeZKVerifier{
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
        let q = crate::pow!(&BigUint::from(2u32), range_params.epsilon as u32);

        let mut rng = Random::new(None);

        let e = rng.randint_signed(
            (-&q.to_bigint().unwrap()),
            q.to_bigint().unwrap(),
        );
        RangeZKVerifier{
            pedersen,
            paillier,
            public_params,
            range_params,
            verifier_private: VerifierPrivate{
                e,
            },
        }
    }

    pub fn Equality_checks(&self, z1: &BigInt, z2: &BigUint, z3: &BigInt, S: &BigUint, A: &BigUint, C: &BigUint, K: &BigUint,) -> bool{
        
        // check1: (1+N_0)^z1 * z2^N_0  = A * K^e mod N_0^2
        let left_eq = self.paillier.encrypt_exp_k(&z1, &z2);
        let right_eq = (A * number::pow_signed(&K.to_bigint().unwrap(), &self.verifier_private.e, &self.paillier.get_n_sq())) % self.paillier.get_n_sq();
        if left_eq != right_eq{
            return false;
        }; 

        // check2 s^z1 * t^z3 = C * S^e mod N_hat
        let left_eq2 = self.pedersen.commit(&z1, &z3);
        let right_eq2 = (C * number::pow_signed(&S.to_bigint().unwrap(), &self.verifier_private.e, &self.pedersen.n_hat)) % &self.pedersen.n_hat;
        if left_eq2 != right_eq2{
            return false;
        };
        true

    }

    pub fn Range_checks(&self, z1: &BigInt) -> bool{
        let ell = self.range_params.ell.clone();
        let epsilon = self.range_params.epsilon.clone();
        
        let lower_bound = -pow!(BigInt::from(2), (ell+ epsilon) as u32);
        let upper_bound = pow!(BigInt::from(2), (ell+ epsilon) as u32);
        // println!("Range check bounds: [{:?}, {:?}]", lower_bound, upper_bound);
        // println!("z1 value: {:?}", z1);
        if z1 < &lower_bound || z1 > &upper_bound{
            return false;
        }
        true
    }
}
