/// Properties: https://en.wikipedia.org/wiki/Commitment_scheme#Additive_and_multiplicative_homomorphic_properties_of_commitments
/// Reference: https://en.wikipedia.org/wiki/Paillier_cryptosystem

use crate::utils::rustcryptodome::number;
use crate::pow;
use crate::utils::random::Random;

use num_bigint::*;

use num_bigint::{BigInt, BigUint, ToBigInt, Sign};
use num_traits::{Zero, One, ToPrimitive};


#[derive(Debug, Clone)] 

pub struct PedersenCryptosystem{
    pub n_hat: BigUint,
    pub s: BigUint,
    pub t: BigUint,    
}

impl PedersenCryptosystem{
    pub fn new(n: BigUint, s: BigUint, t: BigUint) -> Self{
        PedersenCryptosystem{
            n_hat: n,
            s: s,
            t: t,
        }
    }

    /// Commit: C = s^k * t^u mod n_hat
    /// k: value to commit in -2^l..2^l
    /// u: random blinding factor in -2^l*_N_hat..2^l*_N_hat
    pub fn commit(&self,k: &BigInt, u: &BigInt) -> BigUint{
        
        let S1 = number::pow_signed(&self.s.to_bigint().unwrap(), &k, &self.n_hat);
        let S2 = number::pow_signed(&self.t.to_bigint().unwrap(), &u, &self.n_hat);
        let S = (S1 * S2) % &self.n_hat;
        S
    }

    /// Verify commitment
    /// C: commitment
    /// k: value to commit
    /// u: random blinding factor
    /// Returns: true if valid, false otherwise
    pub fn verify(&self, C: &BigUint, k: &BigInt, u: &BigInt) -> bool{
        let C_calculated = self.commit(k, u);
        &C_calculated == C
    }


}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pedersen_commitment() {
        let n_hat = BigUint::parse_bytes(b"10142788912725007", 10).unwrap();
        let s = BigUint::parse_bytes(b"5", 10).unwrap();
        let t = BigUint::parse_bytes(b"7", 10).unwrap();    
        let pedersen = PedersenCryptosystem::new(n_hat, s, t);  
        let k = BigInt::from(12345);
        let u = BigInt::from(67890);
        let commitment = pedersen.commit(&k, &u);
        assert!(pedersen.verify(&commitment, &k, &u));
    }
}