
/// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm


use crate::utils::rustcryptodome::number;
use crate::pow;

use crate::crypto::ecdsa::EllipticCurve::EllipticCurve;
use crate::utils::random::Random;
use crate::crypto::hash::sha256;
use crate::crypto::paillier::PaillierCryptosystem;

use num_bigint::*;

use num_bigint::{BigInt, BigUint, ToBigInt, Sign};
use num_traits::{Zero, One, ToPrimitive};


pub struct ECDSASignature{
    pub r: BigUint,
    pub s: BigUint,
    pub P: (BigUint, BigUint),
    priv_key: BigUint,
    pub curve: EllipticCurve,

}


impl ECDSASignature{
    pub fn new(priv_key: Option<BigUint>)->Self{
        let  curve: EllipticCurve = EllipticCurve::secp256r1();
        let priv_key = match priv_key{
            Some(k) => k,
            None => {
                let mut rng = Random::new(None);
                rng.randint(BigUint::from(1u32), curve.n.clone())
            },
        };
        let pub_key_point = curve.scalar_multiplication(&priv_key, &curve.G);
        ECDSASignature{
            r: BigUint::zero(),
            s: BigUint::zero(),
            P: (pub_key_point.0.to_biguint().unwrap(), pub_key_point.1.to_biguint().unwrap()),
            priv_key: priv_key,
            curve: curve,
        }
    }

    // Sign a message
    /// Return (r, s)
    pub fn sign(&mut self, message: &[u8]) -> (BigUint, BigUint){
        let mut rng = Random::new(None);
        let mut hash_256 = sha256::SHA256::new();
        hash_256.update(message);
        let hash_bytes = hash_256.digest();
        let e = BigUint::from_bytes_be(&hash_bytes);

        loop{
            let k = rng.randint(BigUint::from(1u32), self.curve.n.clone());
            let point = self.curve.scalar_multiplication(&k, &self.curve.G);
            let r = point.0.to_biguint().unwrap() % &self.curve.n;
            if r.is_zero(){
                continue;
            }
            let k_inv_opt = number::inverse(&k, &self.curve.n);
            if k_inv_opt.is_none(){
                continue;
            }
            let k_inv = k_inv_opt.unwrap().to_biguint().unwrap();
            let s = (k_inv * ( &e + &r * &self.priv_key)) % &self.curve.n;
            if s.is_zero(){
                continue;
            }
            self.r = r.clone();
            self.s = s.clone();
            return (r, s);
        }
    }
    
    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &(BigUint, BigUint)) -> bool{
        let r = &signature.0;
        let s = &signature.1;
        if r.is_zero() || r >= &self.curve.n || s.is_zero() || s >= &self.curve.n{
            return false;
        } 
        let mut hash_256 = sha256::SHA256::new();
        hash_256.update(message);
        let hash_bytes = hash_256.digest();
        let e = BigUint::from_bytes_be(&hash_bytes);
        let s_inv_opt = number::inverse(s, &self.curve.n);
        if s_inv_opt.is_none(){
            return false;
        }
        let s_inv = s_inv_opt.unwrap().to_biguint().unwrap();
        let u1 = ( &e * &s_inv) % &self.curve.n;
        let u2 = ( r * &s_inv) % &self.curve.n;
        let point1 = self.curve.scalar_multiplication(&u1, &self.curve.G);
        let pub_key_point = (self.P.0.to_bigint().unwrap(), self.P.1.to_bigint().unwrap());
        let point2 = self.curve.scalar_multiplication(&u2, &pub_key_point);
        
        let point_x = self.curve.point_addition(&point1, &point2);
        if point_x.0.is_zero() && point_x.1.is_zero() {
            return false;
        }

        let v = point_x.0.to_biguint().unwrap() % &self.curve.n;
        
        v == *r

    }

}   

#[cfg(test)]

mod tests {
    use super::*;
    #[test]
    fn test_ecdsa_signature(){
        let mut ecdsa = ECDSASignature::new(None);
        println!("ECDSA Private Key: {:?}", ecdsa.priv_key);
        println!("Curve: {:?}", ecdsa.curve);
        println!("Public Key Point P: {:?}", ecdsa.P);
        println!("------------------\n");
        let message=  b"Hello, this is a test message for ECDSA signing.";
        let signature = ecdsa.sign(message);
        println!("Signature: (r: {:?}, s: {:?})", signature.0, signature.1);
        let is_valid = ecdsa.verify(message, &signature);
        println!("Is the signature valid? {}", is_valid);
        assert!(is_valid);
    }
}