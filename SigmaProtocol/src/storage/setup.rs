/// This module contains storage setup functionalities. 
/// Provides: 
/// RSA params - Pedersen params

use crate::utils::random::Random;
use crate::utils::rustcryptodome::number;
use crate::pow;

use num_bigint::*;
use num_traits::{Zero, One,ToPrimitive};
use serde::{Serialize, Deserialize};

use std::fs::File;
use std::io::Write;


pub struct Parameters{
    
    /// RSA params
    pub p: BigUint,// secret
    pub q: BigUint,// secret
    pub n: BigUint,


    /// Pedersen params
    pub τ: BigUint,// secret
    pub s: BigUint,
    pub t: BigUint,
    pub d: BigUint,// secret for Pedersen
}

#[derive(Serialize, Deserialize)]
pub struct PublicParams {
    pub n: BigUint,
    pub s: BigUint,
    pub t: BigUint,
}

#[derive(Serialize, Deserialize)]
pub struct SecretParams {
    pub p: BigUint,
    pub q: BigUint,
    pub tau: BigUint,
    pub d: BigUint,
}


impl Parameters{
    pub fn get_strong_prime(bits: usize)->BigUint{
        let mut p = BigInt::from(0u32);
        while !number::is_prime(&p){
            let q = number::get_prime(bits - 1);
            p = BigInt::from(2u32)*q + BigInt::from(1u32);
        }
        p.to_biguint().unwrap()
    }
    pub fn new(bits: Option<usize>)-> Self{
        let bits = match bits{
            Some(b) => b,
            None => 1024,
        };
        let mut rng = Random::new(None);
        let p = number::get_prime(bits).to_biguint().unwrap();
        let q = number::get_prime(bits).to_biguint().unwrap();
        let mut n = &p * &q;

        let mut  τ = rng.randint(BigUint::one(), (&n - BigUint::one()));

        let mut gcd_tau_n = number::gcd(&τ, &n);

        while gcd_tau_n != BigUint::one() {
            τ = rng.randint(BigUint::one(), (&n - BigUint::one()));
            gcd_tau_n = number::gcd(&(τ.clone()), &(n.clone()));
        }
        
        let d = rng.getrandbits(Some(256));

        let t = pow!(&τ, BigUint::from(2u32), &n);
        let s = pow!(&τ, &(d.clone()*2u32), &n);

        Parameters{
            p,
            q,
            n,
            τ,
            s,
            t,
            d,
        }


    }

    pub fn split(self) -> (PublicParams, SecretParams) {
        (
            PublicParams {
                n: self.n.clone(),
                s: self.s.clone(),
                t: self.t.clone(),
            },
            SecretParams {
                p: self.p,
                q: self.q,
                tau: self.τ,
                d: self.d,
            },
        )
    }
    pub fn save(self, base_path: &str) {
        let (public, secret) = self.split();

        save_to_file(
            &format!("{}/public_params.json", base_path),
            &public,
        );

        save_to_file(
            &format!("{}/secret_params.json", base_path),
            &secret,
        );
    }
 
}

#[cfg(test)]

mod tests{
    use super::*;

    #[test]
    fn test_parameters(){
        let params = Parameters::new(Some(512));
        println!("p: {:?}", params.p);
        println!("q: {:?}", params.q);
        println!("n: {:?}", params.n);
        println!("τ: {:?}", params.τ);
        println!("s: {:?}", params.s);
        println!("t: {:?}", params.t);
        println!("d: {:?}", params.d);
    }
}

fn save_to_file<T: Serialize>(path: &str, obj: &T) {
    let data = serde_json::to_vec_pretty(obj)
        .expect("serialize failed");
    let mut file = File::create(path)
        .expect("cannot create file");
    file.write_all(&data)
        .expect("write failed");
}

fn load_from_file<T: for<'a> Deserialize<'a>>(path: &str) -> T {
    let data = std::fs::read(path)
        .expect("cannot read file");
    serde_json::from_slice(&data)
        .expect("deserialize failed")
}

