
/// Implementation of Paillier Cryptosystem
/// Reference: https://en.wikipedia.org/wiki/Paillier_cryptosystem
/// Reference: https://github.com/mikeivanov/paillier/blob/master/paillier/paillier.py

use crate::utils::rustcryptodome::number;
use crate::pow;

use crate::utils::random::Random;

use num_bigint::*;

use num_bigint::{BigInt, BigUint, ToBigInt, Sign};
use num_traits::{Zero, One, ToPrimitive, Signed};

#[derive(Debug, Clone)] 
pub struct PaillierPrivateKey{
    l: BigUint,
    p: BigUint,
    q: BigUint,
    m: BigUint,
}

impl PaillierPrivateKey{
    pub fn new(p: BigUint,q: BigUint) -> Self{
  
        let l = number::lcm(&(&p - BigUint::from(1u32))
        , &(&q - BigUint::from(1u32)));
        
        let n = &p * &q;
        
        let mut m = number::inverse(&l.to_biguint().unwrap(), &n.to_biguint().unwrap());
        
        if m.is_none(){
            panic!("Failed to compute modular inverse for Paillier key generation");
        }
        let m = m.unwrap();
        PaillierPrivateKey{
            l: l,
            p: p,
            q: q,
            m: m.to_biguint().unwrap(),
        }
    }
}

#[derive(Debug, Clone)] 
pub struct PaillierPublicKey{
    n: BigUint,
    n_sq: BigUint,
    g: BigUint,

}

// impl PaillierPublicKey{
//     pub fn new(private_key: &PaillierPrivateKey) -> Self{
//         let n = &private_key.p * &private_key.q;
//         let n_sq = &n * &n;
//         let g = &n + BigUint::one();

//         PaillierPublicKey{
//             n,
//             n_sq,
//             g,
//         }
        
//     }
    
// }
impl PaillierPublicKey{
    pub fn new(N: &BigUint) -> Self{
        let n = N.clone();
        let n_sq = &n * &n;
        let g = &n + BigUint::one();

        PaillierPublicKey{
            n,
            n_sq,
            g,
        }
        
    }
    
}

// pub struct PaillierCryptosystem{
//     private_key: PaillierPrivateKey,
//     public_key: PaillierPublicKey,
// }

#[derive(Debug, Clone)] 
pub struct PaillierCryptosystem{
    public_key: PaillierPublicKey,
}


/// Implementation of Paillier Cryptosystem
impl PaillierCryptosystem{

    /// Create a new Paillier cryptosystem with generated keys
    pub fn new(N: &BigUint) -> Self{
        let public_key = PaillierPublicKey::new(N);
        PaillierCryptosystem{
            public_key,
        }
    }
    pub fn get_n(&self) -> &BigUint{
        &self.public_key.n
    }
    
    pub fn get_n_sq(&self) -> &BigUint{
        &self.public_key.n_sq
    }


    /// Encrypt a plaintext message
    /// Example: encrypt(&BigUint::from(42u32)) 
    pub fn encrypt(&self, plaintext: &BigUint)-> BigUint{
        let mut rng = Random::new(None);
        let mut r = rng.randrange(BigUint::from(1u32)
        , Some(self.public_key.n.clone()),None);

        let mut gcd_val = number::gcd(&r, &self.public_key.n);
        while gcd_val != BigUint::one(){
            r = rng.randrange(BigUint::from(1u32)
            , Some(self.public_key.n.clone()),None);
            gcd_val = number::gcd(&r, &self.public_key.n);
        }
        let c1 = pow!(&self.public_key.g, plaintext, &self.public_key.n_sq);
        let c2 = pow!(&r, &self.public_key.n, &self.public_key.n_sq);
        let ciphertext = (c1 * c2) % &self.public_key.n_sq;
        ciphertext
    }

    /// Encrypt a plaintext message 
    /// ciphertext = encrypt_exp_k(k, rho)= (1+N0)^k * rho^N0 mod N0^2
    pub fn encrypt_exp_k(&self, k: &BigInt, rho: &BigUint) -> BigUint {
        let n_sq = &self.public_key.n_sq;
        let n = &self.public_key.n;
        
        // Protocol specifies base g = 1 + N
        let g = n + BigUint::one(); 

        let r_pow_n = pow!(rho, n, n_sq);

        match k {
            val if val.is_negative() => {
                let abs_k = val.abs().to_biguint().unwrap();
                let g_pow_abs_k = pow!(&g, &abs_k, n_sq);
                
                // Calculate inverse of g^|k|
                let g_pow_neg_k_int = number::inverse(&g_pow_abs_k, n_sq)
                    .expect("Inverse failed for g^|k|");
                
                // Safe conversion from BigInt to BigUint
                let g_pow_neg_k = g_pow_neg_k_int.to_biguint().unwrap_or_else(|| {
                     let m_int = n_sq.to_bigint().unwrap();
                     let pos_val = ((g_pow_neg_k_int % &m_int) + &m_int) % &m_int;
                     pos_val.to_biguint().unwrap()
                });

                (g_pow_neg_k * r_pow_n) % n_sq
            },
            val if val.is_zero() => r_pow_n,
            val => {
                let k_pos = val.to_biguint().unwrap();
                let g_pow_k = pow!(&g, &k_pos, n_sq);
                (g_pow_k * r_pow_n) % n_sq
            }
        }
    }

    /// Decrypt a ciphertext message
    /// Example: decrypt(&ciphertext)
    // pub fn decrypt(&self, ciphertext: &BigUint) -> BigUint{
    //     let x: BigUint = pow!(ciphertext, &self.private_key.l, &self.public_key.n_sq) - BigUint::from(1u32); ;
    //     let plain: BigUint = (x / &self.public_key.n) * &self.private_key.m % &self.public_key.n;
    //     plain
        
    // }

    /// Homomorphic addition of two ciphertexts
    /// Example: homomorphic_add(&c1, &c2)
    /// Add one encrypted integer to another
    pub fn homomorphic_add(&self,a: &BigUint, b: &BigUint) -> BigUint{
        (a * b) % &self.public_key.n_sq
    }


    pub fn homomorphic_add_const(&self, a: &BigUint, b: &BigUint) -> BigUint{
        a * pow!(&self.public_key.g, b, &self.public_key.n_sq) % &self.public_key.n_sq
    }

    /// Homomorphic multiplication of a ciphertext with a plaintext
    /// Example: homomorphic_mul(&c, &m)
    /// Multiply an encrypted integer with a plaintext integer
    pub fn homomorphic_mul(&self, c: &BigUint, m: &BigUint) -> BigUint{
        pow!(c, m, &self.public_key.n_sq)
    }

    pub fn homomorphic_mul_const(&self, c: &BigUint, k: &BigUint) -> BigUint{
        pow!(c, k, &self.public_key.n_sq)
    }

    /// Check if a ciphertext is well-formed
    pub fn is_well_formed(&self, c: &BigUint) -> bool{
        c < &self.public_key.n_sq
    }

}


#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_paillier_keygen(){
        for i in 0..10{
            let p = number::get_prime(512).to_biguint().unwrap();
            let q = number::get_prime(512).to_biguint().unwrap();
            let n = &p * &q;
            
            let paillier = PaillierCryptosystem::new(&n);

            assert_eq!(paillier.public_key.n, n);
            println!("Test Paillier keygen {} passed!", i+1);
        }
    }   
}   


