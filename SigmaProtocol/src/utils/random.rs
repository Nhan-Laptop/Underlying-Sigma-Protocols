use core::panic;
/// Mersenne Twister MT19937 implementation
/// Reference: https://en.wikipedia.org/wiki/Mersenne_Twister
/// This implementation is based on the original C code by Takuji Nishimura and Makoto Matsumoto


use std::vec;
use std::time::{SystemTime, UNIX_EPOCH};
use num_bigint::*;
use num_traits::{Zero, One,ToPrimitive};
use std::cmp::min;

const N: usize = 624;
const M: usize = 397;

const W: u32 = 32;
const R: u32 = 31;


const A: u32 = 0x9908b0df;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9d2c5680;
const T: u32 = 15;
const C: u32 = 0xefc60000;
const L: u32 = 18;
const F: u32 = 1812433253;

const w1: u32 = 1 << (W -1);
const lmsk: u32 = 0x7fffffff;
const umsk: u32 = 0x80000000;



pub struct MT19937 {
    index: usize,
    mt: [u32; N],
}

/// MT19937 methods in C++ style
impl MT19937{
    
    pub fn new(seed: Option<u32>)-> Self{

        let mut mt = [0u32; N];
        let mut seed_val = match seed{
            Some(s) => s,
            None => {
                let start = SystemTime::now();
                let since_the_epoch = start.duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                (since_the_epoch.as_secs() as u32)
                .wrapping_add(since_the_epoch.subsec_nanos())
            } 

        };
        mt[0] = seed_val; 
        
        for i in 1..N{
            
            let prev = mt[i-1];
            mt[i] = F.wrapping_mul(prev ^ (prev >> 30))
            .wrapping_add(i as u32);

        }

        MT19937{
            index: N,
            mt,
        }

    }
    fn twist(&mut self){
        
        for i in 0..N{
            
            let tmp = ((self.mt[i] & umsk)
                | (self.mt[(i+1)%N])
                & lmsk);
            
            let mut tmpA = tmp >>1;

            if tmp % 2 == 1 {
                tmpA ^= A;
            }
            
            self.mt[i] = self.mt[(i + M) % N] ^ tmpA;
            
        }

        self.index = 0;

    }
    
    fn temper(&mut self) ->u32{
        if self.index >= N{
            self.twist();
        }
        let mut y = self.mt[self.index];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

        self.index += 1;
        y

    }
    
    /// Get random bits as BigUint
    pub fn _getrandbits_word(&mut self, k: usize)->u32{
        if k <= 0 || k > W as usize {
            panic!("number of bits must be in (0, 32]");
        }
        let r = self.temper();
        if k == W as usize {
            return r;
        }
        return r & ((1 << k) -1);
    }


    /// Get random bits as BigUint
    pub fn getrandbits(&mut self, k: Option<usize>)->BigUint{
        let mut k_val = k.unwrap_or(W as usize);
        if k <= Some(0){
            panic!("number of bits must be greater than zero");
        }
        if k_val <= 32 {
            return BigUint::from(self._getrandbits_word(k_val));
        }

        let mut k = match k {
            Some(val) => val,
            None => W as usize,
        };

        let words = (k-1)/ W as usize + 1;
        let mut result = BigUint::zero();

        for i in 0..words {
            let bits_to_take = min(k_val, W as usize);
            
            let r = self._getrandbits_word(bits_to_take);
            result |= BigUint::from(r) << (i * W as usize);

            // FIX: Trừ đúng số bit đã lấy để tránh Underflow
            k_val -= bits_to_take;
        }
        result
    }


}


/// Random in python style
/// The implementation is inspired: https://chromium.googlesource.com/external/github.com/python/cpython/%2B/refs/tags/v3.6.5/Lib/random.py

pub struct Random{
    engine: MT19937,
}

impl Random{

    pub fn new(seed: Option<u32>)-> Self{

        let mut instance = Random{
            engine: MT19937::new(seed),
        };
        if let Some(s) = seed{
            instance.seed(BigUint::from(s));
        }
        instance
    }

    pub fn seed(&mut self, mut n: BigUint) {
        let mut keys: Vec<u32> = Vec::new();
        
        if n.is_zero() {
             keys.push(0);
        } else {
            while !n.is_zero() {
                let mask = BigUint::from(1u32) << 32; 
                let rem: BigUint = &n % mask;
                let low_bits = rem.to_u32().unwrap_or(0);
                
                keys.push(low_bits);
                n >>= 32;
            }
        }
        
        self.init_by_array(&keys);
    }

    pub fn init_by_array(&mut self, keys: &[u32]) {
        self.engine = MT19937::new(Some(19650218));

        let mut i: usize = 1;
        let mut j: usize = 0;
        let len_keys = keys.len();
        let loop_count = std::cmp::max(N, len_keys);

        for _ in 0..loop_count {
            
            let prev = self.engine.mt[i - 1];
            let x = (prev ^ (prev >> 30)).wrapping_mul(1664525); 
            
            self.engine.mt[i] = (self.engine.mt[i] ^ x)
                .wrapping_add(keys[j])
                .wrapping_add(j as u32);
            
            i += 1;
            j += 1;

            if i >= N {
                self.engine.mt[0] = self.engine.mt[N - 1];
                i = 1;
            }
            if j >= len_keys {
                j = 0;
            }
        }

        for _ in 0..(N - 1) {
            
            let prev = self.engine.mt[i - 1];
            let y = (prev ^ (prev >> 30)).wrapping_mul(1566083941); 
            
            self.engine.mt[i] = (self.engine.mt[i] ^ y).wrapping_sub(i as u32);
            
            i += 1;
            if i >= N {
                self.engine.mt[0] = self.engine.mt[N - 1];
                i = 1;
            }
        }

        self.engine.mt[0] = 0x80000000;
    }
    
    /// Get random bits as BigUint
    pub fn getrandbits(&mut self, k: Option<usize>) -> BigUint {
        self.engine.getrandbits(k)
    }

    /// Get a random integer in [0, n)
    pub fn _randbelow(&mut self, n: &BigUint)-> BigUint{

        if n.is_zero(){
            panic!("n must be greater than zero");
        }
        let bits = n.bits();
        let mut r: BigUint = BigUint::zero();
        
        r = self.getrandbits(Some(bits as usize));
        
        while &r >= n {
            r = self.getrandbits(Some(bits as usize));
        }

        return r;

    }

    /// Get a random integer in [start, stop) with step
    pub fn randrange(&mut self, start: BigUint, stop: Option<BigUint>, step: Option<BigUint>) -> BigUint {
     
        let (eff_start, eff_stop) = match stop {
        Some(s) => (start, s),
        None => (BigUint::zero(), start), 
        };

        let eff_step = step.unwrap_or(BigUint::one());

        if eff_step.is_zero() {
            panic!("step must be greater than zero");
        }

        if &eff_start >= &eff_stop {
            panic!("empty range for randrange()");
        }

        let width = &eff_stop - &eff_start;

        if eff_step.is_one()  {
            return &eff_start + self._randbelow(&width);
        }

        let n = (&width + &eff_step - BigUint::one()) / &eff_step;
        let k = self._randbelow(&n);
        &eff_start + k * &eff_step
        
    }


    /// Get a random integer in [a, b] inclusive
    pub fn randint(&mut self, a: BigUint, b: BigUint) -> BigUint {
        if a > b {
            panic!("a must be less than or equal to b");
        }
        self.randrange(a, Some(b + BigUint::one()), None)
    }

    pub fn choice<T: Clone>(&mut self, seq: &[T]) -> T {
        if seq.is_empty() {
            panic!("Cannot choose from an empty sequence");
        }
        let index = self._randbelow(&BigUint::from(seq.len())).to_usize().unwrap();
        seq[index].clone()
    }

    /// Get a random integer in [-a,b] inclusive
    pub fn randint_signed(&mut self, a: BigInt, b: BigInt) -> BigInt {
        if a > b {
            panic!("a must be less than or equal to b");
        }
        let range = (&b - &a + BigInt::one()).to_biguint().unwrap();
        let rand_offset = self.randrange(BigUint::zero(), Some(range), None);
        a + rand_offset.to_bigint().unwrap()
    }

    /// Shuffle a mutable slice in place
    pub fn shuffle<T>(&mut self, x: &mut [T]) {
        let len = x.len();
        for i in (1..len).rev() {
            let j = self._randbelow(&BigUint::from(i + 1)).to_usize().unwrap();
            x.swap(i, j);
        }
    }


    /// Sample k unique elements from a population
    pub fn sample<T: Clone>(&mut self, population: &[T], k: usize) -> Vec<T> {
        let n = population.len();
        if k > n {
            panic!("Sample larger than population");
        }

        let mut indices: Vec<usize> = (0..n).collect();
        self.shuffle(&mut indices);

        let selected_indices = &indices[0..k];
        let mut result: Vec<T> = Vec::with_capacity(k);
        for &i in selected_indices {
            result.push(population[i].clone());
        }
        result
    }
    

    /// Generate n random bytes
    pub fn randbytes(&mut self, n: usize) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(n);
        let mut bytes_needed = n;

        while bytes_needed > 0 {
            let r = self.getrandbits(Some(32));
            let r_bytes = r.to_bytes_le();

            for &byte in &r_bytes {
                if bytes_needed == 0 {
                    break;
                }
                result.push(byte);
                bytes_needed -= 1;
            }
        }

        result
    }

} 


#[cfg(test)]

mod tests{

    #[test]
    fn test_mt19937(){
        use super::*;
        let mut rng = Random::new(Some(123));
        
        let r1 = rng.getrandbits(Some(64));

        let mut rng2 = Random::new(None);
        let r2 = rng2.getrandbits(Some(64));

        println!("Random 1: {:?}", r1); 
        println!("Random 2: {:?}", r2);
    }
}