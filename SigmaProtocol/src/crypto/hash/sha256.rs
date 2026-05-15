/// This Rust module is an implementation of the SHA-256 algorithm.
/// From https://github.com/keanemind/Python-SHA-256

// Inspired by: https://github.com/keanemind/python-sha-256/blob/master/sha256.py


use std::convert::TryInto;

pub const K: &[u32] = &[
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

pub struct SHA256 {
    h: [u32; 8],
    message: Vec<u8>,
    total_len: u64,
}

impl SHA256{

    pub fn new() -> Self{
        SHA256 {
            h: [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ],
            message: Vec::new(),
            total_len: 0,
        }
    }


    /// Helper function



    /// Rotate right operation
    /// Example: rotate_right(0b0001_0010_0011_0100_0101_0110_0111_1000, 4)
    /// -> 0b1000_0001_0010_0011_0100_0101_0110_0111
    fn rotate_right(x: u32, n: u32) -> u32{
        (x >> n) | (x << (32 - n))
    }

    /// Rotate left operation
    /// Example: rotate_left(0b0001_0010_0011_0100_0101_0110_0111_1000, 4)
    /// -> 0b0010_0011_0100_0101_0110_0111_1000_0001
    fn rotate_left(x: u32, n: u32) -> u32{
        (x << n) | (x >> (32 - n))
    }


    /// SHA-256 Σ0 function As defined in the specification.
    fn sigma0(x: u32) -> u32{
        (Self::rotate_right(x,7) ^ Self::rotate_right(x, 18)
         ^ (x >> 3))
    }

    /// SHA-256 Σ1 function As defined in the specification.
    fn sigma1(x: u32) -> u32{
        (Self::rotate_right(x,17) ^ Self::rotate_right(x, 19)
         ^ (x >> 10))
    }

    /// Capsigma0 function As defined in the specification.
    fn capsigma0(x: u32)->u32{
        (Self::rotate_right(x, 2) ^ Self::rotate_right(x, 13)
         ^ Self::rotate_right(x, 22))
    }

    /// Capsigma1 function As defined in the specification.
    fn capsigma1(x: u32)->u32{
        (Self::rotate_right(x, 6) ^ Self::rotate_right(x, 11)
         ^ Self::rotate_right(x, 25))
    }

    /// Choice function As defined in the specification.
    fn ch (x: u32, y: u32, z: u32) -> u32{
        (x & y) ^ ((!x) & z)
    }

    /// Majority function As defined in the specification.
    fn maj (x: u32, y: u32, z: u32) -> u32{
        (x & y) ^ (x & z) ^ (y & z)
    }

    ///mod 2^32 
    fn mod32(x: u64) -> u32{
        (x % 4294967296) as u32
    }

    /// SHA-256 Functions 
    
    /// Update the hash object with the bytes-like object data
    /// data: &[u8]
    pub fn update(&mut self, data: &[u8]){
        
        self.message.extend_from_slice(data);
        self.total_len += data.len() as u64;;
    }


    /// Return the digest of the data passed to the update() method so far.
    pub fn digest(&mut self) -> Vec<u8>{
        let mut h_working = self.h;
        let mut message = self.message.clone();
        let length = message.len() as usize * 8;

        message.push(0x80); 

        while (message.len() as usize * 8 + 64) % 512 != 0 {
            message.push(0x00);
        };
        
        message.extend_from_slice(&length.to_be_bytes());


        assert!(message.len()as usize * 8 % 512 == 0);

        let mut blocks = Vec::new();

        for bl in message.chunks(64){
            blocks.push(bl.to_vec());
        };
        let mut message_schedule = Vec::new();

        for message_block in blocks{
            message_schedule.clear();

            for t in 0..64{
                if t < 16{

                    message_schedule.push(
                        u32::from_be_bytes(message_block[t*4..t*4+4].try_into().unwrap())
                    );

                }else{

                    let term1 = Self::sigma1(message_schedule[t-2]);
                    let term2 = message_schedule[t-7];
                    let term3 = Self::sigma0(message_schedule[t-15]);
                    let term4 = message_schedule[t-16];
                    
                    let mut schedule_value = term1
                        .wrapping_add(term2)
                        .wrapping_add(term3)
                        .wrapping_add(term4);
                    
                    schedule_value = Self::mod32(schedule_value as u64);

                    message_schedule.push(schedule_value);
                }
            }

            assert! (message_schedule.len() == 64);

            let mut a = self.h[0];
            let mut b = self.h[1];
            let mut c = self.h[2];
            let mut d = self.h[3];
            let mut e = self.h[4];
            let mut f = self.h[5];
            let mut g = self.h[6];
            let mut h = self.h[7];
            
            for t in 0..64{
                let T1 = Self::mod32(
                    (h as u64)
                    + (Self::capsigma1(e) as u64)
                    + (Self::ch(e, f, g) as u64)
                    + (K[t] as u64)
                    + (message_schedule[t] as u64)
                );
                let T2 = Self::mod32(
                    (Self::capsigma0(a) as u64)
                    + (Self::maj(a, b, c) as u64)
                );

                h = g;
                g = f;
                f = e;
                e = Self::mod32((d as u64).wrapping_add(T1 as u64));
                d = c;
                c = b;
                b = a;
                a = Self::mod32((T1 as u64).wrapping_add(T2 as u64));
            }

            h_working[0] = Self::mod32((h_working[0] as u64).wrapping_add(a as u64));
            h_working[1] = Self::mod32((h_working[1] as u64).wrapping_add(b as u64));
            h_working[2] = Self::mod32((h_working[2] as u64).wrapping_add(c as u64));
            h_working[3] = Self::mod32((h_working[3] as u64).wrapping_add(d as u64));
            h_working[4] = Self::mod32((h_working[4] as u64).wrapping_add(e as u64));
            h_working[5] = Self::mod32((h_working[5] as u64).wrapping_add(f as u64));
            h_working[6] = Self::mod32((h_working[6] as u64).wrapping_add(g as u64));
            h_working[7] = Self::mod32((h_working[7] as u64).wrapping_add(h as u64));

        };
        let mut digest = Vec::new();
        for h_part in &h_working {
            digest.extend_from_slice(&h_part.to_be_bytes());
        }
        digest
        
    }


    /// Return the hexadecimal digest of the data passed to the update() method so far.
    pub fn hexdigest(&mut self) -> String {
        let digest = self.digest();
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

}



#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha256() {
        let mut sha256 = SHA256::new();
        sha256.update(b"hello world");
        let digest = sha256.hexdigest();
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        print!("Digest: ");
        println!("{}", digest);
        print!("Expected: ");
        println!("{}", expected_hex);
        assert_eq!(digest, expected_hex);
    }
    fn test_sha256_update(){
        let mut sha256 = SHA256::new();
        sha256.update(b"hello ");
        sha256.update(b"world");
        let digest = sha256.hexdigest();
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        print!("Digest: ");
        println!("{}", digest);
        print!("Expected: ");
        println!("{}", expected_hex);
        assert_eq!(digest, expected_hex);
    }

    fn test_sha256_test(){
        let mut sha256 = SHA256::new();
        sha256.update(b"Day chi la ban test SHA256");
        let digest = sha256.hexdigest();
        let expected_hex = "7557d8777fa1e11a546c378672dcb19b5e257bb8f94ba142efbeba1103a4af03";
        print!("Digest: ");
        println!("{}", digest);
        print!("Expected: ");
        println!("{}", expected_hex);
        assert_eq!(digest, expected_hex);
    }
}   