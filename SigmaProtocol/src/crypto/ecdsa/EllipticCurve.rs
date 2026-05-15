
use crate::utils::rustcryptodome::number;
use crate::pow;

use crate::utils::random::Random;

use num_bigint::*;

use num_bigint::{BigInt, BigUint, ToBigInt, Sign};
use num_traits::{Zero, One, ToPrimitive,Num};



#[derive(Debug, Clone, PartialEq)]
pub struct EllipticCurve {
    pub a: BigInt,
    pub b: BigInt,
    pub p: BigUint,
    pub G: (BigInt, BigInt),
    pub n: BigUint,
}

/// Secp256r1: https://std.neuromancer.sk/secg/secp256r1
/// ECC: y^2 = x^3 + ax + b over finite field F_p
impl EllipticCurve {
    pub fn new(a: BigInt, b: BigInt, p: BigUint, G: (BigInt, BigInt), n: BigUint) -> Self {
        EllipticCurve { a, b, p, G, n }
    }
    pub fn secp256r1()-> Self{
        let p1 = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        let a1 = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"; // a = -3 mod p
        let b1 = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
        let gx1 = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let gy1 = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let n1 = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

        let p = BigUint::from_str_radix(p1, 16).unwrap();
        let n = BigUint::from_str_radix(n1, 16).unwrap();
        
        // a, b, Gx, Gy là BigInt
        let a = BigInt::from_str_radix(a1, 16).unwrap();
        let b = BigInt::from_str_radix(b1, 16).unwrap();
        let gx = BigInt::from_str_radix(gx1, 16).unwrap();
        let gy = BigInt::from_str_radix(gy1, 16).unwrap();

        EllipticCurve {
            a,
            b,
            p,
            G: (gx, gy),
            n,
        }
    }

    /// Helper: Compute n mod p
    /// Ensure the answer in  [0, p-1]
    fn reduce(&self, n: &BigInt) -> BigInt {
        let p_int = self.p.to_bigint().unwrap();
        ((n % &p_int) + &p_int) % &p_int
    }

    /// Helper: Compute n mod p and return as BigUint
    /// Ensure the answer in  [0, p-1]
    fn to_biguint_safe(&self, n: &BigInt) -> BigUint {
        self.reduce(n).to_biguint().unwrap()   
    }

    /// Check Point is on the curve
    pub fn check_point(&self, p_coords: &(BigInt, BigInt)) -> bool {
        let (x, y) = p_coords;
        if x.is_zero() && y.is_zero() { return true; }

        let p_int = self.p.to_bigint().unwrap();

        let lhs = pow!(y, BigInt::from(2), &p_int); 
        
        let x3 = pow!(x, BigInt::from(3), &p_int);
        let ax = (x * &self.a); 
        let rhs_raw = x3 + ax + &self.b;
        
        let rhs = self.reduce(&rhs_raw);

        lhs == rhs
    }

    pub fn point_inverse(&self, P: &(BigInt, BigInt)) -> (BigInt, BigInt) {
        let (x, y) = P;
        if x.is_zero() && y.is_zero() 
            { return (BigInt::zero(), BigInt::zero()); }
        let p_bigint = self.p.to_bigint().unwrap();
        let y_inv = self.reduce(&-y);
        (x.clone(), y_inv)
    }

    /// Point Addition: P1 + P2
    pub fn point_addition(&self, p1: &(BigInt, BigInt), p2: &(BigInt, BigInt)) -> (BigInt, BigInt) {
        let (x1, y1) = p1;
        let (x2, y2) = p2;
        let p_int = self.p.to_bigint().unwrap();

        if x1.is_zero() && y1.is_zero() { return p2.clone(); }
        if x2.is_zero() && y2.is_zero() { return p1.clone(); }

        let lam = if x1 == x2 && y1 == y2 {
            if y1.is_zero() { return (BigInt::zero(), BigInt::zero()); }

            let num = BigInt::from(3) * pow!(x1, BigInt::from(2), &p_int) + &self.a;
            let den = BigInt::from(2) * y1;
            
            let den_inv = number::inverse(&self.to_biguint_safe(&den), &self.p)
                .unwrap();
            
            self.reduce(&(num * den_inv))
        } else {
            let dy = y2 - y1;
            let dx = x2 - x1;

            if self.reduce(&dx).is_zero() {
                return (BigInt::zero(), BigInt::zero()); 
            }
            
            let dx_inv = number::inverse(&self.to_biguint_safe(&dx), &self.p)
                .unwrap();

            self.reduce(&(dy * dx_inv))
        };

        let x3_val = pow!(&lam, BigInt::from(2), &p_int) - x1 - x2;
        let x3 = self.reduce(&x3_val);

        let y3_val = &lam * (x1 - &x3) - y1;
        let y3 = self.reduce(&y3_val);

        (x3, y3)
    }

    pub fn double_and_add(&self, k: &BigUint, p_point: &(BigInt, BigInt)) -> (BigInt, BigInt) {
        let mut result = (BigInt::zero(), BigInt::zero()); // Bắt đầu từ điểm vô cực
        let mut addend = p_point.clone();
        
        let mut k_loop = k.clone();
        
        while !k_loop.is_zero() {
            if &k_loop & BigUint::one() == BigUint::one() {
                result = self.point_addition(&result, &addend);
            }
            addend = self.point_addition(&addend, &addend);
            
            k_loop >>= 1;
        }
        result
    }

    pub fn scalar_multiplication(&self, k: &BigUint, p_point: &(BigInt, BigInt)) -> (BigInt, BigInt) {
        self.double_and_add(k, p_point)
    }


}

#[cfg(test)]

mod tests {
    use super::*;
    #[test]
    fn test_elliptic_curve_creation() {
        let curve = EllipticCurve::new(
            BigInt::from(0),
            BigInt::from(7),
            BigUint::from(97u32),
            (BigInt::from(3), BigInt::from(6)),
            BigUint::from(5u32),
        );
        assert_eq!(curve.a, BigInt::from(0));
        assert_eq!(curve.b, BigInt::from(7));
        assert_eq!(curve.p, BigUint::from(97u32));
        assert_eq!(curve.G, (BigInt::from(3), BigInt::from(6)));
        assert_eq!(curve.n, BigUint::from(5u32));
    }

    fn test_elliptic_curve_creation_secp256r1() {
        let curve = EllipticCurve::secp256r1();
        assert_eq!(curve.a, BigInt::from_str_radix("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16).unwrap());
        assert_eq!(curve.b, BigInt::from_str_radix("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16).unwrap());
        assert_eq!(curve.G, (
            BigInt::from_str_radix("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16).unwrap(),
            BigInt::from_str_radix("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16).unwrap()
        ));
        assert_eq!(curve.p, BigUint::from_str_radix("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16).unwrap());
        assert_eq!(curve.n, BigUint::from_str_radix("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16).unwrap());
    }   

    fn test_point_on_curve() {
        let curve = EllipticCurve::new(
            BigInt::from(0),
            BigInt::from(7),
            BigUint::from(97u32),
            (BigInt::from(3), BigInt::from(6)),
            BigUint::from(5u32),
        );
        let point = (BigInt::from(3), BigInt::from(6));
        assert!(curve.check_point(&point));

        let invalid_point = (BigInt::from(10), BigInt::from(10));
        assert!(!curve.check_point(&invalid_point));
    }
    

}