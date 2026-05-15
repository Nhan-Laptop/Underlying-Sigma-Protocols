/// Public parameters structure
/// Provides the public parameters for the Sigma protocol
use num_bigint::BigUint;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PublicParams {
    #[serde(rename = "n")] 
    pub N_hat: BigUint, 
    
    pub s: BigUint,  
    pub t: BigUint,  
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeParams{
    pub N0: BigUint,
    pub ell: usize,
    pub epsilon: usize,
}



impl PublicParams {
    pub fn load() -> Self {
        let path = "/home/nhanlaptop/CODING/SigmaProtocol/src/storage/public_params.json";
        let data = fs::read(path)
            .expect("cannot read public params");
        serde_json::from_slice(&data)
            .expect("invalid public params")
    }
}

impl RangeParams {
    pub fn load() -> Self {
        let path = "/home/nhanlaptop/CODING/SigmaProtocol/src/storage/range_params.json";
        let data = fs::read(path)
            .expect("cannot read range params");
        serde_json::from_slice(&data)
            .expect("invalid range params")
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_load_public_params() {
        let public_params = PublicParams::load();
        println!("Public params: {:?}", public_params);
    }

    fn test_load_range_params() {
        let range_params = RangeParams::load();
        println!("Range params: {:?}", range_params);
    }
}

