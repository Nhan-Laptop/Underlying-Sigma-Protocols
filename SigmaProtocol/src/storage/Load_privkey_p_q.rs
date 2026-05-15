/// Public parameters structure
/// Provides the public parameters for the Sigma protocol
use num_bigint::BigUint;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SecretPedersenParams{
    pub N_hat: BigUint,
    pub tau: BigUint,
    pub d: BigUint,
    pub p: BigUint,
    pub q: BigUint, 
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretPaillierParams{
    pub p: BigUint,
    pub q: BigUint,
}




impl SecretPedersenParams {
    pub fn load() -> Self {
        let path = "/home/nhanlaptop/CODING/SigmaProtocol/src/storage/secret_params.json";
        let data = fs::read(path)
            .expect("cannot read public params");
        serde_json::from_slice(&data)
            .expect("invalid public params")
    }
}

impl SecretPaillierParams {
    pub fn load() -> Self {
        let path = "/home/nhanlaptop/CODING/SigmaProtocol/src/storage/secret_prover_paillier.json";
        let data = fs::read(path)
            .expect("cannot read secret prover paillier params");
        serde_json::from_slice(&data)
            .expect("invalid secret prover paillier params")
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_load_secret_params() {
        let secret_params = SecretPedersenParams::load();
        println!("Secret params: {:?}", secret_params);
    }

    fn test_load_secret_prover_params() {
        let secret_prover_params = SecretPaillierParams::load();
        println!("Secret prover params: {:?}", secret_prover_params);
    }
}

