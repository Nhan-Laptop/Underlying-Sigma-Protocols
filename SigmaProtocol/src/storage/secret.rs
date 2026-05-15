/// Secret parameters storage
/// Provides the secret parameters for the Sigma protocol

use num_bigint::BigUint;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretParams {
    pub p: BigUint,
    pub q: BigUint,
    pub tau: BigUint,
    pub d: BigUint,
}

use std::fs;

impl SecretParams {
    pub fn load(path: &str) -> Self {
        let data = fs::read(path)
            .expect("cannot read secret params");
        serde_json::from_slice(&data)
            .expect("invalid secret params")
    }
}