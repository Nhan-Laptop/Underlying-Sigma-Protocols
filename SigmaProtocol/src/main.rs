mod utils;
mod crypto;
mod storage;
mod zkproofs;
use num_bigint::*;
use utils::rustcryptodome::number;
use crate::storage::Load_public_params::PublicParams;
use crate::storage::secret::SecretParams;
use crate::zkproofs::{modulus_zk_proof::challenge::challenge as modulus_challenge,
        range_zk_proof::challenge::challenge as range_challenge,
    pederson_zk_proof::challenge::challenge as pederson_challenge,
};

fn main() {
    let mut modulus_challenge = modulus_challenge::new();
    let mut range_challenge = range_challenge::new();
    let mut pederson_challenge = pederson_challenge::new();

    modulus_challenge.paillier_modulus_ZK_protocol_chain();
    range_challenge. paillier_encryption_in_range_ZK_II();
    pederson_challenge.full_m_protocol();
    

}