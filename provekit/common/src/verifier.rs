use {
    crate::{hash_config::TypedHashConfig, whir_r1cs::WhirR1CSScheme, HashConfig},
    serde::{Deserialize, Serialize},
};

/// A verifier for a Noir Proof Scheme
/// Generic over MerkleConfig and PowStrategy to support different hash
/// algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Verifier<
    MerkleConfig = crate::skyscraper::SkyscraperMerkleConfig,
    PowStrategy = crate::skyscraper::SkyscraperPoW,
> where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    pub hash_config:      HashConfig,
    pub whir_for_witness: Option<WhirR1CSScheme<MerkleConfig, PowStrategy>>,
}
