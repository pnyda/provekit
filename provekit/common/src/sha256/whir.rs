//! WHIR integration for SHA256-based Merkle trees.
//!
//! Implements the necessary traits to use SHA256 Merkle trees with WHIR's proof
//! system using SHA256 for both Merkle commitments and Fiat-Shamir transcript.

use {
    crate::sha256::{Sha256Digest, Sha256MerkleConfig, Sha256Sponge},
    spongefish::{BytesToUnitDeserialize, DomainSeparator, ProofResult, VerifierState},
};

/// Implementation of DigestDomainSeparator for SHA256 Merkle with SHA256
/// Fiat-Shamir.
impl whir::whir::domainsep::DigestDomainSeparator<Sha256MerkleConfig>
    for DomainSeparator<Sha256Sponge, u8>
{
    fn add_digest(self, label: &str) -> Self {
        // SHA256 digest is 32 bytes
        self.absorb(32, label)
    }
}

/// Implementation of DigestToUnitDeserialize for SHA256 Merkle with SHA256
/// Fiat-Shamir.
impl whir::whir::utils::DigestToUnitDeserialize<Sha256MerkleConfig>
    for VerifierState<'_, Sha256Sponge, u8>
{
    fn read_digest(&mut self) -> ProofResult<Sha256Digest> {
        // Read 32 bytes from the SHA256 sponge
        let bytes: [u8; 32] = self.next_bytes()?;
        Ok(Sha256Digest(bytes))
    }
}
