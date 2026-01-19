//! WHIR integration for BLAKE3-based Merkle trees.
//!
//! Implements the necessary traits to use BLAKE3 Merkle trees with WHIR's proof
//! system using BLAKE3 for both Merkle commitments and Fiat-Shamir transcript.

use {
    crate::blake3::{Blake3Digest, Blake3MerkleConfig, Blake3Sponge},
    spongefish::{BytesToUnitDeserialize, DomainSeparator, ProofResult, VerifierState},
};

/// Implementation of DigestDomainSeparator for BLAKE3 Merkle with BLAKE3
/// Fiat-Shamir.
impl whir::whir::domainsep::DigestDomainSeparator<Blake3MerkleConfig>
    for DomainSeparator<Blake3Sponge, u8>
{
    fn add_digest(self, label: &str) -> Self {
        // BLAKE3 digest is 32 bytes
        self.absorb(32, label)
    }
}

/// Implementation of DigestToUnitDeserialize for BLAKE3 Merkle with BLAKE3
/// Fiat-Shamir.
impl whir::whir::utils::DigestToUnitDeserialize<Blake3MerkleConfig>
    for VerifierState<'_, Blake3Sponge, u8>
{
    fn read_digest(&mut self) -> ProofResult<Blake3Digest> {
        // Read 32 bytes from the BLAKE3 sponge
        let bytes: [u8; 32] = self.next_bytes()?;
        Ok(bytes.into())
    }
}
