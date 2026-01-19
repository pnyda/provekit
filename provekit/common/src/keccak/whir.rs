//! WHIR integration for Keccak-based Merkle trees.
//!
//! Implements the necessary traits to use Keccak Merkle trees with WHIR's proof
//! system using Keccak for both Merkle commitments and Fiat-Shamir transcript.

use {
    crate::keccak::{KeccakDigest, KeccakMerkleConfig, KeccakSponge},
    spongefish::{BytesToUnitDeserialize, DomainSeparator, ProofResult, VerifierState},
};

/// Implementation of DigestDomainSeparator for Keccak Merkle with Keccak
/// Fiat-Shamir.
impl whir::whir::domainsep::DigestDomainSeparator<KeccakMerkleConfig>
    for DomainSeparator<KeccakSponge, u8>
{
    fn add_digest(self, label: &str) -> Self {
        // Keccak digest is 32 bytes
        self.absorb(32, label)
    }
}

/// Implementation of DigestToUnitDeserialize for Keccak Merkle with Keccak
/// Fiat-Shamir.
impl whir::whir::utils::DigestToUnitDeserialize<KeccakMerkleConfig>
    for VerifierState<'_, KeccakSponge, u8>
{
    fn read_digest(&mut self) -> ProofResult<KeccakDigest> {
        // Read 32 bytes from the Keccak sponge
        let bytes: [u8; 32] = self.next_bytes()?;
        Ok(bytes.into())
    }
}
