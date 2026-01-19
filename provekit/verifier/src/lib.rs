mod whir_r1cs;

use {
    crate::whir_r1cs::WhirR1CSVerifier,
    anyhow::Result,
    provekit_common::{
        Verifier, WhirDomainSep, WhirMerkleConfig, WhirR1CSProof, WhirVerifierState,
    },
    spongefish::{DomainSeparator, VerifierState},
    tracing::instrument,
};

pub trait Verify {
    fn verify(&mut self, proof: &[u8]) -> Result<()>;
}

/// Blanket implementation of `Verify` for all valid hash configurations.
/// This works for any `MerkleConfig` and `PowStrategy` that satisfy the WHIR
/// bounds.
impl<MerkleConfig, PowStrategy> Verify for Verifier<MerkleConfig, PowStrategy>
where
    MerkleConfig: WhirMerkleConfig,
    PowStrategy: spongefish_pow::PowStrategy,
    for<'a> VerifierState<'a, MerkleConfig::Sponge, MerkleConfig::Unit>:
        WhirVerifierState<MerkleConfig>,
    DomainSeparator<MerkleConfig::Sponge, MerkleConfig::Unit>: WhirDomainSep<MerkleConfig>,
{
    #[instrument(skip_all)]
    fn verify(&mut self, transcript: &[u8]) -> Result<()> {
        self.whir_for_witness
            .take()
            .unwrap()
            .verify(&WhirR1CSProof {
                transcript: transcript.to_vec(),
            })?;
        Ok(())
    }
}
