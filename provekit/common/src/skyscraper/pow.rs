use {
    skyscraper::pow::{solve, verify},
    spongefish_pow::PowStrategy,
    zerocopy::transmute,
};

/// Skyscraper proof of work
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SkyscraperPoW {
    challenge: [u64; 4],
    bits:      f64,
}

impl PowStrategy for SkyscraperPoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self {
            challenge: transmute!(challenge),
            bits,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        verify(self.challenge, self.bits, nonce)
    }

    fn solve(&mut self) -> Option<u64> {
        Some(solve(self.challenge, self.bits))
    }
}
