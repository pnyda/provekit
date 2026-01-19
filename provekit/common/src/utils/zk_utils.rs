use {
    crate::FieldElement, ark_ff::UniformRand, rayon::prelude::*,
    whir::poly_utils::evals::EvaluationsList,
};

pub fn create_masked_polynomial(
    original: EvaluationsList<FieldElement>,
    mask: &[FieldElement],
) -> EvaluationsList<FieldElement> {
    let mut combined = Vec::with_capacity(original.num_evals() * 2);
    combined.extend_from_slice(original.evals());
    combined.extend_from_slice(mask);
    EvaluationsList::new(combined)
}
