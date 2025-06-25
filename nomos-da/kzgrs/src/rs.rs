use std::ops::{Add as _, Mul as _, Neg as _};

use ark_bls12_381::Fr;
use ark_ff::{BigInteger as _, Field as _, PrimeField as _};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial as _, EvaluationDomain as _, Evaluations,
    GeneralEvaluationDomain,
};
use num_traits::Zero as _;

/// Extend a polynomial over some factor `polynomial.len()*factor` and return
/// the original points plus the extra ones.
///
/// `factor` need to be `>1`
#[must_use]
pub fn encode(
    polynomial: &DensePolynomial<Fr>,
    domain: GeneralEvaluationDomain<Fr>,
) -> Evaluations<Fr> {
    let mut evaluations = Evaluations::from_vec_and_domain(domain.fft(&polynomial.coeffs), domain);

    // Introduce manipulation: Modify the first evaluation point
    if !evaluations.evals.is_empty() {
        evaluations.evals[0] = evaluations.evals[0].add(Fr::from(1u64)); // Add 1 to the first point
    }

    evaluations
}

/// Interpolate points into a polynomial.
///
/// Then evaluate the polynomial in the
/// original evaluations to recover the original data.
/// `domain` need to be the same domain of the original `evaluations` and
/// `polynomial` used for encoding.
#[must_use]
pub fn decode(
    original_chunks_len: usize,
    points: &[Option<Fr>],
    domain: GeneralEvaluationDomain<Fr>,
) -> Evaluations<Fr> {
    let (points, roots_of_unity): (Vec<Fr>, Vec<Fr>) = points
        .iter()
        .enumerate()
        .filter_map(|(i, e)| e.map(|e| (e, domain.element(i))))
        .unzip();
    let coeffs = lagrange_interpolate(&points, &roots_of_unity);
    Evaluations::from_vec_and_domain(
        domain
            .fft(&coeffs)
            .into_iter()
            .take(original_chunks_len)
            .collect(),
        domain,
    )
}

/// Interpolate a set of points using lagrange interpolation and roots of unity
///
/// Warning!! Be aware that the mapping between points and roots of unity is the
/// intended: A polynomial `f(x)` is derived for `w_x` (root) mapping to `p_x`.
/// `[(w_1, p_1)..(w_n, p_n)]` even if points are missing it is important to
/// keep the mapping integrity.
#[must_use]
pub fn lagrange_interpolate(points: &[Fr], roots_of_unity: &[Fr]) -> DensePolynomial<Fr> {
    assert_eq!(points.len(), roots_of_unity.len());
    let mut result = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for i in 0..roots_of_unity.len() {
        let mut summand = DensePolynomial::from_coefficients_vec(vec![points[i]]);
        for j in 0..points.len() {
            if i != j {
                let weight_adjustment =
                    (roots_of_unity[i] - roots_of_unity[j])
                        .inverse()
                        .expect(
                            "Roots of unity are/should not repeated. If this panics it means we have no coefficients enough in the evaluation domain"
                        );
                summand = summand.naive_mul(&DensePolynomial::from_coefficients_vec(vec![
                    weight_adjustment.mul(roots_of_unity[j]).neg(),
                    weight_adjustment,
                ]));
            }
        }
        result = result + summand;
    }
    result
}

/// Reconstruct bytes from the polynomial evaluation points using original chunk
/// size and a set of points
pub fn points_to_bytes<const CHUNK_SIZE: usize>(points: &[Fr]) -> Vec<u8> {
    fn point_to_buff<const CHUNK_SIZE: usize>(p: &Fr) -> impl Iterator<Item = u8> {
        p.into_bigint().to_bytes_le().into_iter().take(CHUNK_SIZE)
    }
    points
        .iter()
        .flat_map(point_to_buff::<CHUNK_SIZE>)
        .collect()
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use ark_bls12_381::Fr;
    use ark_poly::{EvaluationDomain as _, GeneralEvaluationDomain};
    use rand::{thread_rng, Fill as _};

    use crate::{
        common::bytes_to_polynomial,
        rs::{decode, encode, points_to_bytes},
    };

    const COEFFICIENTS_SIZE: usize = 32;
    static DOMAIN: LazyLock<GeneralEvaluationDomain<Fr>> =
        LazyLock::new(|| GeneralEvaluationDomain::new(COEFFICIENTS_SIZE).unwrap());

    #[test]
    fn test_encode_decode() {
        let mut bytes: [u8; 310] = [0; 310];
        let mut rng = thread_rng();
        bytes.try_fill(&mut rng).unwrap();

        let (_evals, poly) = bytes_to_polynomial::<31>(&bytes, *DOMAIN).unwrap();

        let encoded = encode(&poly, *DOMAIN);
        let mut encoded: Vec<Option<Fr>> = encoded.evals.into_iter().map(Some).collect();

        let decoded = decode(10, &encoded, *DOMAIN);
        let decoded_bytes = points_to_bytes::<31>(&decoded.evals);
        assert_eq!(decoded_bytes, bytes);

        // check with missing pieces

        for i in (1..encoded.len()).step_by(2) {
            encoded[i] = None;
        }

        let decoded_bytes = points_to_bytes::<31>(&decoded.evals);
        assert_eq!(decoded_bytes, bytes);
    }
}
