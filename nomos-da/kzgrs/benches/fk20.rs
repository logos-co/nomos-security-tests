use std::{hint::black_box, sync::LazyLock};

use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain as _, GeneralEvaluationDomain};
use ark_poly_commit::kzg10::KZG10;
use divan::{counter::ItemsCount, Bencher};
use kzgrs::{
    bytes_to_polynomial,
    fk20::{fk20_batch_generate_elements_proofs, Toeplitz1Cache},
    GlobalParameters, BYTES_PER_FIELD_ELEMENT,
};
use rand::SeedableRng as _;
#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};

fn main() {
    divan::main();
}

static GLOBAL_PARAMETERS: LazyLock<GlobalParameters> = LazyLock::new(|| {
    let mut rng = rand::rngs::StdRng::seed_from_u64(1987);
    KZG10::<Bls12_381, DensePolynomial<Fr>>::setup(4096, true, &mut rng).unwrap()
});

#[divan::bench(args = [16, 32, 64, 128, 256, 512, 1_024, 2_048, 4_096], sample_count = 10, sample_size = 10)]
fn compute_fk20_proofs_for_size(bencher: Bencher, size: usize) {
    bencher
        .with_inputs(|| {
            let buff: Vec<_> = (0..BYTES_PER_FIELD_ELEMENT * size)
                .map(|i| (i % 255) as u8)
                .rev()
                .collect();
            let domain = GeneralEvaluationDomain::new(size).unwrap();
            let (_, poly) = bytes_to_polynomial::<BYTES_PER_FIELD_ELEMENT>(&buff, domain).unwrap();
            poly
        })
        .input_counter(move |_| ItemsCount::new(size))
        .bench_refs(|poly| {
            black_box(fk20_batch_generate_elements_proofs(
                poly,
                &GLOBAL_PARAMETERS,
                None,
            ))
        });
}

#[cfg(feature = "parallel")]
#[divan::bench(args = [16, 32, 64, 128, 256, 512, 1_024, 2_048, 4_096], sample_count = 10, sample_size = 10)]
fn compute_parallel_fk20_proofs_for_size(bencher: Bencher, size: usize) {
    let thread_count: usize = rayon::max_num_threads().min(rayon::current_num_threads());
    bencher
        .with_inputs(|| {
            let buff: Vec<_> = (0..BYTES_PER_FIELD_ELEMENT * size)
                .map(|i| (i % 255) as u8)
                .rev()
                .collect();
            let domain = GeneralEvaluationDomain::new(size).unwrap();
            let (_, poly) = bytes_to_polynomial::<BYTES_PER_FIELD_ELEMENT>(&buff, domain).unwrap();
            poly
        })
        .input_counter(move |_| ItemsCount::new(size * thread_count))
        .bench_refs(|poly| {
            (0..thread_count).into_par_iter().for_each(|_| {
                let _ = fk20_batch_generate_elements_proofs(poly, &GLOBAL_PARAMETERS, None);
            });
            black_box(());
        });
}

#[divan::bench(args = [16, 32, 64, 128, 256, 512, 1_024, 2_048, 4_096], sample_count = 10, sample_size = 10)]
fn compute_fk20_proofs_for_size_with_cache(bencher: Bencher, size: usize) {
    bencher
        .with_inputs(|| {
            let buff: Vec<_> = (0..BYTES_PER_FIELD_ELEMENT * size)
                .map(|i| (i % 255) as u8)
                .rev()
                .collect();
            let domain = GeneralEvaluationDomain::new(size).unwrap();
            let (_, poly) = bytes_to_polynomial::<BYTES_PER_FIELD_ELEMENT>(&buff, domain).unwrap();
            let cache = Toeplitz1Cache::with_size(&GLOBAL_PARAMETERS, size);
            (poly, cache)
        })
        .input_counter(move |_| ItemsCount::new(size))
        .bench_refs(|(poly, cache)| {
            black_box(fk20_batch_generate_elements_proofs(
                poly,
                &GLOBAL_PARAMETERS,
                Some(cache),
            ))
        });
}

#[cfg(feature = "parallel")]
#[divan::bench(args = [16, 32, 64, 128, 256, 512, 1_024, 2_048, 4_096], sample_count = 10, sample_size = 10)]
fn compute_parallel_fk20_proofs_for_size_with_cache(bencher: Bencher, size: usize) {
    let thread_count: usize = rayon::max_num_threads().min(rayon::current_num_threads());
    bencher
        .with_inputs(|| {
            let buff: Vec<_> = (0..BYTES_PER_FIELD_ELEMENT * size)
                .map(|i| (i % 255) as u8)
                .rev()
                .collect();
            let domain = GeneralEvaluationDomain::new(size).unwrap();
            let (_, poly) = bytes_to_polynomial::<BYTES_PER_FIELD_ELEMENT>(&buff, domain).unwrap();
            let cache = Toeplitz1Cache::with_size(&GLOBAL_PARAMETERS, size);
            (poly, cache)
        })
        .input_counter(move |_| ItemsCount::new(size * thread_count))
        .bench_refs(|(poly, cache)| {
            (0..thread_count).into_par_iter().for_each(|_| {
                let _ = fk20_batch_generate_elements_proofs(poly, &GLOBAL_PARAMETERS, Some(cache));
            });
            black_box(());
        });
}
