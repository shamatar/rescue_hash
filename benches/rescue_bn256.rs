#![feature(test)]

extern crate rand;
extern crate test;
extern crate pairing;
extern crate rescue_hash;

use rand::{Rand, thread_rng};
use pairing::bn256::{Bn256, Fr};
use rescue_hash::rescue_hash;
use rescue_hash::bn256::Bn256RescueParams;

#[bench]
fn bench_2_1_hash(b: &mut test::Bencher) {
    let params = Bn256RescueParams::new_checked_2_into_1();
    let rng = &mut thread_rng();
    let input = (0..2).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

    b.iter(|| {
        rescue_hash::<Bn256>(&params, &input)
    });
}

#[bench]
fn bench_2_1_hash_128(b: &mut test::Bencher) {
    use rescue_hash::group_hash::*;
    let params = Bn256RescueParams::new_for_params::<BlakeHasher>(1, 2, 16, 126);
    let rng = &mut thread_rng();
    let input = (0..2).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

    b.iter(|| {
        rescue_hash::<Bn256>(&params, &input)
    });
}
