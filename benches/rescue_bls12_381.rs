#![feature(test)]

extern crate rand;
extern crate test;
extern crate pairing;
extern crate rescue_hash;

use rand::{Rand, thread_rng};
use pairing::bls12_381::{Bls12, Fr};
use rescue_hash::*;
use rescue_hash::generator::*;
use rescue_hash::group_hash::*;

#[bench]
fn bench_2_1_hash(b: &mut test::Bencher) {
    let params = RescueParamsInstance::<Bls12, QuinticSBox>::new_2_into_1::<BlakeHasher>();
    let rng = &mut thread_rng();
    let input = (0..2).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

    b.iter(|| {
        rescue_hash::<Bls12>(&params, &input)
    });
}
