use pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use super::{RescueEngine, RescueHashParams, RescueParamsInternal, PowerSBox, generate_mds_matrix, POWER_SBOX_WINDOW_SIZE, LowDegreeSBox};
use super::group_hash::{GroupHasher};

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
use self::num_bigint::{BigUint, BigInt};
use self::num_integer::{Integer, ExtendedGcd};
use self::num_traits::{ToPrimitive, Zero, One};

#[derive(Clone)]
pub struct RescueParamsInstance<E: RescueEngine, S: LowDegreeSBox<E>> {
    c: u32,
    r: u32,
    rounds: u32,
    round_constants: Vec<E::Fr>,
    mds_matrix: Vec<E::Fr>,
    security_level: u32,
    sbox_0: PowerSBox<E>,
    sbox_1: S,
}

impl<E: RescueEngine, S: LowDegreeSBox<E>> RescueParamsInstance<E, S> {
    pub fn new_2_into_1<H: GroupHasher>() -> Self {
        let c = 1u32;
        let r = 2u32;
        let rounds = 22u32;
        let security_level = 126u32;

        Self::new_for_params::<H>(c, r, rounds, security_level, b"Rescue_m", b"Rescue_f")
    }

    pub fn new_3_into_1<H: GroupHasher>() -> Self {
        let c = 1u32;
        let r = 3u32;
        let rounds = 22u32;
        let security_level = 126u32;

        Self::new_for_params::<H>(c, r, rounds, security_level,b"Rescue_m", b"Rescue_f")
    }

    pub fn new_for_params<H: GroupHasher>(
        c: u32, 
        r: u32, 
        rounds: u32, 
        security_level: u32,
        mds_tag: &[u8],
        round_constants_tag: &[u8]
    ) -> Self {
        use byteorder::{WriteBytesExt, ReadBytesExt, BigEndian};
        use super::constants;

        let state_width = c + r;
        let num_round_constants = (1 + rounds * 2) * state_width;
        let num_round_constants = num_round_constants as usize;

        // generate round constants based on some seed and hashing
        let round_constants = {
            let tag = round_constants_tag;
            let mut round_constants = Vec::with_capacity(num_round_constants);
            let mut nonce = 0u32;
            let mut nonce_bytes = [0u8; 4];

            loop {
                (&mut nonce_bytes[0..4]).write_u32::<BigEndian>(nonce).unwrap();
                let mut h = H::new(&tag[..]);
                h.update(constants::GH_FIRST_BLOCK);
                h.update(&nonce_bytes[..]);
                let h = h.finalize();
                assert!(h.len() == 32);

                let mut constant_repr = <E::Fr as PrimeField>::Repr::default();
                constant_repr.read_le(&h[..]).unwrap();

                if let Ok(constant) = E::Fr::from_repr(constant_repr) {
                    if !constant.is_zero() {
                        round_constants.push(constant);
                    }
                }

                if round_constants.len() == num_round_constants {
                    break;
                }

                nonce += 1;
            }

            round_constants
        };

        let mds_matrix = {
            use rand::{SeedableRng};
            use rand::chacha::ChaChaRng;
            // Create an RNG based on the outcome of the random beacon
            let mut rng = {
                let tag = mds_tag;
                let mut h = H::new(&tag[..]);
                h.update(constants::GH_FIRST_BLOCK);
                let h = h.finalize();
                assert!(h.len() == 32);
                let mut seed = [0u32; 8];
                for i in 0..8 {
                    seed[i] = (&h[..]).read_u32::<BigEndian>().expect("digest is large enough for this to work");
                }

                ChaChaRng::from_seed(&seed)
            };

            generate_mds_matrix::<E, _>(state_width, &mut rng)
        };


        let alpha = BigUint::from(S::DEGREE);
        let mut p = BigUint::from(0u64);
        for limb in E::Fr::char().as_ref().iter().rev() {
            p <<= 64;
            p += BigUint::from(*limb);
        }

        let alpha_inv = caculate_alpha_inv(alpha, p);

        let alpha_inv = biguint_to_u64_array(alpha_inv);

        let mut alpha_inv_repr = <E::Fr as PrimeField>::Repr::default();

        for (r, limb) in alpha_inv_repr.as_mut().iter_mut().zip(alpha_inv.iter()) {
            *r = *limb;
        }

        let mut indexes = vec![];

        let mut exp = alpha_inv_repr;

        let mask = (1u64 << POWER_SBOX_WINDOW_SIZE) - 1u64;
        while !exp.is_zero() {
            let bits = exp.as_ref()[0] & mask;
            indexes.push(bits as usize);
            exp.shr(POWER_SBOX_WINDOW_SIZE as u32);
        }

        // need highest bits first
        indexes.reverse();

        Self {
            c: c,
            r: r,
            rounds: rounds,
            round_constants: round_constants,
            mds_matrix: mds_matrix,
            security_level: security_level,
            sbox_0: PowerSBox { power: alpha_inv_repr, precomputed_indexes: indexes, inv: 5u64 },
            sbox_1: S::default(),
        }
    }
}

fn biguint_to_u64_array(mut v: BigUint) -> [u64; 4] {
    let m = BigUint::from(1u64) << 64;
    let mut ret = [0; 4];

    for idx in 0..4 {
        ret[idx] = (&v % &m).to_u64().expect("is guaranteed to fit");
        v >>= 64;
    }
    assert!(v.is_zero());
    ret
}

fn caculate_alpha_inv(alpha: BigUint, modulus: BigUint) -> BigUint {
    let mut p_minus_one_biguint = modulus;
    p_minus_one_biguint -= BigUint::one();

    let alpha_signed = BigInt::from(alpha);
    let p_minus_one_signed = BigInt::from(p_minus_one_biguint);

    let ExtendedGcd{ gcd, x: _, y, .. } = p_minus_one_signed.extended_gcd(&alpha_signed); 
    assert!(gcd.is_one());
    let y = if y < BigInt::zero() {
        let mut y = y;
        y += p_minus_one_signed;

        y.to_biguint().expect("must be > 0")
    } else {
        y.to_biguint().expect("must be > 0")
    };

    y
}

impl<E: RescueEngine, S: LowDegreeSBox<E>> RescueParamsInternal<E> for RescueParamsInstance<E, S> {
    fn set_round_constants(&mut self, to: Vec<E::Fr>) {
        assert_eq!(self.round_constants.len(), to.len());
        self.round_constants = to;
    }
}

impl<E: RescueEngine, S: LowDegreeSBox<E>> RescueHashParams<E> for RescueParamsInstance<E, S> {
    type SBox0 = PowerSBox<E>;
    type SBox1 = S;

    fn capacity(&self) -> u32 {
        self.c
    }
    fn rate(&self) -> u32 {
        self.r
    }
    fn num_rounds(&self) -> u32 {
        self.rounds
    }
    fn round_constants(&self, round: u32) -> &[E::Fr] {
        let t = self.c + self.r;
        let start = (t*round) as usize;
        let end = (t*(round+1)) as usize;

        &self.round_constants[start..end]
    }
    fn mds_matrix_row(&self, row: u32) -> &[E::Fr] {
        let t = self.c + self.r;
        let start = (t*row) as usize;
        let end = (t*(row+1)) as usize;

        &self.mds_matrix[start..end]
    }
    fn security_level(&self) -> u32 {
        self.security_level
    }
    fn output_len(&self) -> u32 {
        self.capacity()
    }
    fn absorbtion_cycle_len(&self) -> u32 {
        self.rate()
    }
    fn compression_rate(&self) -> u32 {
        self.absorbtion_cycle_len() / self.output_len()
    }

    fn sbox_0(&self) -> &Self::SBox0 {
        &self.sbox_0
    }
    fn sbox_1(&self) -> &Self::SBox1 {
        &self.sbox_1
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::generator::num_traits::Num;

    #[test]
    fn print_inv_alpha() {
        let modulus = BigUint::from_str_radix("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10).unwrap();
        // let modulus = BigUint::from_str_radix("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10).unwrap();
        // let modulus = BigUint::from_str_radix("3618502788666131213697322783095070105623107215331596699973092056135872020481", 10).unwrap();
        let alpha = BigUint::from(5u64);
        // let alpha = BigUint::from(3u64);

        let alpha_inv = caculate_alpha_inv(alpha, modulus);

        println!("Alpha inv = {}", alpha_inv.to_str_radix(16));
        println!("Alpha inv bit length = {}", alpha_inv.bits());

        let mut hamming = 0;
        let mut tmp = alpha_inv.clone();
        while !tmp.is_zero() {
            if tmp.is_odd() {
                hamming += 1;
            }

            tmp >>= 1;
        }

        println!("Alpha inv hamming = {}", hamming);

        let chain = get_add_chain(alpha_inv);

        println!("Addition chain length = {}", chain.len());
    }

    extern crate addchain;

    use addchain::{build_addition_chain, Step};

    fn get_add_chain(value: BigUint) -> Vec<Step> {
        build_addition_chain(value)
    }
}
//     use rand::{Rng, thread_rng};
//     use crate::pairing::bn256::{Bn256, Fr};
//     use super::*;
//     use crate::*;
//     use crate::group_hash::BlakeHasher;

//     #[test]
//     fn test_generate_bn256_rescue_params() {
//         let _params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
//     }

//     #[test]
//     fn test_bn256_rescue_params_permutation() {
//         let rng = &mut thread_rng();
//         let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();

//         for _ in 0..1000 {
//             let input: Fr = rng.gen();
//             let mut input_arr: [Fr; 1] = [input];
//             params.sbox_1().apply(&mut input_arr);
//             params.sbox_0().apply(&mut input_arr);
//             assert_eq!(input_arr[0], input);
//         }

//         for _ in 0..1000 {
//             let input: Fr = rng.gen();
//             let mut input_arr: [Fr; 1] = [input];
//             params.sbox_0().apply(&mut input_arr);
//             params.sbox_1().apply(&mut input_arr);
//             assert_eq!(input_arr[0], input);
//         }
//     }

//     #[test]
//     fn test_bn256_rescue_hash() {
//         let rng = &mut thread_rng();
//         let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
//         let input: Vec<Fr> = (0..params.rate()).map(|_| rng.gen()).collect();
//         let output = rescue_hash::<Bn256>(&params, &input[..]);
//         assert!(output.len() == 1);
//     }

//     #[test]
//     fn test_bn256_stateful_rescue_hash() {
//         let rng = &mut thread_rng();
//         let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
//         let input: Vec<Fr> = (0..params.rate()).map(|_| rng.gen()).collect();
//         let output = rescue_hash::<Bn256>(&params, &input[..]);
//         assert!(output.len() == 1);

//         let mut stateful_rescue = super::super::StatefulRescue::<Bn256>::new(&params);
//         stateful_rescue.absorb(&input);

//         let first_output = stateful_rescue.squeeze_out_single();
//         assert_eq!(first_output, output[0]);

//         let _ = stateful_rescue.squeeze_out_single();
//     }

//     #[test]
//     fn test_bn256_long_input_rescue_hash() {
//         let rng = &mut thread_rng();
//         let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
//         let input: Vec<Fr> = (0..((params.rate()*10) + 1)).map(|_| rng.gen()).collect();
//         let output = rescue_hash::<Bn256>(&params, &input[..]);
//         assert!(output.len() == 1);

//         let mut stateful_rescue = super::super::StatefulRescue::<Bn256>::new(&params);
//         stateful_rescue.absorb(&input);

//         let first_output = stateful_rescue.squeeze_out_single();
//         assert_eq!(first_output, output[0]);

//         let _ = stateful_rescue.squeeze_out_single();
//     }

//     #[test]
//     #[should_panic]
//     fn test_bn256_stateful_rescue_depleted_sponge() {
//         let rng = &mut thread_rng();
//         let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
//         let input: Vec<Fr> = (0..params.rate()).map(|_| rng.gen()).collect();

//         let mut stateful_rescue = super::super::StatefulRescue::<Bn256>::new(&params);
//         stateful_rescue.absorb(&input);

//         let _ = stateful_rescue.squeeze_out_single();
//         let _ = stateful_rescue.squeeze_out_single();
//         let _ = stateful_rescue.squeeze_out_single();
//     }

//     #[test]
//     fn print_mds() {
//         let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
//         println!("MDS_MATRIX");
//         let mut vec = vec![];
//         for i in 0..params.state_width() {
//             vec.push(format!("{:?}", params.mds_matrix_row(i)));
//         }

//         println!("[ {} ]", vec.join(","));
//     }
// }