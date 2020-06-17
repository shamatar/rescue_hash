use super::*;
use super::generator::*;
use pairing::bls12_381::Bls12;

impl RescueEngine for Bls12 {
    type Params = RescueParamsInstance<Bls12, QuinticSBox>;
}