use ark_bls12_381::{Bls12_381, Fr as ScalarField};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Result};
use ark_r1cs_std::prelude::*;
use ark_snark::SNARK;
use ark_serialize::CanonicalSerialize;

#[derive(Clone, Copy)]
struct MyProof {
    pub a: u32,
    pub b: u32,

    pub c: u32
}

impl MyProof {
    pub fn new(a: u32, b: u32, c: u32) -> Self {
        Self { a, b, c }
    }
}

fn f(a: u32, b: u32) -> u32 {
    a + b
}

impl ConstraintSynthesizer<ScalarField> for MyProof {
    fn generate_constraints(self, cs: ConstraintSystemRef<ScalarField>) -> ark_relations::r1cs::Result<()> {
        let c = UInt32::new_witness(ark_relations::ns!(cs, "c"), || Ok(self.c))?;
        let res = UInt32::new_constant(ark_relations::ns!(cs, "res"), f(self.a, self.b))?;

        res.enforce_equal(&c)?;

        Ok(())
    }
}

fn main() -> Result<()>{
    let v = MyProof::new(2, 2, 4);

    let cs = ConstraintSystem::new_ref();
    v.generate_constraints(cs.clone())?;
    let sat = cs.is_satisfied()?;

    println!("{sat}");

    let mut rng = rand::thread_rng();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(v, &mut rng)?;

    let proof = Groth16::prove(&pk, v, &mut rng)?;

    let mut writer = Vec::<u8>::new();
    proof.serialize(&mut writer).expect("failed to serialize proof");

    let valid_proof = Groth16::verify(&vk, &[], &proof)?;

    println!("{valid_proof}");

    Ok(())
}
