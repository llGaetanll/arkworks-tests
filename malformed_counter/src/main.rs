use ark_bls12_381::{Bls12_381, Fr as ScalarField};
use ark_groth16::Groth16;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result};
use ark_snark::SNARK;

#[derive(Clone, Copy)]
struct MyProof {
    /// A public input
    x: u32,

    /// A private witness
    y: u32,
}

impl MyProof {
    pub fn new(x: u32, y: u32) -> Self {
        Self { x, y }
    }
}

impl ConstraintSynthesizer<ScalarField> for MyProof {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ScalarField>,
    ) -> ark_relations::r1cs::Result<()> {
        // let _x = UInt32::new_input(cs.clone(), || Ok(self.x))?; // this doesn't work
        let _x = cs.new_input_variable(|| Ok(self.x.into()))?;  // this does

        // either of these works
        let _y = UInt32::new_witness(cs.clone(), || Ok(self.y))?;
        // let _y = cs.new_witness_variable(|| Ok(self.y.into()))?;

        Ok(())
    }
}

fn main() -> Result<()> {
    let (x, y) = (1, 2);
    let v = MyProof::new(x, y);

    let mut rng = rand::thread_rng();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(v, &mut rng)?;
    let proof = Groth16::prove(&pk, v, &mut rng)?;
    let valid_proof = Groth16::<Bls12_381>::verify(&vk, &[x.into()], &proof)?;

    println!("{valid_proof}");

    Ok(())
}
