use ark_bls12_381::{Bls12_381, Fr as ScalarField};
use ark_groth16::Groth16;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Result};
use ark_snark::SNARK;
use rand::RngCore;

#[derive(Debug, Clone)]
struct Example {
    input: u8
}

impl ConstraintSynthesizer<ScalarField> for Example {
    #[tracing::instrument(target = "r1cs")]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ScalarField>,
    ) -> ark_relations::r1cs::Result<()> {
        let x = UInt8::new_input(cs.clone(), || { Ok(self.input) })?;

        Ok(())
    }
}

fn build_circuit() -> Example {
    let mut rng = rand::thread_rng();
    let input = (rng.next_u32() % (u8::MAX as u32)) as u8;

    Example { input }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let mut rng = ark_std::test_rng();

    let c1 = build_circuit();

    let cs = ConstraintSystem::new_ref();
    c1.clone().generate_constraints(cs.clone())?;
    let sat = cs.is_satisfied()?;

    println!("{sat}");

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c1, &mut rng)?;

    let c2 = build_circuit();
    let public_input = [
        c2.input.into()
    ];

    let proof = Groth16::prove(&pk, c2, &mut rng)?;
    let is_valid = Groth16::<Bls12_381>::verify(&vk, &public_input, &proof)?;

    assert!(is_valid);

    Ok(())
}
