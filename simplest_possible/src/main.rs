use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result};
use ark_snark::SNARK;

#[derive(Clone, Copy)]
struct MyProof {
    a: Fr,
    b: Fr,
    c: Fr
}

impl ConstraintSynthesizer<Fr> for MyProof {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let a = FpVar::new_witness(cs.clone(), || Ok(self.a))?; 
        let b = FpVar::new_witness(cs.clone(), || Ok(self.b))?; 

        let c = FpVar::new_input(cs.clone(), || Ok(self.c))?; 
        c.enforce_equal(&(a + b))?;

        Ok(())
    }
}

fn main() -> Result<()> {
    let a: u64 = 2;
    let b: u64 = 2;
    let c: u64 = 4;

    let v = MyProof {
        a: a.into(),
        b: b.into(),
        c: c.into()
    };

    let mut rng = rand::thread_rng();

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(v, &mut rng)?;
    let proof = Groth16::prove(&pk, v, &mut rng)?;

    let valid_proof = Groth16::<Bls12_381>::verify(&vk, &[c.into()], &proof)?;

    println!("{valid_proof}");

    Ok(())
}
