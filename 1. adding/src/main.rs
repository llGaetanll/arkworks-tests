use ark_bls12_381::Fr;
use ark_bls12_381::Bls12_381;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result};
use ark_groth16::Groth16;
use ark_snark::SNARK;

#[derive(Clone, Copy)]
struct AddingProof {
    a: Fr,
    b: Fr,
    c: Fr
}

impl AddingProof {
    pub fn new(a: u64, b: u64, c: u64) -> Self {
        Self {
            a: a.into(), b: b.into(), c: c.into()
        }
    }
}

impl ConstraintSynthesizer<Fr> for AddingProof {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        // a and b are private witnesses for the proof
        let a = FpVar::new_witness(ark_relations::ns!(cs, "a"), || Ok(self.a))?;
        let b = FpVar::new_witness(ark_relations::ns!(cs, "b"), || Ok(self.b))?;

        // c is a public input
        let c = FpVar::new_input(ark_relations::ns!(cs, "c"), || Ok(self.c))?;

        c.enforce_equal(&(a + b))?;

        Ok(())
    }
}

fn main() -> Result<()> {
    let mut rng = rand::thread_rng();

    let v = AddingProof::new(1, 1, 1);
    let (pk, vk) = Groth16::<Bls12_381, LibsnarkReduction>::circuit_specific_setup(v, &mut rng)?;

    let proof = Groth16::<Bls12_381, LibsnarkReduction>::prove(&pk, v, &mut rng)?;

    let public_inputs = [v.c];
    let is_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)?;

    println!("{is_valid}");

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_relations::r1cs::{ConstraintSystem, Result};
    use ark_bls12_381::Bls12_381;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;

    #[test]
    fn cs_sat() -> Result<()> {
        let v = AddingProof::new(1, 1, 2);

        let cs = ConstraintSystem::new_ref();
        v.generate_constraints(cs.clone())?;

        assert!(cs.is_satisfied()?);

        Ok(())
    }

    #[test]
    /// Check that a false proof is invalid
    fn pf_sound() -> Result<()> {
        let v = AddingProof::new(1, 1, 1);

        let cs = ConstraintSystem::new_ref();
        v.generate_constraints(cs.clone())?;
        let valid_circuit = cs.is_satisfied()?;

        assert!(!valid_circuit);

        Ok(())
    }

    #[test]
    /// Check that a true proof is valid
    fn pf_complete() -> Result<()> {
        let mut rng = rand::thread_rng();

        let v = AddingProof::new(1, 1, 2);
        let (pk, vk) = Groth16::<Bls12_381, LibsnarkReduction>::circuit_specific_setup(v, &mut rng)?;

        let proof = Groth16::<Bls12_381, LibsnarkReduction>::prove(&pk, v, &mut rng)?;

        let public_inputs = [v.c];
        let is_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)?;

        assert!(is_valid);

        Ok(())
    }
}
