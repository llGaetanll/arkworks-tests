use ark_bls12_381::Fr;
use ark_crypto_primitives::commitment::{CommitmentGadget, CommitmentScheme};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, ToBytesGadget};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_ff::UniformRand;

mod poseidon;
use poseidon::{Bls12PoseidonCommitter, UnitVar};

pub type Commitment = <Bls12PoseidonCommitter as CommitmentScheme>::Output;
pub type Randomness = <Bls12PoseidonCommitter as CommitmentScheme>::Randomness;

#[derive(Clone)]
struct CommitmentProof {
    cmd_rnd: Randomness,
    value: Fr,
    commitment: Commitment
}

impl CommitmentProof {
    pub fn new(value: Fr, rnd: Fr, commitment: Fr) -> Self {
        Self { cmd_rnd: rnd, value, commitment }
    }
}

impl ConstraintSynthesizer<Fr> for CommitmentProof {
    fn generate_constraints(self, cs: ark_relations::r1cs::ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        let public_commitment = FpVar::new_input(ark_relations::ns!(cs, "pub commitment"), || Ok(self.commitment))?;

        let r = FpVar::new_witness(ark_relations::ns!(cs, "com_rnd"), || Ok(self.cmd_rnd))?;
        let value = FpVar::new_witness(ark_relations::ns!(cs, "value"), || Ok(self.value))?;

        let params = UnitVar::new_constant(ark_relations::ns!(cs, "poseidon_params"), ())?;
        let input = value.to_bytes()?;
        let final_commitment = <Bls12PoseidonCommitter as CommitmentGadget<Bls12PoseidonCommitter, Fr>>::commit(&params, &input, &r)?;

        final_commitment.enforce_equal(&public_commitment)?;

        Ok(())
    }
}

fn create_new_commitment() -> CommitmentProof {
    let mut rng = rand::thread_rng();
    let rnd = Fr::rand(&mut rng);
    let value = 3;
    let commitment = <Bls12PoseidonCommitter as CommitmentScheme>::commit(&(), &[value], &rnd).unwrap();

    CommitmentProof::new(value.into(), rnd, commitment)
}

fn main() {

}

#[cfg(test)]
mod test {
    use super::*;
    // use ark_crypto_primitives::CommitmentScheme;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::{ConstraintSystem, Result};
    use ark_bls12_381::Bls12_381;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;

    #[test]
    fn cs_sat() -> Result<()> {
        let proof = create_new_commitment();

        let cs = ConstraintSystem::new_ref();
        proof.generate_constraints(cs.clone())?;

        assert!(cs.is_satisfied()?);

        Ok(())
    }

    #[test]
    /// Check that a false proof is invalid
    fn pf_sound() -> Result<()> {
        let mut rng = rand::thread_rng();
        let p1 = create_new_commitment();

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(p1.clone(), &mut rng)?;
        let proof = Groth16::prove(&pk, p1, &mut rng)?;

        let p2 = create_new_commitment();
        let public_inputs = [p2.commitment];
        let is_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)?;

        assert!(!is_valid);

        Ok(())
    }

    #[test]
    /// Check that a true proof is valid
    fn pf_complete() -> Result<()> {
        let mut rng = rand::thread_rng();
        let rnd = Fr::rand(&mut rng);
        let value = 3;
        let commitment = <Bls12PoseidonCommitter as CommitmentScheme>::commit(&(), &[value], &rnd).unwrap();

        let v = CommitmentProof::new(value.into(), rnd, commitment);
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(v.clone(), &mut rng)?;

        let proof = Groth16::prove(&pk, v.clone(), &mut rng)?;

        let public_inputs = [v.commitment];
        let is_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)?;

        assert!(is_valid);

        Ok(())
    }
}
