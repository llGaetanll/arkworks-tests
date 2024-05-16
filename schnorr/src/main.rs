use ark_ec::{CurveGroup, models::twisted_edwards::Projective as TEProjective};
use ark_ed_on_bls12_381::JubjubConfig;
use ark_ff::fields::PrimeField;
use ark_crypto_primitives::{crh::sha256::Sha256, signature::{schnorr::{PublicKey, Schnorr, SecretKey}, SignatureScheme}};
use ark_relations::r1cs::Result;

#[derive(Debug)]
struct User<C: CurveGroup> {
    pub pk: PublicKey<C>,
    pub sk: SecretKey<C>,
}

impl<C> User<C> 
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();

        let params = Schnorr::<C, Sha256>::setup(&mut rng).unwrap();
        let (pk, sk) = Schnorr::keygen(&params, &mut rng).unwrap();

        Self { pk, sk }
    }
}

fn main() -> Result<()> {
    let user = User::<TEProjective<JubjubConfig>>::new();

    println!("{user:?}");

    Ok(())
}
