use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{crh::TwoToOneCRH, CRH};
use ark_ff::ToBytes;
use ark_groth16::Groth16;
use ark_r1cs_std::{prelude::*, uint64::UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Result};
use ark_snark::SNARK;
use rand::RngCore;
use std::{
    hash::{DefaultHasher, Hasher},
    marker::PhantomData,
};

use merkletree::{
    LeafHash, LeafHashParamsVar, Root, RootVar, TreePath, TreePathVar, TwoToOneHash, TwoToOneHashParamsVar
};

use crate::merkletree::MerkleTree;

mod merkletree;

pub type ScalarField = ark_bls12_381::Fr;

pub type Key = u64;
pub type CoinID = u64;

#[derive(Clone)]
pub struct Coin {
    pub pk: Key,
    pub pre_serial_no: CoinID,
    pub com_rnd: u64,
}

impl Coin {
    pub fn new(pk: Key, pre_serial_no: CoinID, com_rnd: u64) -> Self {
        Coin {
            pk,
            pre_serial_no,
            com_rnd,
        }
    }
}

#[derive(Clone)]
#[repr(transparent)]
pub struct Commitment<T> {
    hash: u64,
    _t: PhantomData<T>,
}

impl Commitment<Coin> {
    /// Create a commitment from a `Coin`.
    pub fn from(coin: Coin) -> Self {
        Self {
            hash: Self::hash(coin),
            _t: PhantomData,
        }
    }

    pub fn gen_rand<R: RngCore>(pk: Key, rng: &mut R) -> Self {
        Commitment::from(Coin::new(pk, rng.next_u64(), rng.next_u64()))
    }

    pub fn verify(&self, coin: Coin) -> bool {
        self.hash == Self::hash(coin)
    }

    fn hash(coin: Coin) -> u64 {
        // TODO: maybe use a different hash function
        let mut hasher = DefaultHasher::new();

        hasher.write(&coin.pk.to_be_bytes());
        hasher.write(&coin.pre_serial_no.to_be_bytes());
        hasher.write(&coin.com_rnd.to_be_bytes());

        hasher.finish()
    }
}

impl<T> From<Commitment<T>> for u64 {
    fn from(value: Commitment<T>) -> Self {
        value.hash
    }
}

impl std::borrow::Borrow<u64> for Commitment<Coin> {
    fn borrow(&self) -> &u64 {
        &self.hash
    }
}

impl ToBytes for Commitment<Coin> {
    fn write<W: std::io::prelude::Write>(&self, writer: W) -> std::io::Result<()> {
        self.hash.write(writer)
    }
}

#[derive(Clone)]
struct MyProof {
    // Circuit Constants
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // Public Inputs
    /// The root of the Merkle Tree
    pub root: Root,

    /// The leaf corresponding to the Coin Commitment belonging to the user.
    pub leaf: Commitment<Coin>, // u64

    // Private Witnesses
    /// The path down the [`MerkleTree`] which leads to `leaf`.
    pub path: Option<TreePath>,

    /// The `Coin` we expect to match the commitment in the [`MerkleTree`].
    pub coin: Coin,

    /// The user's secret key. We prove that `pk = H(sk)`.
    pub sk: Key,

    /// The serial number to be revealed by the user. We prove that `serial_no = prf(sk, pre_serial_no)`.
    pub serial_no: CoinID,
}

impl ConstraintSynthesizer<ScalarField> for MyProof {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ScalarField>,
    ) -> ark_relations::r1cs::Result<()> {
        // constants
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "merkle_root"), || Ok(&self.root))?;
        let leaf = UInt64::new_input(ark_relations::ns!(cs, "merkle_leaf"), || Ok(self.leaf))?;

        // private witnesses
        
        // A private witness of the path down the MerkleTree which leads to the commitment.
        let path = TreePathVar::new_witness(ark_relations::ns!(cs, "merkle_tree_path"), || {
            Ok(self.path.as_ref().unwrap())
        })?;
        
        let pk = UInt64::new_witness(ark_relations::ns!(cs, "pub_key"), || Ok(self.coin.pk))?;
        // let pre_serial_no = UInt64::new_witness(ark_relations::ns!(cs, "pre_serial_no"), || {
        //     Ok(&self.coin.pre_serial_no)
        // })?;
        // let com_rnd =
        //     UInt64::new_witness(ark_relations::ns!(cs, "com_rnd"), || Ok(&self.coin.com_rnd))?;
        //
        // let sk = UInt64::new_witness(ark_relations::ns!(cs, "sec_key"), || Ok(&self.sk))?;
        let serial_no =
            UInt64::new_witness(ark_relations::ns!(cs, "serial_no"), || Ok(&self.serial_no))?;

        // 1. We prove that we have a path down the MerkleTree that leads to a commitment which
        //    hashes to:
        //    - pk
        //    - pre_serial_no
        //    - com_rnd
        let is_member =
            path.verify_membership(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf)?;
        
        is_member.enforce_equal(&Boolean::TRUE)?;

        // 2. We enforce that `serial_no = prf(sk, pre_serial_no)`, so that the the payer can't lie
        //    to the payee
        let expected_serial_no = UInt64::new_constant(
            ark_relations::ns!(cs, "expected_serial_no"),
            f(self.sk, self.coin.pre_serial_no),
        )?;
        
        expected_serial_no.enforce_equal(&serial_no)?;

        // 3. We prove that `pk = H(sk)`
        let expected_pk = UInt64::new_constant(ark_relations::ns!(cs, "expected_pk"), h(self.sk))?;
        expected_pk.enforce_equal(&pk)?;

        Ok(())
    }
}

// an example hash function
pub fn h(x: u64) -> u64 {
    x + 1
}

// an example prf
fn f(sk: u64, pre_serial_no: u64) -> u64 {
    sk ^ pre_serial_no
}

fn main() -> Result<()> {
    let sk = 5;
    let pk = h(sk);

    let mut com_rng = rand::thread_rng();
    let mut ark_rng = rand::thread_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut ark_rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut ark_rng).unwrap();

    let pre_serial_no = 4;
    let com_rnd = com_rng.next_u64();
    let serial_no = f(sk, pre_serial_no);

    let coin = Coin::new(pk, pre_serial_no, com_rnd);
    let leaf = Commitment::from(coin.clone());

    let tree = MerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &[
            Commitment::gen_rand(pk, &mut com_rng),
            Commitment::gen_rand(pk, &mut com_rng),
            Commitment::gen_rand(pk, &mut com_rng),
            Commitment::gen_rand(pk, &mut com_rng),
            Commitment::gen_rand(pk, &mut com_rng),
            Commitment::gen_rand(pk, &mut com_rng),
            leaf.clone(), // we're gonna prove it for THIS leaf!
            Commitment::gen_rand(pk, &mut com_rng),
        ],
    )
    .expect("failed to construct MerkleTree");

    let proof = tree.generate_proof(6).unwrap();

    let root = tree.root();

    let v = MyProof {
        leaf_crh_params,
        two_to_one_crh_params,
        root,
        leaf: leaf.clone(),
        path: Some(proof),
        coin,
        sk,
        serial_no,
    };

    let cs = ConstraintSystem::new_ref();
    v.clone().generate_constraints(cs.clone())?;
    let sat = cs.is_satisfied()?;

    println!("{sat}");

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(v.clone(), &mut ark_rng)?;
    let proof = Groth16::prove(&pk, v, &mut ark_rng)?;

    // let mut writer = Vec::<u8>::new();
    // proof
    //     .serialize(&mut writer)
    //     .expect("failed to serialize proof");

    let public_inputs = [
        root,
        Into::<u64>::into(leaf).into()
    ];
    let valid_proof = Groth16::verify(&vk, &public_inputs, &proof)?;

    println!("{valid_proof}");

    Ok(())
}
