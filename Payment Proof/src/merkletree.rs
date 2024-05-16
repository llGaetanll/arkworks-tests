use ark_crypto_primitives::{
    crh::{
        constraints::{CRHGadget, TwoToOneCRHGadget}, injective_map::{
            constraints::{PedersenCRHCompressorGadget, TECompressorGadget},
            PedersenCRHCompressor, TECompressor,
        }, pedersen, TwoToOneCRH
    },
    merkle_tree::{Config, MerkleTree as ArkMerkleTree}, Path, PathVar, CRH,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use crate::ScalarField;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 144;
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 128;
}

pub type LeafHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;
pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;

#[derive(Clone)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

pub type TwoToOneHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    TwoToOneWindow,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    LeafWindow,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHashParamsVar = <LeafHashGadget as CRHGadget<LeafHash, ScalarField>>::ParametersVar;
pub type TwoToOneHashParamsVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ScalarField>>::ParametersVar;
pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ScalarField>>::OutputVar;
pub type LeafVar = <LeafHashGadget as CRHGadget<LeafHash, ScalarField>>::OutputVar;
pub type TreePathVar = PathVar<MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ScalarField>;

pub type MerkleTree = ArkMerkleTree<MerkleConfig>;
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;
pub type Leaf = <LeafHash as CRH>::Output;
pub type TreePath = Path<MerkleConfig>;
