use bellman::pairing::{
    Engine,
};

use bellman::pairing::ff::{
    Field,
    PrimeField,
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    LinearCombination,
    Variable
};

use std::marker::PhantomData;

use common::num::*;
use common::boolean::*;
use common::{FromStream, OracleHeight, CosetSize};

pub mod rescue_merklee_proof;


// this trais is used as an abstraction over Merklee proofs

pub trait OracleGadget<E: Engine> {
    type Params;
    // additional paramter for parser is the height of the tree
    type Proof : FromStream<E, OracleHeight>;
    type Commitment : FromStream<E, OracleHeight> + Clone;

    fn new(params: &Self::Params) -> Self;

    fn validate<CS: ConstraintSystem<E>>(
        &self, 
        cs: CS,
        height: usize, 
        elems : &[AllocatedNum<E>],
        path: &[Boolean],
        commitment: &Self::Commitment, 
        proof: &Self::Proof,
    ) -> Result<Boolean, SynthesisError>;
}


// container that holds the values alongside the proof 
// NB: there is no need to store the index (or path), as it is calculated and checked by verifier
pub struct Query<E: Engine, O: OracleGadget<E>> {
    pub values: Vec<AllocatedNum<E>>,
    pub proof: O::Proof,
    pub _marker: std::marker::PhantomData<O>,
}


impl<E: Engine, O: OracleGadget<E>> FromStream<E, (CosetSize, OracleHeight)> for Query<E, O> {

    fn from_stream<CS: ConstraintSystem<E>, I: Iterator<Item = Option<E::Fr>>>(
        mut cs: CS, 
        iter: &mut I,
        params: (CosetSize, OracleHeight),
    ) -> Result<Self, SynthesisError> {

        let coset_size = params.0;
        let height = params.1;

        let values = Vec::from_stream(cs.namespace(|| "query values"), iter, coset_size)?;
        let proof = O::Proof::from_stream(cs.namespace(|| "query proof"), iter, height)?;

        Ok(Query { values, proof, _marker: std::marker::PhantomData::<O> })
    }
}


