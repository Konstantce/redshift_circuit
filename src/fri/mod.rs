pub mod fri_utils;
pub mod fri_verifier;
pub mod tests;

use common::*;
use common::num::*;
use oracles::*;

use bellman::{
    Engine,
    SynthesisError,
    ConstraintSystem,
};

use bellman::redshift::IOP::FRI::coset_combining_fri::FriParams;


pub trait UpperLayerCombiner<E: Engine> {
    fn combine<CS: ConstraintSystem<E>>(
        &self,
        cs: CS, 
        domain_values: Vec<Labeled<&AllocatedNum<E>>>,
        evaluation_point : &Num<E>
    ) -> Result<AllocatedNum<E>, SynthesisError>; 
}


pub struct FriSingleQueryRoundData<E: Engine, I: OracleGadget<E>> {   
    pub upper_layer_queries: LabeledVec<Query<E, I>>,
    // this structure is modified internally as we simplify Nums during he work of the algorithm
    pub queries: Vec<Query<E, I>>,
}


pub struct FriVerifierGadget<E: Engine, I: OracleGadget<E>, C: UpperLayerCombiner<E>>
{
    pub collapsing_factor : usize,
    //number of iterations done during FRI query phase
    pub num_query_rounds : usize,
    pub initial_degree_plus_one : usize,
    pub lde_factor: usize,
    //the degree of the resulting polynomial at the bottom level of FRI
    pub final_degree_plus_one : usize,
    pub upper_layer_combiner: C,

    pub _engine_marker : std::marker::PhantomData<E>,
    pub _oracle_marker : std::marker::PhantomData<I>,
}


impl<E: Engine, O: OracleGadget<E>> FromStream<E, (FriParams, &[Label])> for FriSingleQueryRoundData<E, O> {

    fn from_stream<CS: ConstraintSystem<E>, I: Iterator<Item = Option<E::Fr>>>(
        mut cs: CS, 
        iter: &mut I,
        params: (FriParams, &[Label]),
    ) -> Result<Self, SynthesisError> 
    {
        let (fri_params, labels) = params;
        
        let coset_size = 1 << fri_params.collapsing_factor;
        let top_level_oracle_size = (fri_params.initial_degree_plus_one.get() * fri_params.lde_factor) / coset_size;
        let top_level_height = log2_floor(top_level_oracle_size);
        
        let mut num_of_iters = log2_floor(fri_params.initial_degree_plus_one.get() / fri_params.final_degree_plus_one) / fri_params.collapsing_factor as usize;
        // we do not count the very first and the last iterations
        num_of_iters -= 1;
        println!("from stream num_iters: {}", num_of_iters);
        
        let mut upper_layer_queries = Vec::with_capacity(labels.len());

        for label in labels.iter() {
            let elem = Labeled::new(
                label, 
                Query::from_stream(cs.namespace(|| "upper_layer_query"), iter, (coset_size, top_level_height))?,
            );
            upper_layer_queries.push(elem);
        }

        let mut cur_height = top_level_height - fri_params.collapsing_factor as usize;
        let mut queries = Vec::with_capacity(num_of_iters);

        for _ in 0..num_of_iters {
            println!("reading query");
            let query = Query::from_stream(
                cs.namespace(|| "intermidiate query"), 
                iter, 
                (coset_size, cur_height),
            )?;
            cur_height -= fri_params.collapsing_factor as usize;
            queries.push(query)
        }

        Ok(FriSingleQueryRoundData{ upper_layer_queries, queries })
    }
}