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
};


use common::num::*;
use common::boolean::*;
use oracles::*;
use common::*;
use fri::*;

use bellman::redshift::IOP::FRI::coset_combining_fri::FriParams;


pub struct SinglePolySetupData<E: Engine, I: OracleGadget<E>> {
    pub setup_value : AllocatedNum<E>,
    pub commitment : I::Commitment,
}


pub struct RedshiftSetupPrecomputation<E: Engine, I: OracleGadget<E>> {
    pub setup_point: AllocatedNum<E>,
    // containes precomputations for:  
    // q_l, q_r, q_o, q_m, q_c, q_add_sel, s_id, sigma_1, sigma_2, sigma_3
    pub data : LabeledVec<SinglePolySetupData<E, I>>,
}


pub struct BatchedFriProof<E: Engine, I: OracleGadget<E>> {
    // commitments to all intermidiate oracles
    pub commitments: Vec<I::Commitment>,
    pub final_coefficients: Vec<AllocatedNum<E>>,
    pub fri_round_queries : Vec<FriSingleQueryRoundData<E, I>>,
}


pub struct RedshiftProof<E: Engine, I: OracleGadget<E>> {
    // containes opening values for:
    // a, b, c, c_shifted, q_l, q_r, q_o, q_m, q_c, q_add_sel, 
    // s_id, sigma_1, sigma_2, sigma_3,
    // z_1, z_2, z_1_shifted, z_2_shifted, t_low, t_mid, t_high
    pub opening_values: LabeledVec<AllocatedNum<E>>,
    // contains commitments for a, b, c, z_1, z_2, t_low, t_mid, t_high
    pub commitments: LabeledVec<I::Commitment>,
    pub fri_proof: BatchedFriProof<E, I>,
}


impl<E: Engine, O: OracleGadget<E>> FromStream<E, OracleHeight> for SinglePolySetupData<E, O>
{
    fn from_stream<CS: ConstraintSystem<E>, I: Iterator<Item = Option<E::Fr>>>(
        mut cs: CS, 
        iter: &mut I,
        params: OracleHeight,
    ) -> Result<Self, SynthesisError> 
    {
        let setup_value = AllocatedNum::from_stream(cs.namespace(|| "setup value"), iter, ())?;
        let commitment = O::Commitment::from_stream(cs.namespace(|| "setup commitment"), iter, params)?;
        Ok(SinglePolySetupData { setup_value, commitment })
    }
}


impl<E: Engine, O: OracleGadget<E>> FromStream<E, OracleHeight> for RedshiftSetupPrecomputation<E, O> {

    fn from_stream<CS: ConstraintSystem<E>, I: Iterator<Item = Option<E::Fr>>>(
        mut cs: CS, 
        iter: &mut I,
        params: OracleHeight,
    ) -> Result<Self, SynthesisError> 
    {
        let setup_point = AllocatedNum::from_stream(cs.namespace(|| "setup value"), iter, ())?;
        // q_l, q_r, q_o, q_m, q_c, q_add_sel, s_id, sigma_1, sigma_2, sigma_3
        let labels = ["q_l", "q_r", "q_o", "q_m", "q_c", "q_add_sel", "s_id", "sigma_1", "sigma_2", "sigma_3"];
        let mut data = Vec::with_capacity(labels.len());

        for label in labels.iter() {
            let elem = Labeled::new(
                label, 
                SinglePolySetupData::from_stream(cs.namespace(|| "setup data"), iter, params)?,
            );
            data.push(elem);
        }
        
        Ok(RedshiftSetupPrecomputation {setup_point, data})
    }
}


impl<E: Engine, O: OracleGadget<E>> FromStream<E, FriParams> for BatchedFriProof<E, O> {

    fn from_stream<CS: ConstraintSystem<E>, I: Iterator<Item = Option<E::Fr>>>(
        mut cs: CS, 
        iter: &mut I,
        fri_params: FriParams,
    ) -> Result<Self, SynthesisError> 
    {

        let coset_size = 1 << fri_params.collapsing_factor;
        let top_level_oracle_size = (fri_params.initial_degree_plus_one.get() * fri_params.lde_factor) / coset_size;
        let top_leve_height = log2_floor(top_level_oracle_size);
        
        let mut num_of_iters = log2_floor(fri_params.initial_degree_plus_one.get() / fri_params.final_degree_plus_one) / fri_params.collapsing_factor as usize;
        // we do not count the very first and the last iterations
        num_of_iters -= 1;

        let mut cur_height = top_leve_height - fri_params.collapsing_factor as usize;
        let mut commitments = Vec::with_capacity(num_of_iters);

        for _ in 0..num_of_iters {
            let commitment = O::Commitment::from_stream(
                cs.namespace(|| "intermidiate commitment"), 
                iter, 
                cur_height,
            )?;
            commitments.push(commitment);
            cur_height -= fri_params.collapsing_factor as usize;
        }

        let final_coefficients = 
            Vec::from_stream(cs.namespace(|| "final coefficients"), iter, fri_params.final_degree_plus_one)?;

        let labels = ["q_l", "q_r", "q_o", "q_m", "q_c", "q_add_sel", "s_id", "sigma_1", "sigma_2", "sigma_3",
            "a", "b", "c", "z_1", "z_2", "t_low", "t_mid", "t_high"];

        let mut fri_round_queries = Vec::with_capacity(fri_params.R);
        for _ in 0..fri_params.R {
            let fri_round = FriSingleQueryRoundData::from_stream(
                cs.namespace(|| "FRI round query"), iter, (fri_params.clone(), &labels))?;
            fri_round_queries.push(fri_round);
        }
        
        Ok(BatchedFriProof { commitments, final_coefficients, fri_round_queries })
    }
}


impl<E: Engine, O: OracleGadget<E>> FromStream<E, FriParams> for RedshiftProof<E, O> {

    fn from_stream<CS: ConstraintSystem<E>, I: Iterator<Item = Option<E::Fr>>>(
        mut cs: CS, 
        iter: &mut I,
        fri_params: FriParams,
    ) -> Result<Self, SynthesisError> 
    {
              
        // containes opening values for:
        // a, b, c, c_shifted, q_l, q_r, q_o, q_m, q_c, q_add_sel, 
        // s_id, sigma_1, sigma_2, sigma_3,
        // z_1, z_2, z_1_shifted, z_2_shifted, t_low, t_mid, t_high
        let labels = ["a", "b", "c", "c_shifted", "q_l", "q_r", "q_o", "q_m", "q_c", "q_add_sel", 
            "s_id", "sigma_1", "sigma_2", "sigma_3", "z_1", "z_2", "z_1_shifted", "z_2_shifted",
            "t_low", "t_mid", "t_high"];

        let mut opening_values = Vec::with_capacity(labels.len());

        for label in labels.iter() {
            let elem = Labeled::new(
                label,
                AllocatedNum::from_stream(cs.namespace(|| "opening values"), iter, ())?,
            );
        
            opening_values.push(elem);
        }

        let coset_size = 1 << fri_params.collapsing_factor;
        let top_level_oracle_size = (fri_params.initial_degree_plus_one.get() * fri_params.lde_factor) / coset_size;
        let height = log2_floor(top_level_oracle_size);

        // contains commitments for a, b, c, z_1, z_2, t_low, t_mid, t_high
        let labels = ["a", "b", "c", "z_1", "z_2", "t_low", "t_mid", "t_high"];
        let mut commitments = Vec::with_capacity(labels.len());
        for label in labels.iter() {
            let elem = Labeled::new(
                label,
                O::Commitment::from_stream(cs.namespace(|| "commitments to witness polys"), iter, height)?,
            );
            commitments.push(elem);
        }

        let fri_proof = BatchedFriProof::from_stream(
            cs.namespace(|| "batched FRI proof"), 
            iter, 
            fri_params,
        )?;

        Ok(RedshiftProof { opening_values, commitments, fri_proof })
    }
}
