use super::fri_utils::*;
use oracles::*;

use bellman::pairing::{
    Engine,
};
use bellman::{
    SynthesisError,
    ConstraintSystem,
};

use bellman::pairing::ff::{
    Field,
    PrimeField,
};

use common::num::*;
use common::boolean::*;
use common::{Labeled, LabeledVec, log2_floor};


use super::{UpperLayerCombiner, FriVerifierGadget, FriSingleQueryRoundData};


impl<E: Engine, I: OracleGadget<E>, C: UpperLayerCombiner<E>> FriVerifierGadget<E, I, C> 
{

    fn verify_single_proof_round<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,

        upper_layer_queries: &[Labeled<Query<E, I>>],
        upper_layer_commitments: &[Labeled<I::Commitment>], 
        fri_helper: &mut FriUtilsGadget<E>,

        queries: &[Query<E, I>],
        commitments: &[I::Commitment],
        final_coefficients: &[AllocatedNum<E>],

        natural_first_element_index: &[Boolean],
        fri_challenges: &[AllocatedNum<E>],

        oracle_params: &I::Params,
   
    ) -> Result<Boolean, SynthesisError>
    {
        
        let collapsing_factor = fri_helper.get_collapsing_factor();
        let mut natural_index = &natural_first_element_index[..];
        let coset_idx = fri_helper.get_coset_idx_for_natural_index(natural_index);
        let coset_size = 1 << collapsing_factor;

        // check oracle proof for each element in the upper layer!
        let oracle = I::new(oracle_params);
        let mut final_result = Boolean::Constant(true);

        for labeled_query in upper_layer_queries.iter() {

            let label = &labeled_query.label;
            let commitment_idx = upper_layer_commitments.iter().position(|x| x.label == *label).ok_or(SynthesisError::Unknown)?;
            let commitment = &upper_layer_commitments[commitment_idx].data;
            let oracle_check = oracle.validate(
                cs.namespace(|| "Oracle proof"),
                fri_helper.get_log_domain_size(),
                &labeled_query.data.values, 
                coset_idx,
                commitment, 
                &labeled_query.data.proof, 
            )?;

            final_result = Boolean::and(cs.namespace(|| "and"), &final_result, &oracle_check)?;
        }

        // apply combiner function in order to conduct Fri round consistecy check
        // with respect to the topmost layer
        // let n be the size of coset
        // let the values contained inside queries to be (a_1, a_2, ..., a_n), (b_1, b_2, ..., b_n) , ..., (c_1, ..., c_n)
        // Coset combining function F constructs new vector of length n: (d_1, ..., d_n) via the following_rule : 
        // d_i = F(a_i, b_i, ..., c_i, x_i), i in (0..n)
        // here additiona argument x_i is the evaluation point and is defined by the following rule:
        // if the coset idx has bit representation xxxxxxxx, then x_i = w^(bitreverse(yyyy)|xxxxxxx)
        // here i = |yyyy| (bit decomposition)
        // From this we see that the only common constrained part for all x_i is coset_omega = w^(xxxxxx)
        // and to get corresponding x_i we need to multiply coset_omega by constant c_i = w^(bitreverse(yyyy)|000000)
        // if g = w^(100000) then c_i = w^(bitreverse(yyyy) * 1000000) = g^(bitreverse(yyyy))
        // constants c_i are easily deduced from domain parameters
        // construction of x_i is held by fri_utils

        let mut values = Vec::with_capacity(coset_size);
        let evaluation_points = fri_helper.get_combiner_eval_points(
            cs.namespace(|| "find evaluation points"), 
            coset_idx.iter()
        )?;

        for i in 0..coset_size {

            let labeled_argument : Vec<Labeled<&AllocatedNum<E>>> = upper_layer_queries.iter().map(|x| {
                Labeled::new(x.label, &x.data.values[i])
                }).collect();

            let res = self.upper_layer_combiner.combine(
                cs.namespace(|| "upper layer combiner"), 
                labeled_argument, 
                &evaluation_points[i]
            )?;
            values.push(res);
        }

        let mut previous_layer_element = fri_helper.coset_interpolation_value(
            cs.namespace(|| "coset interpolant computation"),
            &values[..],
            coset_idx.iter(),
            &fri_challenges[0..coset_size], 
        )?;

        for ((query, commitment), challenges) 
            in queries.into_iter().zip(commitments.iter()).zip(fri_challenges.chunks(coset_size).skip(1)) 
        {
            // adapt fri_helper for smaller domain
            fri_helper.next_domain(cs.namespace(|| "shrink domain to next layer"));

            // new natural_elem_index = (old_natural_element_index << collapsing_factor) % domain_size
            natural_index = &natural_index[collapsing_factor..fri_helper.get_log_domain_size()];
            let coset_idx = fri_helper.get_coset_idx_for_natural_index(natural_index);
            let offset = fri_helper.get_coset_offset_for_natural_index(natural_index);

            // oracle proof for current layer!
            let oracle_check = oracle.validate(
                cs.namespace(|| "Oracle proof"),
                fri_helper.get_log_domain_size(),
                &query.values, 
                coset_idx,
                commitment, 
                &query.proof, 
            )?;

            final_result = Boolean::and(cs.namespace(|| "and"), &final_result, &oracle_check)?;

            // round consistency check (rcc) : previous layer element interpolant has already been stored
            // compare it with current layer element (which is chosen from query values by offset)
            let cur_layer_element = fri_helper.choose_element_in_coset(
                cs.namespace(|| "choose element from coset by index"),
                &query.values[..],
                offset,
            )?; 
            let rcc_flag = AllocatedNum::equals(
                cs.namespace(|| "FRI round consistency check"), 
                &previous_layer_element, 
                &cur_layer_element,
            )?;
            final_result = Boolean::and(cs.namespace(|| "and"), &final_result, &rcc_flag)?;

            //recompute interpolant (using current layer for now) 
            //and store it for use on the next iteration (or for final check)
            previous_layer_element = fri_helper.coset_interpolation_value(
                cs.namespace(|| "coset interpolant computation"),
                &query.values[..],
                coset_idx.iter(),
                &fri_challenges, 
            )?;
        }

        // finally we compare the last interpolant with the value f(\omega), 
        // where f is built from coefficients

        assert!(final_coefficients.len() > 0);
        let val = if final_coefficients.len() == 1 {
            // if len is 1 there is no need to create additional omega with constraint overhea
            final_coefficients[0].clone()
        }
        else {

            fri_helper.next_domain(cs.namespace(|| "shrink domain to final layer"));
            natural_index = &natural_index[collapsing_factor..fri_helper.get_log_domain_size()];
            let omega = fri_helper.get_bottom_layer_omega(cs.namespace(|| "final layer generator"))?;
            let ev_p = AllocatedNum::pow(
                cs.namespace(|| "poly eval: evaluation point"), 
                omega, 
                natural_index.iter(),
            )?;

            let mut t = ev_p.clone();
            let mut running_sum : Num<E> = final_coefficients[0].clone().into();

            for c in final_coefficients.iter().skip(1) {

                let term = t.mul(cs.namespace(|| "next term"), c)?;
                t = t.mul(cs.namespace(|| "t^i"), &ev_p)?;
                running_sum.mut_add_number_with_coeff(&term, E::Fr::one());
            }

            running_sum.simplify(cs.namespace(|| "simplification of running sum"))?
        };

        let flag = AllocatedNum::equals(
            cs.namespace(|| "FRI final round consistency check"), 
            &previous_layer_element, 
            &val,
        )?;
        final_result = Boolean::and(cs.namespace(|| "and"), &final_result, &flag)?;

        Ok(final_result)
    }


    pub fn verify_proof<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        oracle_params: &I::Params,
        // data that is shared among all Fri query rounds
        upper_layer_commitments: &[Labeled<I::Commitment>],
        commitments: &[I::Commitment],
        final_coefficients: &[AllocatedNum<E>],
        fri_challenges: &[AllocatedNum<E>],
        natural_first_element_indexes: Vec<Vec<Boolean>>, 

        query_rounds_data: &Vec<FriSingleQueryRoundData<E, I>>,
    ) -> Result<Boolean, SynthesisError> 
    {
        
        // construct global parameters
        let mut final_result = Boolean::Constant(true);
        let mut temp_arr = Vec::with_capacity(self.collapsing_factor * fri_challenges.len());

        let unpacked_fri_challenges = match self.collapsing_factor {
            1 => &fri_challenges,
            _ => {
                for challenge in fri_challenges.iter().cloned() {
                    let mut cur = challenge.clone();
                    temp_arr.push(challenge);
                    for _ in 1..self.collapsing_factor {
                        cur = cur.square(cs.namespace(|| "square challenge"))?;
                        temp_arr.push(cur.clone())
                    }
                }
                &temp_arr[..]
            }
        };

        let num_iters = log2_floor(self.initial_degree_plus_one / self.final_degree_plus_one) / self.collapsing_factor;

        let mut fri_helper = FriUtilsGadget::new(
            cs.namespace(|| "Fri Utils constructor"),
            self.initial_degree_plus_one * self.lde_factor,
            self.collapsing_factor,
            num_iters,
        );

        for (single_round_data, natural_first_element_index) in 
            query_rounds_data.iter().zip(natural_first_element_indexes) {

            let flag = self.verify_single_proof_round(
                cs.namespace(|| "FRI single round verifier"),
                &single_round_data.upper_layer_queries[..],
                upper_layer_commitments,
                &mut fri_helper,

                &single_round_data.queries[..],
                commitments,
                final_coefficients,

                &natural_first_element_index[..],
                &unpacked_fri_challenges[..],
                oracle_params,
            )?;

            final_result = Boolean::and(cs.namespace(|| "and"), &final_result, &flag)?;
        }

        Ok(final_result)
    }
}


#[cfg(test)]
mod test {
    use bellman::pairing::bn256::{Bn256, Fr};
    use bellman::pairing::ff::{PrimeField, PrimeFieldRepr};
    use bellman::Circuit;
    use bellman::redshift::IOP::hashes::rescue::{Rescue, RescueParams};
    use bellman::redshift::IOP::hashes::rescue::bn256_rescue_params::BN256Rescue;
    
    use bellman::redshift::IOP::oracle::Oracle;
    use bellman::redshift::IOP::oracle::coset_combining_rescue_tree::*;
    
    use common::num::AllocatedNum;
    use common::boolean::AllocatedBit;    
    use crate::tester::naming_oblivious_cs::NamingObliviousConstraintSystem as TestConstraintSystem;

    use hashes::rescue::*;
    use hashes::bn256_rescue_sbox::BN256RescueSbox;

    use super::*;

    use bellman::redshift::IOP::FRI::coset_combining_fri::FriParams;


    #[test]
    fn test_fri_verifier() 
    {
        struct TestCircuit<E: Engine, RP: RescueParams<E::Fr>, SBOX: RescueSbox<E>, C: UpperLayerCombiner<E>> {
            size: usize,
            num_elems_per_leaf: usize,
            sbox: SBOX,
            rescue_params: RP,

            root_hash: E::Fr,
            leaf_elems: Vec<E::Fr>,
            index: u64,
            merkle_proof: Vec<E::Fr>,
        }

        impl<E: Engine, RP: RescueParams<E::Fr>, SBOX: RescueSbox<E>> Circuit<E> for TestCircuit<E, RP, SBOX> {
            fn synthesize<CS: ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {

                let root = AllocatedNum::alloc_input(cs.namespace(|| "allocate root"), || Ok(self.root_hash))?;
                let index = self.index;

                let elems = self.leaf_elems.into_iter().map(|e| {
                    AllocatedNum::alloc(cs.namespace(|| "allocate leaf elem"), || Ok(e))
                }).collect::<Result<Vec<_>, SynthesisError>>()?;

                let proof : Vec<AllocatedNum<E>> = self.merkle_proof.into_iter().map(|e| {
                    AllocatedNum::alloc(cs.namespace(|| "allocate merkle proof elem"), || Ok(e))
                }).collect::<Result<Vec<_>, SynthesisError>>()?;

                let index = AllocatedNum::alloc(
                    cs.namespace(|| "index"), 
                    || {
                        let mut r = <E::Fr as PrimeField>::Repr::default();
                        r.as_mut()[0] = index;
                        let x = <E::Fr as PrimeField>::from_repr(r).expect("must convert");
                        Ok(x)
                    },
                )?;
                let path = index.into_bits_le(cs.namespace(|| "parse index"))?;

                let tree_params = RescueTreeGadgetParams {
                    num_elems_per_leaf: self.num_elems_per_leaf,
                    rescue_params: &self.rescue_params,
                    _marker: std::marker::PhantomData::<E::Fr>,
                };
                let tree = RescueTreeGadget::<E, RP, SBOX>::new(&tree_params);

                let is_valid = tree.validate(
                    cs.namespace(|| "test merkle proof"),
                    log2_floor(self.size), 
                    &elems[..], 
                    &path,
                    &root, 
                    &proof,
                )?;

                Boolean::enforce_equal(
                    cs.namespace(|| "Validate output bit of Merkle proof"),
                    &is_valid,
                    &Boolean::constant(true),
                )
            }
        }

        let bn256_rescue_params = BN256Rescue::default();

        let (index, root, elems, proof) = {

            let oracle_params = RescueTreeParams {
                values_per_leaf: 4,
                rescue_params: &bn256_rescue_params,
                _marker: std::marker::PhantomData::<Fr>,
            };

            // we are going to create tree constaining 4096 elements, with 4 elements per leaf
            // hence there are 1024 leaves

            let values : Vec<Fr> = (0..4096).scan(Fr::multiplicative_generator(), |cur, _| {
                let res = cur.clone();
                cur.double();
                Some(res)
            }).collect();

            let tree = FriSpecificRescueTree::create(&values[..], &oracle_params);

            assert_eq!(tree.size(), 4096);

            let root = tree.get_commitment();

            // let out index be 42

            let leaf_elements = Vec::from_iter(values[42*4..43*4].iter().cloned());
            let query : CosetCombinedQuery<Fr> = tree.produce_query(42*4..43*4, &values[..], &oracle_params);
            let proof = query.raw_merkle_proof();

            (42, root, leaf_elements, proof)
        };

        let test_circuit = TestCircuit::<Bn256, BN256Rescue, BN256RescueSbox> {
            size: 1024,
            num_elems_per_leaf: 4,
            sbox: BN256RescueSbox{},
            rescue_params: bn256_rescue_params,

            root_hash: root,
            leaf_elems: elems,
            index: index as u64,
            merkle_proof: proof,
        };

        let mut cs = TestConstraintSystem::<Bn256>::new();
        test_circuit.synthesize(&mut cs).expect("should synthesize");

        assert!(cs.is_satisfied());

        cs.modify_input(1, "allocate root/num", Fr::one());
        assert!(!cs.is_satisfied());

        println!("Rescue tree for 4096 elements with 4 elements per leaf requires {} constraints", cs.num_constraints());
    }
}

   