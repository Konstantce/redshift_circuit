#[cfg(test)]
mod test {
    use bellman::pairing::bn256::{Bn256, Fr};
    use bellman::pairing::ff::{PrimeField, PrimeFieldRepr};
    use bellman::{Engine, Circuit, ConstraintSystem, SynthesisError};
    use bellman::redshift::IOP::hashes::rescue::{Rescue, RescueParams};
    use bellman::redshift::IOP::hashes::rescue::bn256_rescue_params::BN256Rescue;
    
    use bellman::redshift::IOP::oracle::Oracle;
    use bellman::redshift::IOP::oracle::coset_combining_rescue_tree::*;
    
    use common::num::AllocatedNum;
    use common::boolean::*;
    use common::*;    
    use crate::tester::naming_oblivious_cs::NamingObliviousConstraintSystem as TestConstraintSystem;

    use hashes::rescue::*;
    use hashes::bn256_rescue_sbox::BN256RescueSbox;

    use bellman::redshift::IOP::FRI::coset_combining_fri::FriParams;
    use oracles::OracleGadget;
    use fri::*;
    use oracles::rescue_merklee_proof::*;


    struct FriSetup<E: Engine, O: OracleGadget<E>> 
    {
        upper_layer_commitments: Vec<Labeled<O::Commitment>>,  
        intermidiate_commitments: Vec<O::Commitment>,
        
        final_coefficients: Vec<AllocatedNum<E>>,
        fri_challenges: Vec<AllocatedNum<E>>,
        natural_first_element_indexes: Vec<Vec<Boolean>>,

        _engine_marker : std::marker::PhantomData<E>,
        _oracle_marker: std::marker::PhantomData<O>,
    }

    impl<'a, E: Engine, O: OracleGadget<E>> FromStream<E, &'a FriParams> for FriSetup<E, O> 
    {
        fn from_stream<CS: ConstraintSystem<E>, I: Iterator<Item = Option<E::Fr>>>(
            mut cs: CS, 
            iter: &mut I,
            fri_params: &'a FriParams,
        ) -> Result<Self, SynthesisError> 
        {
            let coset_size = 1 << fri_params.collapsing_factor;
            let top_level_oracle_size = (fri_params.initial_degree_plus_one.get() * fri_params.lde_factor) / coset_size;
            let top_level_oracle_height = log2_floor(top_level_oracle_size);
            
            let mut num_of_iters = log2_floor(fri_params.initial_degree_plus_one.get() / fri_params.final_degree_plus_one) / fri_params.collapsing_factor as usize;
            // we do not count the very first and the last iterations
            num_of_iters -= 2;
            let label = "starting oracle";

            let upper_layer_commitment = Labeled::new(
                label, 
                O::Commitment::from_stream(cs.namespace(|| "upper layer commitment"), iter, top_level_oracle_height)?,
            );

            let mut intermidiate_commitments = Vec::with_capacity(num_of_iters);
            let mut cur_oracle_height = top_level_oracle_height - fri_params.collapsing_factor as usize;
            for _ in 0..num_of_iters {
                let commitment = O::Commitment::from_stream(
                    cs.namespace(|| "intermidiate oracle"), 
                    iter, 
                    cur_oracle_height,
                )?;
                cur_oracle_height -= fri_params.collapsing_factor as usize;
                intermidiate_commitments.push(commitment);
            }

            let final_coefficients = Vec::from_stream(cs.namespace(|| "final coefficients"), iter, fri_params.final_degree_plus_one)?;
            let fri_challenges = Vec::from_stream(cs.namespace(|| "fri challenges"), iter, num_of_iters + 2)?;
            
            let mut natural_first_element_indexes = Vec::with_capacity(num_of_iters);
            for _ in 0..fri_params.R {
                // we prefer to make natural indexes public for testing purposes
                let index = AllocatedNum::alloc_input2(cs.namespace(|| "natural index"), iter.next().unwrap())?; 
                let path = index.into_bits_le(cs.namespace(|| "parse index"))?;
                natural_first_element_indexes.push(path);
            }

            let fri_proof = FriSetup::<E, O> {
                upper_layer_commitments: vec![upper_layer_commitment], 
                intermidiate_commitments,
 
                final_coefficients,
                fri_challenges,
                natural_first_element_indexes,

                _engine_marker : std::marker::PhantomData::<E>,
                _oracle_marker: std::marker::PhantomData::<O>,
            }; 

            Ok(fri_proof)
        }
    }

    struct TestCircuit<E, RP, SBOX, C, I> 
    where E: Engine, RP: RescueParams<E::Fr>, SBOX: RescueSbox<E>, C: UpperLayerCombiner<E>, I: Iterator<Item = Option<E::Fr>>
    {
        iter: I,
        sbox: SBOX,
        rescue_params: RP,
        fri_params: FriParams,
        combiner: C,

        _engine_marker : std::marker::PhantomData<E>,
    }

    impl<E, RP, SBOX, C, I> Circuit<E> for TestCircuit<E, RP, SBOX, C, I> 
    where E: Engine, RP: RescueParams<E::Fr>, SBOX: RescueSbox<E>, C: UpperLayerCombiner<E>, I: Iterator<Item = Option<E::Fr>>
    {
        fn synthesize<CS: ConstraintSystem<E>>(
            self,
            cs: &mut CS,
        ) -> Result<(), SynthesisError> 
        {            
            let fri_verifier_gadget = FriVerifierGadget {
                collapsing_factor : self.fri_params.collapsing_factor as usize,
                num_query_rounds : self.fri_params.R,
                initial_degree_plus_one : self.fri_params.initial_degree_plus_one.get(),
                lde_factor: self.fri_params.lde_factor,
                final_degree_plus_one : self.fri_params.final_degree_plus_one,
                upper_layer_combiner: self.combiner,

                _engine_marker : std::marker::PhantomData::<E>,
                _oracle_marker : std::marker::PhantomData::<RescueTreeGadget<E, RP, SBOX>>,
            };

            let oracle_params = RescueTreeGadgetParams {
                num_elems_per_leaf: 1 << self.fri_params.collapsing_factor,
                rescue_params: &self.rescue_params,
                _marker: std::marker::PhantomData::<E::Fr>,
            };

            let fri_setup = FriSetup::<E, RescueTreeGadget<E, RP, SBOX>>::from_stream(
                cs.namespace(|| "fri setup"),
                &mut self.iter,
                &self.fri_params,
            )?;

            let fri_query_rounds = (0..self.fri_params.R).map(|_| {

                let single_query_data = FriSingleQueryRoundData::from_stream(
                    cs.namespace(|| "fri round"),
                    &mut self.iter,
                    self.fri_params.clone(),
                );
                single_query_data
            }).collect::<Result<Vec<_>, _>>()?;

            let is_valid = fri_verifier_gadget.verify_proof(
                cs.namespace(|| "Validate FRI instance"),
                &oracle_params,

                &fri_setup.upper_layer_commitments[..],
                &fri_setup.intermidiate_commitments[..],
                &fri_setup.final_coefficients[..],
                &fri_setup.fri_challenges[..],
                fri_setup.natural_first_element_indexes,
            
                &fri_query_rounds
            )?;

            Boolean::enforce_equal(
                cs.namespace(|| "Validate output bit of Merkle proof"),
                &is_valid,
                &Boolean::constant(true),
            )
        }
    }


    #[test]
    fn test_fri_verifier() 
    {
        use crate::pairing::bn256::Fr as Fr;

        let bn256_rescue_params = BN256Rescue::default();

        const SIZE: usize = 1024;
        let worker = Worker::new_with_cpus(1);
        let mut channel = Blake2sChannel::new(&());

        let params = FriParams {
            collapsing_factor: 2,
            R: 4,
            initial_degree_plus_one: std::cell::Cell::new(SIZE),
            lde_factor: 4,
            final_degree_plus_one: 4,
        };

        let oracle_params = FriSpecificBlake2sTreeParams {
            values_per_leaf: 1 << params.collapsing_factor
        };

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let coeffs = (0..SIZE).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    
        let poly = Polynomial::<Fr, _>::from_coeffs(coeffs).unwrap();
        let precomp = BitReversedOmegas::<Fr>::new_for_domain_size(poly.size());

        let coset_factor = Fr::multiplicative_generator();
        let eval_result = poly.bitreversed_lde_using_bitreversed_ntt(&worker, 4, &precomp, &coset_factor).unwrap();

        // construct upper layer oracle from eval_result

        let upper_layer_oracle = FriSpecificBlake2sTree::create(eval_result.as_ref(), &oracle_params);
        let batched_oracle = BatchedOracle::create(vec![("starting oracle", &upper_layer_oracle)]);
        let upper_layer_commitments = batched_oracle.get_commitment();

        let fri_precomp = <OmegasInvBitreversed::<Fr> as FriPrecomputations<Fr>>::new_for_domain_size(eval_result.size());

        let fri_proto = FriIop::<Fr, FriSpecificBlake2sTree<Fr>, Blake2sChannel<Fr>>::proof_from_lde(
            eval_result.clone(), 
            &fri_precomp, 
            &worker, 
            &mut channel,
            &params,
            &oracle_params,
        ).expect("FRI must succeed");

        let proof = FriIop::<Fr, FriSpecificBlake2sTree<Fr>, Blake2sChannel<Fr>>::prototype_into_proof(
            fri_proto,
            &batched_oracle,
            vec![eval_result.as_ref()],
            vec![6, 4, 127, 434],
            &params,
            &oracle_params,
        ).expect("Fri Proof must be constrcuted");

        channel.reset();
        let fri_challenges = FriIop::<Fr, FriSpecificBlake2sTree<Fr>, Blake2sChannel<Fr>>::get_fri_challenges(
            &proof,
            &mut channel,
            &params,
        );

        // upper layer combiner is trivial in our case
        let upper_layer_combiner = |arr: Vec<(Label, &Fr)>| -> Option<Fr> {
            let res = arr.iter().find(|(l, _)| *l == "starting oracle").map(|(_, c)| (*c).clone());
            res
        };

        let result = FriIop::<Fr, FriSpecificBlake2sTree<Fr>, Blake2sChannel<Fr>>::verify_proof_queries(
            &proof,
            upper_layer_commitments,
            vec![6, 4, 127, 434],
            &fri_challenges,
            &params,
            &oracle_params,
            upper_layer_combiner,
        ).expect("Verification must be successful");

        assert_eq!(result, true);    
        let mut cs = TestConstraintSystem::<Bn256>::new();
        test_circuit.synthesize(&mut cs).expect("should synthesize");

        assert!(cs.is_satisfied());

        cs.modify_input(1, "allocate root/num", Fr::one());
        assert!(!cs.is_satisfied());

        println!("Rescue tree for 4096 elements with 4 elements per leaf requires {} constraints", cs.num_constraints());
    }
}

   