#[cfg(test)]
mod test {
    use bellman::pairing::bn256::{Bn256, Fr};
    use bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
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


    struct TrivialCombiner {}

    impl<E: Engine> UpperLayerCombiner<E> for TrivialCombiner {
        fn combine<CS: ConstraintSystem<E>>(
            &self,
            cs: CS, 
            domain_values: Vec<Labeled<&AllocatedNum<E>>>,
            evaluation_point : &Num<E>
        ) -> Result<AllocatedNum<E>, SynthesisError>
        {
            let res = domain_values.into_iter().find(|elem| elem.label == "starting oracle").map(|elem| elem.data.clone()).ok_or(SynthesisError::Unknown);
            res
        }
    }


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
            num_of_iters -= 1;
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
            println!("num fri challenges read: {}", num_of_iters + 1);
            let fri_challenges = Vec::from_stream(cs.namespace(|| "fri challenges"), iter, num_of_iters + 1)?;
            
            let mut natural_first_element_indexes = Vec::with_capacity(fri_params.R);
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
            let mut iter = self.iter;
            let fri_params = self.fri_params;

            println!("before reading from stream");

            let fri_setup = FriSetup::<E, RescueTreeGadget<E, RP, SBOX>>::from_stream(
                cs.namespace(|| "fri setup"),
                &mut iter,
                &fri_params,
            )?;

            println!("1");

            let labels = vec!["starting oracle"];
            let fri_query_rounds = (0..fri_params.R).map(|_| {

                let single_query_data = FriSingleQueryRoundData::from_stream(
                    cs.namespace(|| "fri round"),
                    &mut iter,
                    (fri_params.clone(), &labels),
                );
                single_query_data
            }).collect::<Result<Vec<_>, _>>()?;

            println!("2");

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
        use bellman::redshift::IOP::channel::rescue_channel::*;
        use bellman::multicore::*;
        use bellman::redshift::IOP::channel::*;
        use bellman::redshift::IOP::oracle::coset_combining_rescue_tree::*;
        use bellman::redshift::polynomials::*;
        use bellman::redshift::fft::cooley_tukey_ntt::*;
        use bellman::redshift::IOP::oracle::*;
        use bellman::redshift::IOP::FRI::coset_combining_fri::*;
        use bellman::redshift::IOP::FRI::coset_combining_fri::precomputation::*;
        use bellman::redshift::redshift::serialization::ToStream;

        use hashes::bn256_rescue_sbox::BN256RescueSbox;
        use tester::naming_oblivious_cs::NamingObliviousConstraintSystem as TestConstraintSystem;

        use rand::*;
        
        type E = bellman::pairing::bn256::Bn256;
        type O<'a> = FriSpecificRescueTree<'a, Fr, BN256Rescue>;
        type T<'a> = RescueChannel<'a, Fr, BN256Rescue>;

        let bn256_rescue_params = BN256Rescue::default();

        const SIZE: usize = 1024;
        let worker = Worker::new_with_cpus(1);

        let channel_params = RescueChannelParams {
            rescue_params: &bn256_rescue_params,
            _marker: std::marker::PhantomData::<Fr>,
        };

        let mut channel = RescueChannel::new(&channel_params);
        //let natural_indexes = vec![6, 4, 127, 434];
        let natural_indexes = vec![0];

        let fri_params = FriParams {
            collapsing_factor: 2,
            R: natural_indexes.len(),
            initial_degree_plus_one: std::cell::Cell::new(SIZE),
            lde_factor: 4,
            final_degree_plus_one: 4,
        };

        let oracle_params = RescueTreeParams {
            values_per_leaf: 1 << fri_params.collapsing_factor,
            rescue_params: &bn256_rescue_params,
            _marker: std::marker::PhantomData::<Fr>,
        };

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let coeffs = (0..SIZE).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    
        let poly = Polynomial::<Fr, _>::from_coeffs(coeffs).unwrap();
        let precomp = BitReversedOmegas::<Fr>::new_for_domain_size(poly.size());

        let coset_factor = Fr::multiplicative_generator();
        let eval_result = poly.bitreversed_lde_using_bitreversed_ntt(&worker, 4, &precomp, &coset_factor).unwrap();

        // construct upper layer oracle from eval_result

        let upper_layer_oracle = FriSpecificRescueTree::create(eval_result.as_ref(), &oracle_params);
        let batched_oracle = BatchedOracle::create(vec![("starting oracle", &upper_layer_oracle)]);
        let upper_layer_commitments = batched_oracle.get_commitment();

        let fri_precomp = <OmegasInvBitreversed::<Fr> as FriPrecomputations<Fr>>::new_for_domain_size(eval_result.size());

        let fri_proto = FriIop::<Fr, O, T>::proof_from_lde(
            eval_result.clone(), 
            &fri_precomp, 
            &worker, 
            &mut channel,
            &fri_params,
            &oracle_params,
        ).expect("FRI must succeed");

        let proof = FriIop::<Fr, O, T>::prototype_into_proof(
            fri_proto,
            &batched_oracle,
            vec![eval_result.as_ref()],
            natural_indexes.clone(),
            &fri_params,
            &oracle_params,
        ).expect("Fri Proof must be constrcuted");

        channel.reset();
        let fri_challenges = FriIop::<Fr, O, T>::get_fri_challenges(
            &proof,
            &mut channel,
            &fri_params,
        );

        // upper layer combiner is trivial in our case
        let upper_layer_combiner = |arr: Vec<(Label, &Fr)>| -> Option<Fr> {
            let res = arr.iter().find(|(l, _)| *l == "starting oracle").map(|(_, c)| (*c).clone());
            res
        };

        let result = FriIop::<Fr, O, T>::verify_proof_queries(
            &proof,
            upper_layer_commitments.clone(),
            natural_indexes.clone(),
            &fri_challenges,
            &fri_params,
            &oracle_params,
            upper_layer_combiner,
        ).expect("Verification must be successful");

        assert_eq!(result, true); 

        println!("FRI instance is valid");

        let mut container : Vec<Fr> = Vec::new();
        upper_layer_commitments[0].1.to_stream(&mut container, ());
        
        let intermidiate_commitments = &proof.commitments;
        println!("intermidiate commitments len: {}", intermidiate_commitments.len());
        for c in intermidiate_commitments {
            c.to_stream(&mut container, ());
        }

        proof.final_coefficients.to_stream(&mut container, fri_params.final_degree_plus_one);
        let num_challenges = fri_challenges.len();
        println!("num fri challenges: {}", num_challenges);
        fri_challenges.to_stream(&mut container, num_challenges);

        let temp : Vec<Fr> = natural_indexes.into_iter().map(|idx| {
            let mut repr = <Fr as PrimeField>::Repr::default();
            repr.as_mut()[0] = idx as u64;
            let elem = Fr::from_repr(repr).expect("should convert");
            elem
        }).collect();
        temp.to_stream(&mut container, fri_params.R);

        let coset_size = 1 << fri_params.collapsing_factor;
        let top_level_oracle_size = (fri_params.initial_degree_plus_one.get() * fri_params.lde_factor) / coset_size;
        let top_level_height = crate::common::log2_floor(top_level_oracle_size);
        
        let mut num_of_iters = crate::common::log2_floor(fri_params.initial_degree_plus_one.get() / fri_params.final_degree_plus_one) / fri_params.collapsing_factor as usize;
        // we do not count the very first and the last iterations
        // TODO: investigate, why we have to substract only one (instead of 2)
        num_of_iters -= 1;

        for (top_layer, intermidiate) in proof.upper_layer_queries.into_iter().zip(proof.queries.into_iter()) 
        {
            let top_layer_query = top_layer[0].1.clone();
            top_layer_query.to_stream(&mut container, (coset_size, top_level_height));
            
            let mut cur_height = top_level_height - fri_params.collapsing_factor as usize;
            assert_eq!(intermidiate.len(), num_of_iters as usize);

            for query in intermidiate.into_iter() {
                query.to_stream(&mut container, (coset_size, cur_height as usize));
                cur_height -= fri_params.collapsing_factor as usize;
            }
        }

        let test_circuit = TestCircuit {
            iter: container.into_iter().map(|x| Some(x)),
            sbox: BN256RescueSbox,
            rescue_params: bn256_rescue_params,
            fri_params: fri_params.clone(),
            combiner: TrivialCombiner{},

            _engine_marker : std::marker::PhantomData::<E>,
        };

        let mut cs = TestConstraintSystem::<Bn256>::new();
        test_circuit.synthesize(&mut cs).expect("should synthesize");

        assert!(cs.is_satisfied());

        cs.modify_input(1, "natural_index/num", Fr::one());
        assert!(!cs.is_satisfied());

        println!("Fri verifier cicrcuit for polynomials of degree {}, lde-factor {}, collapsing_factor {} and 
            {} query rounds contains {} constraints", fri_params.initial_degree_plus_one.get(), fri_params.lde_factor, 
            fri_params.collapsing_factor, fri_params.R, cs.num_constraints());
    }
}

   