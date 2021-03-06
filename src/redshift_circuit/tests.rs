#[cfg(test)]
mod test {
    use bellman::redshift::redshift::tests::*;
    use bellman::redshift::redshift::serialization::*;
    
    use redshift_circuit::circuit::*;
    use bellman::redshift::IOP::oracle::coset_combining_rescue_tree::*;
    use bellman::redshift::IOP::channel::rescue_channel::*;
    use bellman::redshift::IOP::hashes::rescue::bn256_rescue_params::BN256Rescue;
    use bellman::redshift::IOP::hashes::rescue::RescueParams;
    use bellman::pairing::bn256::Fr as Fr;

    use bellman::pairing::ff::{Field, PrimeField};
    use bellman::redshift::IOP::FRI::coset_combining_fri::FriParams;
    use common::log2_floor;
    use oracles::rescue_merklee_proof::*;
    use redshift_circuit::circuit::*;
    use crate::tester::naming_oblivious_cs::NamingObliviousConstraintSystem as TestConstraintSystem;
    use bellman::Circuit;
    use hashes::rescue::bn256_rescue_sbox::BN256RescueSbox;
    use channel::rescue_channel::RescueChannelGadget;
    use hashes::rescue::RESCUE_PERMUTATIONS_COUNT;

    use std::time::{Duration, Instant};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use std::iter;
    
    #[test]
    fn redshift_recursion_for_fibbonacci() 
    {
        type E = bellman::pairing::bn256::Bn256;
        type O<'a> = FriSpecificRescueTree<'a, Fr, BN256Rescue>;
        type T<'a> = RescueChannel<'a, Fr, BN256Rescue>;

        // prepare parameters
        // TODO: log2 and multicore nt_fft fail on small number of steps (<= 10),
        // the reason of failure should be additionally investigated
        let a = Fr::one();
        let b = Fr::one();
        let num_steps = 10000;

        let fri_params = FriParams {
            initial_degree_plus_one: std::cell::Cell::new(0),
            lde_factor: 16,
            R: 20,
            collapsing_factor: 2,
            final_degree_plus_one: std::cell::Cell::new(1),
        };

        let bn256_rescue_params = BN256Rescue::default();

        let oracle_params = RescueTreeParams {
            values_per_leaf: 1 << fri_params.collapsing_factor,
            rescue_params: &bn256_rescue_params,
            _marker: std::marker::PhantomData::<Fr>,
        };

        let channel_params = RescueChannelParams {
            rescue_params: &bn256_rescue_params,
            _marker: std::marker::PhantomData::<Fr>,
        };

        let res = redshift_template::<E, O, T>(
            a,
            b,
            num_steps,
            &fri_params,
            &oracle_params,
            &channel_params,
        ).expect("should pass");

        let is_valid = res.0;
        let setup_precomp = res.1;
        let proof = res.2;

        assert_eq!(is_valid, true);

        println!("REDSHIFT PROOF DONE");

        let mut container = Vec::<Fr>::new();

        let coset_size = 1 << fri_params.collapsing_factor;
        let top_level_oracle_size = (fri_params.initial_degree_plus_one.get() * fri_params.lde_factor) / coset_size;
        let top_leve_height = log2_floor(top_level_oracle_size);

        setup_precomp.to_stream(&mut container, top_leve_height);
        proof.to_stream(&mut container, fri_params.clone());

        let rescue_params = BN256Rescue::default();
        let oracle_params =  RescueTreeGadgetParams {
            num_elems_per_leaf: coset_size,
            rescue_params: &rescue_params,
            _marker: std::marker::PhantomData::<Fr>,
        };

        let iter = container.into_iter().map(|x| Some(x));

        type OG<'a> = RescueTreeGadget<'a, E, BN256Rescue, BN256RescueSbox>;
        type TG<'a> = RescueChannelGadget<'a, E, BN256Rescue, BN256RescueSbox>;

        let output = fibbonacci(&a, &b, num_steps);

        let redshift_recursion_circuit = RedShiftVerifierCircuit::<E, OG, TG, _>::new(
            &rescue_params,
            oracle_params, 
            fri_params, 
            iter, 
            vec![a, b, output],
        );

        // verify that circuit is satifiable
        let mut test_assembly = TestConstraintSystem::new();
        let now = Instant::now();
        redshift_recursion_circuit.synthesize(&mut test_assembly).expect("should synthesize");
        println!("CIRCUIT synthesize took {}s", now.elapsed().as_secs());
        println!("NUM OF RESCUE PERMUTATIONS in CIRCUIT: {}", RESCUE_PERMUTATIONS_COUNT.load(Ordering::SeqCst));

        if !test_assembly.is_satisfied() 
        {
            println!("UNSATISFIED AT: {}", test_assembly.which_is_unsatisfied().unwrap());
        }
        assert!(test_assembly.is_satisfied(), "some constraints are not satisfied");

        println!("Num of constraints: {}", test_assembly.num_constraints());
    }

    #[test]
    fn redshift_recursion_estimator() 
    {
        type E = bellman::pairing::bn256::Bn256;
        type O<'a> = FriSpecificRescueTree<'a, Fr, BN256Rescue>;
        type T<'a> = RescueChannel<'a, Fr, BN256Rescue>;

        // prepare parameters
        // TODO: log2 and multicore nt_fft fail on small number of steps (<= 10),
        // the reason of failure should be additionally investigated
        let a = Fr::one();
        let b = Fr::one();
        let num_steps = 268435456 / 16;

        let fri_params = FriParams {
            initial_degree_plus_one: std::cell::Cell::new(num_steps),
            lde_factor: 16,
            R: 20,
            collapsing_factor: 2,
            final_degree_plus_one: std::cell::Cell::new(1),
        };
        fri_params.recompute_final_degree(true);

        let bn256_rescue_params = BN256Rescue::default();

        let oracle_params = RescueTreeParams {
            values_per_leaf: 1 << fri_params.collapsing_factor,
            rescue_params: &bn256_rescue_params,
            _marker: std::marker::PhantomData::<Fr>,
        };

        let channel_params = RescueChannelParams {
            rescue_params: &bn256_rescue_params,
            _marker: std::marker::PhantomData::<Fr>,
        };

        let container  = iter::repeat(None);

        let coset_size = 1 << fri_params.collapsing_factor;
        let rescue_params = BN256Rescue::default();
        let oracle_params =  RescueTreeGadgetParams {
            num_elems_per_leaf: coset_size,
            rescue_params: &rescue_params,
            _marker: std::marker::PhantomData::<Fr>,
        };

        type OG<'a> = RescueTreeGadget<'a, E, BN256Rescue, BN256RescueSbox>;
        type TG<'a> = RescueChannelGadget<'a, E, BN256Rescue, BN256RescueSbox>;

        let output = fibbonacci(&a, &b, num_steps);

        let redshift_recursion_circuit = RedShiftVerifierCircuit::<E, OG, TG, _>::new(
            &rescue_params,
            oracle_params, 
            fri_params, 
            container, 
            vec![a, b, output],
        );

        // verify that circuit is satifiable
        let mut test_assembly = TestConstraintSystem::new();
        let now = Instant::now();
        redshift_recursion_circuit.synthesize(&mut test_assembly).expect("should synthesize");
        println!("CIRCUIT synthesize took {}s", now.elapsed().as_secs());
        println!("Num of constraints: {}", test_assembly.num_constraints());
        println!("NUM OF RESCUE PERMUTATIONS in CIRCUIT: {}", RESCUE_PERMUTATIONS_COUNT.load(Ordering::SeqCst));

        if !test_assembly.is_satisfied() 
        {
            println!("UNSATISFIED AT: {}", test_assembly.which_is_unsatisfied().unwrap());
        }
        assert!(test_assembly.is_satisfied(), "some constraints are not satisfied");

        println!("Num of constraints: {}", test_assembly.num_constraints());
    }

}
      

    