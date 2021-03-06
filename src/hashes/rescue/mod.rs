#![allow(non_snake_case)]

use bellman::redshift::IOP::hashes::rescue::{RescueParams};

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

use common::num::*;

pub mod bn256_rescue_sbox;

use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) static RESCUE_PERMUTATIONS_COUNT: AtomicUsize = AtomicUsize::new(0);

pub trait RescueSbox<E: Engine>: Clone + Copy {

    fn new() -> Self;

    fn rescue_alpha<CS : ConstraintSystem<E>>(elem: &Num<E>, cs: CS) -> Result<Num<E>, SynthesisError>;

    fn rescue_inalpha<CS : ConstraintSystem<E>>(elem: &Num<E>, cs: CS) -> Result<Num<E>, SynthesisError>;
}


fn mds<E: Engine, Params: RescueParams<E::Fr>>(
    in_state: &[Num<E>],
    params: &Params,
) -> Vec<Num<E>> {
    let mut out_state = vec![];
    let mds_matrix = params.get_mds_matrix();
    let RESCUE_M = params.t();
    
    for i in 0..RESCUE_M {
        let mut res = Num::zero();
        for j in 0..RESCUE_M {
            let mut temp = in_state[j].clone();
            temp.scale(mds_matrix[i][j]);
            res.add_assign(&temp);
        }
        out_state.push(res);
    }
    out_state
}


fn rescue_f<E: Engine, CS: ConstraintSystem<E>, Params: RescueParams<E::Fr>, SBOX: RescueSbox<E>>(
    cs: &mut CS,
    state: &mut [Num<E>],
    params: &Params,
) -> Result<(), SynthesisError> {

    let RESCUE_M = params.t();
    let RESCUE_ROUNDS = params.get_num_rescue_rounds();
    let constants = params.get_constants();
   
    for i in 0..RESCUE_M {
        state[i].add_assign(&Num::from_constant(&constants[0][i], &cs));
    }

    for r in 0..2 * RESCUE_ROUNDS {

        for entry in state.iter_mut() {
            if r % 2 == 0 {
                *entry = SBOX::rescue_inalpha(&entry, cs.namespace(|| "sbox inalpha"))?;
            }
            else {
                *entry = SBOX::rescue_alpha(&entry, cs.namespace(|| "sbox alpha"))?;
            }
        }

        for (input, output) in  mds::<E, Params>(state, params).into_iter().zip(state.iter_mut()) {
            *output = input;
        }
        for i in 0..RESCUE_M {
            state[i].add_assign(&Num::from_constant(&(constants[r + 1][i]), &cs));
        }
    }

    Ok(())
}

fn pad<E: Engine, CS: ConstraintSystem<E>, Params: RescueParams<E::Fr>>(
    input: &mut Vec<Num<E>>,
    cs: &mut CS,
    params: &Params,
) {

    let SPONGE_RATE = params.r();
    let magic_constant = params.padding_constant();
    let range = SPONGE_RATE - input.len();

    // apply necessary padding
    input.extend((0..range).map(|_| Num::from_constant(magic_constant, &cs))); 
}

fn rescue_duplex<E: Engine, CS: ConstraintSystem<E>, Params: RescueParams<E::Fr>, SBOX: RescueSbox<E>>(
    state: &mut Vec<Num<E>>,
    input: &mut Vec<Num<E>>,
    mut cs: CS,
    params: &Params,
) -> Result< Vec<Option<Num<E>>>, SynthesisError> {

    let SPONGE_RATE = params.r();
    let OUTPUT_RATE = params.c();
    pad(input, &mut cs, params);

    for i in 0..SPONGE_RATE {
        state[i].add_assign(&input[i]);
    }

    rescue_f::<E, CS, Params, SBOX>(&mut cs, state, params)?;

    let mut output = Vec::with_capacity(OUTPUT_RATE);
    for i in 0..OUTPUT_RATE {
        output.push(Some(state[i].clone()));
    }

    Ok(output)
}

enum SpongeState<E: Engine> {
    Absorbing(Vec<Num<E>>),
    Squeezing(Vec<Option<Num<E>>>),
}

impl<E: Engine> SpongeState<E> {
    fn absorb(val: Num<E>) -> Self {
        SpongeState::Absorbing(vec![val])
    }

    fn default() -> Self {
        SpongeState::Absorbing(vec![])
    }
}


pub struct RescueGadget<E: Engine, RP: RescueParams<E::Fr>, SBOX: RescueSbox<E>> {
    sponge: SpongeState<E>,
    state: Vec<Num<E>>,
    _params_marker: std::marker::PhantomData<RP>,
    _sbox_marker: std::marker::PhantomData<SBOX>,
}


impl<E: Engine, RP: RescueParams<E::Fr>, SBOX: RescueSbox<E>> RescueGadget<E, RP, SBOX> {

    pub fn new(params: &RP) -> Self {
        
        let RESCUE_M = params.t();
        let state = (0..RESCUE_M).map(|_| Num::zero()).collect();

        RescueGadget {
            sponge: SpongeState::Absorbing(vec![]),
            state,
            _params_marker: std::marker::PhantomData::<RP>,
            _sbox_marker: std::marker::PhantomData::<SBOX>,
        }
    }
   
    pub fn absorb<CS: ConstraintSystem<E>>(&mut self, val: AllocatedNum<E>, mut cs: CS, params: &RP) -> Result<(), SynthesisError> {
        let SPONGE_STATE = params.r();
        let val = val.into();
        match self.sponge {
            SpongeState::Absorbing(ref mut input) => {
                if input.len() < SPONGE_STATE {
                    input.push(val);
                    return Ok(());
                }

                // We've already absorbed as many elements as we can
                RESCUE_PERMUTATIONS_COUNT.fetch_add(1, Ordering::SeqCst);
                rescue_duplex::<E, _, RP, SBOX>(&mut self.state, input, cs.namespace(|| "rescue duplex"), params)?;
                self.sponge = SpongeState::absorb(val);
            }
            SpongeState::Squeezing(_) => {
                // Drop the remaining output elements
                self.sponge = SpongeState::absorb(val);
            }
        }

        Ok(())
    }

    pub fn squeeze<CS: ConstraintSystem<E>>(&mut self, mut cs: CS, params: &RP) -> Result<AllocatedNum<E>, SynthesisError> {
        loop {
            match self.sponge {
                SpongeState::Absorbing(ref mut input) => {
                    RESCUE_PERMUTATIONS_COUNT.fetch_add(1, Ordering::SeqCst);
                    self.sponge = SpongeState::Squeezing(rescue_duplex::<E, _, RP, SBOX>(
                        &mut self.state,
                        input,
                        cs.namespace(|| "rescue duplex"),
                        params,
                    )?);
                }
                SpongeState::Squeezing(ref mut output) => {
                    for entry in output.iter_mut() {
                        if let Some(mut e) = entry.take() {
                            let e = e.simplify(cs.namespace(|| "simplification"))?;
                            return Ok(e)
                        }
                    }
                    // We've already squeezed out all available elements
                    //unreachable!("Sponge number is too small");
                    self.sponge = SpongeState::Absorbing(vec![]);
                }
            }
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use bellman::Circuit;
    use bellman::redshift::IOP::hashes::rescue::{Rescue, RescueParams};
    use bellman::redshift::IOP::hashes::rescue::bn256_rescue_params::BN256Rescue;

    use bellman::pairing::bn256::Fr as Fr;
    use bellman::pairing::bn256::Bn256;

    use super::bn256_rescue_sbox::BN256RescueSbox;
    use crate::tester::naming_oblivious_cs::NamingObliviousConstraintSystem as TestConstraintSystem;

    use bellman::redshift::redshift::adaptor::*;
    use bellman::redshift::redshift::test_assembly::*;
    use bellman::redshift::redshift::cs::Circuit as PlonkCircuit;

    #[test]
    fn test_rescue_gadget() {
        struct TestCircuit<E: Engine, RP: RescueParams<E::Fr>, SBOX: RescueSbox<E>> {
            params: RP,
            sbox: SBOX,
            inputs: Vec<E::Fr>,
            expected_outputs: Vec<E::Fr>,
        }

        impl<E: Engine, RP: RescueParams<E::Fr>, SBOX: RescueSbox<E>> Circuit<E> for TestCircuit<E, RP, SBOX> {
            fn synthesize<CS: ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {

                let mut g = RescueGadget::<E, RP, SBOX>::new(&self.params);

                assert!(self.expected_outputs.len() <= self.params.c());

                for elem in self.inputs.into_iter() {
                    let val = AllocatedNum::alloc(cs.namespace(|| "rescue test input"), || Ok(elem))?;
                    g.absorb(val.into(),  cs.namespace(|| "absorb input"), &self.params)?;
                }

                for elem in self.expected_outputs.into_iter() {
                    let val = AllocatedNum::alloc_input(cs.namespace(|| "rescue output"), || Ok(elem))?;
                    let s = g.squeeze(cs.namespace(|| "squeeze s"), &self.params)?;
                    cs.enforce(
                        || "check output", 
                        |lc| lc + s.get_variable(), 
                        |lc| lc + CS::one(),
                        |lc| lc + val.get_variable(),
                    );
                }

                Ok(())
            }
        }

        {
            // test one iteration of Rescue hash
            println!("RESCUE HASH SINGLE ITERAION");

            // construct 3 and 9 as inputs
            let mut a = Fr::one();
            a.double();
            a.add_assign(&Fr::one());

            let mut b = a.clone();
            b.double();


            let inputs = vec![a, b]; 

            let bn256_rescue_params = BN256Rescue::default();
            let mut r = Rescue::new(&bn256_rescue_params);
            r.absorb(a, &bn256_rescue_params);
            r.absorb(b, &bn256_rescue_params);

            let expected_s = r.squeeze(&bn256_rescue_params);

            let test_circuit = TestCircuit::<Bn256, BN256Rescue, BN256RescueSbox> {
                params: bn256_rescue_params,
                sbox: BN256RescueSbox{},
                inputs: inputs.clone(),
                expected_outputs: vec![expected_s],
            };

            let mut cs = TestConstraintSystem::<Bn256>::new();
            test_circuit.synthesize(&mut cs).expect("should synthesize");

            if !cs.is_satisfied()
            {
                println!("UNSATISFIED at: {}", cs.which_is_unsatisfied().unwrap());
            }
            assert!(cs.is_satisfied());

            cs.modify_input(1, "rescue output/num", Fr::one());

            assert!(!cs.is_satisfied());
            println!("Rescue 2->1 with 22 rounds requires {} R1CS constraints", cs.num_constraints());

            let mut transpiler = Transpiler::<Bn256>::new();

            let test_circuit = TestCircuit::<Bn256, BN256Rescue, BN256RescueSbox> {
                params: BN256Rescue::default(),
                sbox: BN256RescueSbox{},
                inputs: inputs.clone(),
                expected_outputs: vec![expected_s],
            };

            test_circuit.synthesize(&mut transpiler).expect("sythesize into traspilation must succeed");

            let test_circuit = TestCircuit::<Bn256, BN256Rescue, BN256RescueSbox> {
                params: BN256Rescue::default(),
                sbox: BN256RescueSbox{},
                inputs: inputs.clone(),
                expected_outputs: vec![expected_s],
            };

            let hints = transpiler.hints;
            let adapted_curcuit = AdaptorCircuit::new(test_circuit, &hints);

            let mut assembly = TestAssembly::<Bn256>::new();
            adapted_curcuit.synthesize(&mut assembly).expect("sythesize of transpiled into CS must succeed");

            assert!(assembly.is_satisfied(false));
            let num_gates = assembly.num_gates();
            println!("Transpiled into {} gates", num_gates);
        }

        {
            // we run this second test for the following purpose: 
            // in previous test we start with the empty state, absord a couple of elements and squeeze an element
            // here wa want to analyze, how would the number of constraints change if we start with "constrainted" state
            // for this we measure the number of constraints in double run of Resuce
            // if there is no dependence between the "constaintification" of state and number of resulting constraints
            // then the number of constraints should be simply doubled

             // test one iteration of Rescue hash
            println!("RESCUE HASH 2 ITERAIONS");

            // construct 1, 3, 9, 81 as inputs
            let a = Fr::one();

            let mut b = a.clone();
            b.double();
            b.add_assign(&Fr::one());

            let mut c = b.clone();
            c.double();

            let mut d = c.clone();
            d.square();

            let inputs = vec![a, b, c, d]; 

            let bn256_rescue_params = BN256Rescue::default();
            let mut r = Rescue::new(&bn256_rescue_params);
            r.absorb(a, &bn256_rescue_params);
            r.absorb(b, &bn256_rescue_params);
            r.absorb(c, &bn256_rescue_params);
            r.absorb(d, &bn256_rescue_params);

            let expected_s = r.squeeze(&bn256_rescue_params);

            let test_circuit = TestCircuit::<Bn256, BN256Rescue, BN256RescueSbox> {
                params: bn256_rescue_params,
                sbox: BN256RescueSbox{},
                inputs: inputs,
                expected_outputs: vec![expected_s],
            };

            let mut cs = TestConstraintSystem::<Bn256>::new();
            test_circuit.synthesize(&mut cs).expect("should synthesize");

            if !cs.is_satisfied()
            {
                println!("UNSATISFIED at: {}", cs.which_is_unsatisfied().unwrap());
            }
            assert!(cs.is_satisfied());

            cs.modify_input(1, "rescue output/num", Fr::one());

            assert!(!cs.is_satisfied());
            println!("Rescue 2->1 with 22 rounds requires {} R1CS constraints", cs.num_constraints());
        }
    }    
}