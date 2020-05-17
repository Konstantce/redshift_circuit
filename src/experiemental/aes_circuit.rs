// here is the implementation of AES circuit based partially on STARK paper

use super::basic_gadgets::*;
use super::binary_field::BinaryField256 as Fr;
use super::cs::*;

use crate::bellman::SynthesisError;
use crate::bellman::pairing::ff::Field;


pub struct RindjaelGadget {
    pub NB, SB, NumRounds,
}


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
   