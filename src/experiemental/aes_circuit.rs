// here is the implementation of AES circuit based partially on STARK paper

use super::basic_gadgets::*;
use super::binary_field::BinaryField256 as Fr;
use super::cs::BinaryConstraintSystem as ConstraintSystem;

use crate::bellman::SynthesisError;
use crate::bellman::pairing::ff::Field;


#[derive(Debug, Clone, Copy)]
pub struct RijndaelGadget {
    // block size in 32bits words
    Nb : usize,
    // key size in 32bits words
    Nk: usize,
    // number of rounds
    Nr: usize,
    // initial state for Davis-Meyer transformation
    state: Vec<AllocatedNum>, 
}


impl RijndaelGadget {

    pub fn new<CS: ConstraintSystem>(cs: &mut CS, Nb: usize, Nk: usize, Nr: usize) -> Self {
        Self {
            Nb, 
            Nk, 
            Nr,
            (0..Nb*4).map(|_| AllocatedNum::alloc_random(cs)).collect::<_, SynthesisError>().unwrap(),
        }
    }

    fn sub_bytes()
}

