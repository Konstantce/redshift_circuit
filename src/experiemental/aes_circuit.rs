// here is the implementation of AES circuit based partially on STARK paper

use super::basic_gadgets::*;
use super::binary_field::BinaryField256 as Fr;
use super::cs::BinaryConstraintSystem as ConstraintSystem;

use crate::bellman::SynthesisError;
use crate::bellman::pairing::ff::Field;
use rand::Rng;

type RijndaelState = Vec<AllocatedNum>;


#[derive(Debug, Clone)]
pub struct RijndaelGadget {
    // block size in 32bits words
    Nb : usize,
    // key size in 32bits words
    Nk: usize,
    // number of rounds
    Nr: usize,
    // initial state for Davis-Meyer transformation
    hash_state: Vec<AllocatedNum>, 
    // coeffs of c_i of linearized polynomial C used in ByteSub
    byte_sub_constants: Vec<Fr>,
}


impl RijndaelGadget {

    pub fn new<CS: ConstraintSystem>(cs: &mut CS, Nb: usize, Nk: usize, Nr: usize) -> Self {
        Self {
            Nb, 
            Nk, 
            Nr,
            hash_state: (0..Nb*4).map(|_| AllocatedNum::alloc_random(cs)).collect::<Result<Vec<_>, _>>().unwrap(),
            byte_sub_constants: (0..8).map(|_| rand::thread_rng().gen()).collect(),
        }
    }

    fn ByteSub<CS: ConstraintSystem>(
        &self, cs: &mut CS, state: &mut RijndaelState, subfield_check: bool) -> Result<(), SynthesisError> {
        for elem in state.iter_mut() {

            let (flag, inv) = elem.extended_inv_gadget()?;

            // The full SubBytes S-box is defined according to x → M ·x^{−1}+b, 
            // where M \in F_2[8; 8] and b \in F_2[8; 1] are constants
            // Adding the constant b is a simple field addition in GF(2^8),
            // whereas the multiplication by the constant matrix M can be represented using a linear transformation 
            // T : GF(2^8) \to GF(2^8) over F_2 . 
            // In fact any such linear transformation can be represented by a linearized polynomial 
            // [Lidl, Niederreiter, Chaper 3.4]. 
            // Linearized polynomials are polymomials in GF(2^8) of the form:
            // C(x) = \sum c_i x^{2^i}, where i \in (0..8), and c_i - are constants (depending on T)

             pub fn pow4<CS>(
        &self,
        cs: &mut CS



ShiftRow(State);

MixColumn(State);

AddRoundKey(State,RoundKey);

Key schedule 

    pub fn absord()

    pub fn squeeze()
 

}

