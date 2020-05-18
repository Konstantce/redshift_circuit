// here is the implementation of AES circuit partially based on STARK paper

use super::basic_gadgets::*;
use super::binary_field::BinaryField128 as Fr;
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
    // offsets used in ShiftRow
    shift_offsets: Vec<usize>,
    // constant elemets of GF(2^8) used in MixColumns
    g0 : Fr,
    g1: Fr,
}


impl RijndaelGadget {

    pub fn new<CS: ConstraintSystem>(cs: &mut CS, Nb: usize, Nk: usize, Nr: usize, shift_offsets: Vec<usize>) -> Self {
        Self {
            Nb, 
            Nk, 
            Nr,
            hash_state: (0..Nb*4).map(|_| AllocatedNum::alloc_random(cs)).collect::<Result<Vec<_>, _>>().unwrap(),
            byte_sub_constants: (0..8).map(|_| rand::thread_rng().gen()).collect(),
            shift_offsets,
            g0: rand::thread_rng().gen(),
            g1: rand::thread_rng().gen(),
        }
    }

    fn ByteSub<CS: ConstraintSystem>(
        &self, cs: &mut CS, state: &mut RijndaelState, subfield_check: bool) -> Result<(), SynthesisError> 
    {
        for elem in state.iter_mut() {

            // if x was initially zero we should left it unchanged, else inverse

            let (zero_flag, elem_inv) = elem.extended_inv_gadget(cs)?;
            let x = AllocatedNum::selector_gadget(cs, &zero_flag, elem, &elem_inv)?;

            // The full SubBytes S-box is defined according to x → M ·x^{−1}+b, 
            // where M \in F_2[8; 8] and b \in F_2[8; 1] are constants
            // Adding the constant b is a simple field addition in GF(2^8),
            // whereas the multiplication by the constant matrix M can be represented using a linear transformation 
            // T : GF(2^8) \to GF(2^8) over F_2 . 
            // In fact any such linear transformation can be represented by a linearized polynomial 
            // [Lidl, Niederreiter, Chaper 3.4]. 
            // Linearized polynomials are polymomials in GF(2^8) of the form:
            // C(x) = \sum c_i x^{2^i}, where i \in (0..8), and c_i - are constants (depending on T)

            let [x1, x2] = x.pow4(cs)?;
            let [x3, x4] = x2.pow4(cs)?;
            let [x5, x6] = x4.pow4(cs)?;
            let [x7, x8] = x6.pow4(cs)?;

            if subfield_check {
                AllocatedNum::check_subfield_gadget(cs, &x, &x8);
            }

            // y0 = c_0 * x + c_1 * x1 + c_2 * x2
            // y1 = y0 + c_3 *x3 + c_4 * x4
            // y2 = y1 + c_5 * x5 + c_6 * x6
            // res = y2 + c_7 * x7

            let cc = self.byte_sub_constants;
            let one = Fr::one();

            let y0 = AllocatedNum::long_linear_combination_gadget(cs, &x, &x1, &x2, &cc[0], &cc[1], &cc[2])?;
            let y1 = AllocatedNum::long_linear_combination_gadget(cs, &y0, &x3, &x4, &one, &cc[3], &cc[4])?;
            let y2 = AllocatedNum::long_linear_combination_gadget(cs, &y1, &x5, &x6, &one, &cc[5], &cc[6])?;
            let y3 = AllocatedNum::linear_combination_gadget(cs, &y2, &x7, &one, &cc[7])?;

            *elem = y3;
        }

        Ok(())
    }

    fn ShiftRow(&self, state: &mut RijndaelState) -> Result<(), SynthesisError>
    {
        // cyclically rotate each row of RinjndaleState matrix
        // it's all about renumeration, so won't give any new constants

        Ok(())
    }

    fn MixColumn<CS: ConstraintSystem>(&self, cs: &mut CS, state: &mut RijndaelState) -> Result<(), SynthesisError> 
    {
        // for each column = [PO, P1, P2, P3]
        // do the following matrix multiplication in place (here [Q0, Q1, Q2, Q3] is the new resulting column)
        // g0, g1 are predefined constants in GF(2^8)
        
        P0[j](t+1) = g0 · P0[j](t) + g1 · P1[j](t) + P2[j](t) + P3[j](t)
P1[j](t+1) = P0[j](t) + g0 · P1[j](t) + g1 · P2[j](t) + P3[j](t)
P2[j](t+1) = P0[j](t) + P1[j](t) + g0 · P2[j](t) + g1 · P3[j](t)
P3[j](t+1) = g1 · P0[j](t) + P1[j](t) + P2[j](t) + g0 · P3[j](t)

    }

    AddRoundKey(State,RoundKey);
    // simle element-wise addition








Key schedule 

    pub fn absord()

    pub fn squeeze()
 

}

