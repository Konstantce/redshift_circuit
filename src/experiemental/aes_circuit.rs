#[allow(non_camel_case_types)]
// here is the implementation of AES circuit partially based on STARK paper

use super::basic_gadgets::*;
use super::binary_field::BinaryField;
use super::cs::BinaryConstraintSystem as ConstraintSystem;
use super::cs::*;

use crate::bellman::SynthesisError;
use crate::bellman::pairing::ff::Field;
use rand::Rng;

type RijndaelState<E: Engine> = Vec<AllocatedNum<E>>;


#[derive(Debug, Clone)]
pub struct RijndaelGadget<E: Engine> {
    // block size in 32bits words
    Nb : usize,
    // key size in 32bits words
    Nk: usize,
    // number of rounds
    Nr: usize,
    // initial state for Davis-Meyer transformation
    hash_state: RijndaelState<E>, 
    // coeffs of c_i of linearized polynomial C used in ByteSub
    byte_sub_constants: Vec<E::Fr>,
    // offsets used in ShiftRow
    shift_offsets: Vec<usize>,
    // constant elemets of GF(2^8) used in MixColumns
    g0 : E::Fr,
    g1: E::Fr,
    // constants used in subfields decomposition
    s_128_to_8 : E::Fr,
    s_128_to_32: E::Fr,
    s_32_to_8: E::Fr,
    // constant used in key derivation
    // TODO: actually it is a constant, but my cs is not perfect yet
    // and doesn't allow to use constant in the place where it is used
    R_con: AllocatedNum<E>,
}


impl<E: Engine> RijndaelGadget<E> {

    pub fn new<CS: ConstraintSystem<E>>(cs: &mut CS, Nb: usize, Nk: usize, Nr: usize, shift_offsets: Vec<usize>) -> Self {
        Self {
            Nb, 
            Nk, 
            Nr,
            hash_state: (0..Nb).map(|_| AllocatedNum::<E>::alloc_random(cs)).collect::<Result<Vec<_>, _>>().unwrap(),
            byte_sub_constants: (0..8).map(|_| rand::thread_rng().gen()).collect(),
            shift_offsets,
            g0: rand::thread_rng().gen(),
            g1: rand::thread_rng().gen(),
            s_128_to_8 : rand::thread_rng().gen(),
            s_128_to_32: rand::thread_rng().gen(),
            s_32_to_8: rand::thread_rng().gen(),
            R_con: AllocatedNum::alloc_random(cs).unwrap(),
        }
    }

    fn ColumnDecomposition<CS: ConstraintSystem<E>>(
        &self, cs: &mut CS, state: &mut RijndaelState<E>) -> Result<(), SynthesisError> 
    {
        let mut decomposed_state = Vec::with_capacity(state.len() * 4);

        for column in state.into_iter() {
            let tmp = column.unpack_32_into_8(cs, &self.s_32_to_8)?;
            decomposed_state.extend(tmp.into_iter());
        }

        *state = decomposed_state;
        Ok(())
    }

    fn ColumnComposition<CS: ConstraintSystem<E>>(
        &self, cs: &mut CS, state: &mut RijndaelState<E>) -> Result<(), SynthesisError> 
    {
        let mut composed_state = Vec::with_capacity(state.len() / 4);

        for column in state.chunks(4) {
            let args = [&column[0], &column[1], &column[2], &column[3]];
            let tmp = AllocatedNum::pack_8_t0_32(cs, args, &self.s_32_to_8)?;
            
            composed_state.push(tmp);
        }

        *state = composed_state;
        Ok(())
    }

    fn ByteSub<CS: ConstraintSystem<E>>(
        &self, cs: &mut CS, state: &mut RijndaelState<E>, subfield_check: bool) -> Result<(), SynthesisError> 
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
                AllocatedNum::check_subfield_gadget(cs, &x, &x8)?;
            }

            // y0 = c_0 * x + c_1 * x1 + c_2 * x2
            // y1 = y0 + c_3 *x3 + c_4 * x4
            // y2 = y1 + c_5 * x5 + c_6 * x6
            // res = y2 + c_7 * x7

            let cc = &self.byte_sub_constants;
            let one = E::Fr::one();

            let y0 = AllocatedNum::long_linear_combination_gadget(cs, &x, &x1, &x2, &cc[0], &cc[1], &cc[2])?;
            let y1 = AllocatedNum::long_linear_combination_gadget(cs, &y0, &x3, &x4, &one, &cc[3], &cc[4])?;
            let y2 = AllocatedNum::long_linear_combination_gadget(cs, &y1, &x5, &x6, &one, &cc[5], &cc[6])?;
            let y3 = AllocatedNum::linear_combination_gadget(cs, &y2, &x7, &one, &cc[7])?;

            *elem = y3;
        }

        Ok(())
    }

    fn ShiftRow(&self, state: &mut RijndaelState<E>) -> Result<(), SynthesisError>
    {
        // cyclically rotate each row of RinjndaleState matrix
        // it's all about renumeration, so won't give any new constants

        Ok(())
    }

    fn MixColumn<CS: ConstraintSystem<E>>(&self, cs: &mut CS, state: &mut RijndaelState<E>) -> Result<(), SynthesisError> 
    {
        // for each column = [PO, P1, P2, P3]
        // do the following matrix multiplication in place (here [Q0, Q1, Q2, Q3] is the new resulting column)
        // g0, g1 are predefined constants in GF(2^8)        
        // Q0 = g0 · P0 + g1 · P1 + P2 + P3
        // Q1 = P0 + g0 · P1 + g1 · P2 + P3
        // Q2 = P0 + P1 + g0 · P2 + g1 · P3
        // Q3 = g1 · P0 + P1 + P2 + g0 · P3

        for column in state.chunks_mut(4) {
            let P0 = column[0];
            let P1 = column[1];
            let P2 = column[2];
            let P3 = column[3];

            let y0 = AllocatedNum::linear_combination_gadget(cs, &P0, &P1, &self.g0, &self.g1)?;
            let Q0 = AllocatedNum::ternary_add(cs, &y0, &P2, &P3)?;

            let y1 = AllocatedNum::linear_combination_gadget(cs, &P1, &P2, &self.g0, &self.g1)?;
            let Q1 = AllocatedNum::ternary_add(cs, &y1, &P0, &P3)?;

            let y2 = AllocatedNum::linear_combination_gadget(cs, &P2, &P3, &self.g0, &self.g1)?;
            let Q2 = AllocatedNum::ternary_add(cs, &y2, &P0, &P1)?;

            let y3 = AllocatedNum::linear_combination_gadget(cs, &P3, &P0, &self.g0, &self.g1)?;
            let Q3 = AllocatedNum::ternary_add(cs, &y3, &P1, &P2)?;

            column[0] = Q0;
            column[1] = Q1;
            column[2] = Q2;
            column[3] = Q3;
        }

        Ok(())

    }

    fn AddRoundKey<CS: ConstraintSystem<E>>(
        &self, cs: &mut CS, state: &mut RijndaelState<E>, key: &RijndaelState<E>, round: usize) -> Result<(), SynthesisError>
    {
        // simle element-wise addition
        let start = round * self.Nb;
        let end = (round+1) * self.Nb;
        let round_key = &key[start..end];

        assert_eq!(state.len(), round_key.len());
        for (x, k) in state.iter_mut().zip(round_key) {
            *x = x.add(cs, k)?;
        }

        Ok(())
    }

    fn KeyShedule<CS: ConstraintSystem<E>>(
        &self, cs: &mut CS, master_key: &mut RijndaelState<E>) -> Result<RijndaelState<E>, SynthesisError>
    {
        // we assume that master_ley is given in compressed form: 
        // i.e. it is represented as vector of length NK consisting of GF(2^128) elems
        // we start by decompressing each of them into 16 elements
        // so we demand Nk to be a multiple of 4 for now

        let mut key : RijndaelState<E> = Vec::with_capacity(self.Nb * (self.Nr+1));
        assert_eq!(self.Nr % 4, 0);

        for elem in master_key.iter() {
            let tmp = elem.unpack_128_into_32(cs, &self.s_128_to_32)?;
            key.extend(tmp.into_iter());
        }

        for i in self.Nk..self.Nb * (self.Nr + 1) {
            if (i % self.Nk == 0) || ((self.Nk >= 6) & (i % self.Nk == 4)) {
                
                let mut col = key[i-1].unpack_128_into_32(cs, &self.s_32_to_8)?.to_vec();
                col.rotate_left(1);
                self.ByteSub(cs, &mut col, true);

                let args = [&col[0], &col[1], &col[2], &col[3]];
                let mut tmp = AllocatedNum::pack_8_t0_32(cs, args, &self.s_32_to_8)?;

                tmp = AllocatedNum::ternary_add(cs, &tmp, &self.R_con, &key[i - self.Nk])?;
                key.push(tmp);
            }
            else {
                let col = key[i - 1].add(cs, &key[i - self.Nk])?;
                key.push(col);
            }
        }

        Ok(key)
    }

    pub fn absord<CS: ConstraintSystem<E>>(&self, cs: &mut CS, elem: AllocatedNum<E>) -> Result<(), SynthesisError> 
    {

        Ok(())
    }

    pub fn squeeze<CS: ConstraintSystem<E>>(
        &self, cs: &mut CS, elem: AllocatedNum<E>) -> Result<AllocatedNum<E>, SynthesisError>
    {

    }
}


