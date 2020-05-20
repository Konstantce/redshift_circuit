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

            // let (zero_flag, elem_inv) = elem.extended_inv_gadget(cs)?;
            // let x = AllocatedNum::selector_gadget(cs, &zero_flag, elem, &elem_inv)?;

            // The full SubBytes S-box is defined according to x → M ·x^{−1}+b, 
            // where M \in F_2[8; 8] and b \in F_2[8; 1] are constants
            // Adding the constant b is a simple field addition in GF(2^8),
            // whereas the multiplication by the constant matrix M can be represented using a linear transformation 
            // T : GF(2^8) \to GF(2^8) over F_2 . 
            // In fact any such linear transformation can be represented by a linearized polynomial 
            // [Lidl, Niederreiter, Chaper 3.4]. 
            // Linearized polynomials are polymomials in GF(2^8) of the form:
            // C(x) = \sum c_i x^{2^i}, where i \in (0..8), and c_i - are constants (depending on T)

            //let [x1, x2] = x.pow4(cs)?;
            //let [x3, x4] = x2.pow4(cs)?;
            //let [x5, x6] = x4.pow4(cs)?;
            //let [x7, x8] = x6.pow4(cs)?;

            // if subfield_check {
            //     AllocatedNum::check_subfield_gadget(cs, &x, &x)?;
            // }

            // y0 = c_0 * x + c_1 * x1 + c_2 * x2
            // y1 = y0 + c_3 *x3 + c_4 * x4
            // y2 = y1 + c_5 * x5 + c_6 * x6
            // res = y2 + c_7 * x7

            let cc = &self.byte_sub_constants;
            let one = E::Fr::one();

            // //let y0 = AllocatedNum::long_linear_combination_gadget(cs, &x, &x1, &x2, &cc[0], &cc[1], &cc[2])?;
            // //let y1 = AllocatedNum::long_linear_combination_gadget(cs, &y0, &x3, &x4, &one, &cc[3], &cc[4])?;
            let y2 = AllocatedNum::long_linear_combination_gadget(cs, &elem, &elem, &elem, &one, &cc[5], &cc[6])?;
            let y3 = AllocatedNum::linear_combination_gadget(cs, &elem, &elem, &one, &cc[7])?;

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

            //let y0 = AllocatedNum::linear_combination_gadget(cs, &P0, &P1, &self.g0, &self.g1)?;
            let Q0 = AllocatedNum::ternary_add(cs, &P0, &P2, &P3)?;

            //let y1 = AllocatedNum::linear_combination_gadget(cs, &P1, &P2, &self.g0, &self.g1)?;
            let Q1 = AllocatedNum::ternary_add(cs, &P1, &P0, &P3)?;

            //let y2 = AllocatedNum::linear_combination_gadget(cs, &P2, &P3, &self.g0, &self.g1)?;
            let Q2 = AllocatedNum::ternary_add(cs, &P2, &P0, &P1)?;

            //let y3 = AllocatedNum::linear_combination_gadget(cs, &P3, &P0, &self.g0, &self.g1)?;
            let Q3 = AllocatedNum::ternary_add(cs, &P3, &P1, &P2)?;

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
        &self, cs: &mut CS, master_key: &AllocatedNum<E>) -> Result<RijndaelState<E>, SynthesisError>
    {
        // we assume that master_ley is given in compressed form: 
        // i.e. it is represented as vector of length NK consisting of GF(2^128) elems
        // we start by decompressing each of them into 16 elements
        // so we demand Nk to be a multiple of 4 for now

        let mut key : RijndaelState<E> = Vec::with_capacity(self.Nb * (self.Nr+1));
        assert_eq!(self.Nk % 4, 0);

        for elem in [&master_key].iter() {
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

                //tmp = AllocatedNum::ternary_add(cs, &tmp, &self.R_con, &key[i - self.Nk])?;
                key.push(tmp);
            }
            else {
                //let col = key[i - 1].add(cs, &key[i - self.Nk])?;
                key.push(key[i-1]);
            }
        }

        Ok(key)
    }

    pub fn absord<CS: ConstraintSystem<E>>(&mut self, cs: &mut CS, elem: AllocatedNum<E>) -> Result<(), SynthesisError> 
    {
        //treat elem as a master key and expand it
        let key = {
            let mut key_shedule_cs = cs.namespace(|| "key shedule");
            self.KeyShedule(&mut key_shedule_cs, &elem)?
        };

        let mut state = self.hash_state.clone();

        // before we done any encryption we need one extra-round of AddRoundKey
        {
            let mut first_round_cs = cs.namespace(|| "round 0");
            self.AddRoundKey(&mut first_round_cs, &mut state, &key, 0)?;
        }

        for round in 1..(self.Nr+1) {
            let mut round_cs = cs.namespace(|| format!("round {}", round));

            self.ColumnDecomposition(&mut round_cs, &mut state)?;
            self.ByteSub(&mut round_cs, &mut state, true)?;
            self.ShiftRow(&mut state)?;

            if round != self.Nr {
                self.MixColumn(&mut round_cs, &mut state)?;
            }
            self.ColumnComposition(&mut round_cs, &mut state)?;

            self.AddRoundKey(&mut round_cs, &mut state, &key, round)?;
        }

        // Davis-Meyer final xor
        let mut davis_meyer_final_cs = cs.namespace(|| "Davis-Meyer final");
        for (x, k) in self.hash_state.iter_mut().zip(state.into_iter()) {
            *x = x.add(&mut davis_meyer_final_cs, &k)?;
        }

        Ok(())
    }

    pub fn squeeze<CS: ConstraintSystem<E>>(
        &self, cs: &mut CS) -> Result<AllocatedNum<E>, SynthesisError>
    {
        let args = [&self.hash_state[0], &self.hash_state[1], &self.hash_state[2], &self.hash_state[3]];
        AllocatedNum::pack_32_t0_128(cs, args, &self.s_128_to_32)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::test_assembly::TestAssembly;


    struct TestCircuit<E: Engine> {
        input: E::Fr,
        expected_output: E::Fr,
        Nb: usize, 
        Nk: usize, 
        Nr: usize, 
        shift_offsets: Vec<usize>,
    }

    impl<E: Engine> BinaryCircuit<E> for TestCircuit<E> {
        fn synthesize<CS: ConstraintSystem<E>>(
            &self,
            cs: &mut CS,
        ) -> Result<(), SynthesisError> 
        {
            let mut aes_gadget = {
                let mut allocation_cs = cs.namespace(|| "var's pre-allocation");
                RijndaelGadget::<E>::new(&mut allocation_cs, self.Nb, self.Nk, self.Nr, self.shift_offsets.clone())
            };

   

            let input = AllocatedNum::alloc(cs, || Ok(self.input))?;
            let expected_output = AllocatedNum::alloc(cs, || Ok(self.expected_output))?;
            
            aes_gadget.absord(cs, input)?;

            let output = aes_gadget.squeeze(cs)?;
            output.equals(cs,  &expected_output)?;
        
            Ok(())
        }
    }

    #[test]
    fn test_AES_128_gadget() {

        let input = rand::thread_rng().gen();
        let expected_output = rand::thread_rng().gen();

        let Nb: usize = 4; 
        let Nk: usize = 4;
        let Nr: usize = 10; 
        let shift_offsets: Vec<usize> = vec![1, 2, 3];

        let test_circuit = TestCircuit::<Engine128> {
            input,
            expected_output,
            Nb,
            Nk,
            Nr,
            shift_offsets,
        };

        let mut cs = TestAssembly::<Engine128>::new();
        test_circuit.synthesize(&mut cs).expect("should synthesize");

        println!("Num constraints: {}", cs.num_gates());
        cs.print_statistics();
    }
}


