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
pub struct HiroseGadget<E: Engine> {
    // block size in 32bits words
    Nb : usize,
    // key size in 32bits words
    Nk: usize,
    // number of rounds
    Nr: usize,
    // initial state for Hirose transformation of the form L || R
    hash_state: RijndaelState<E>, 
}


impl<E: Engine> HiroseGadget<E> {

    pub fn new<CS: ConstraintSystem<E>>(cs: &mut CS, Nb: usize, Nk: usize, Nr: usize) -> Self 
    {
        // for now we only correctly handle the following special case
        assert_eq!(Nb * 2, Nk);
        assert_eq!(Nb, 4);

        let hash_state = 
            (0..(Nb* 2)).map(|_| AllocatedNum::<E>::alloc_random(cs)).collect::<Result<Vec<_>, _>>().unwrap();
        Self {
            Nb, Nk, Nr, hash_state
        }
    }

    // in this function we are working with exactly one byte
    pub fn paired_sub_bytes<CS: ConstraintSystem<E>>(
        &mut self, 
        cs: &mut CS, 
        x: &AllocatedNum<E>,
        y: &AllocatedNum<E>,
    ) -> Result<(AllocatedNum<E>, AllocatedNum<E>), SynthesisError> {

        let (x_inv, y_inv) = AllocatedNum::paired_inv_select(cs, x, y)?;
        AllocatedNum::paired_sub_bytes(cs, &x_inv, &y_inv)
    }

    pub fn absord<CS: ConstraintSystem<E>>(
        &mut self, 
        cs: &mut CS, 
        master_key: Vec<AllocatedNum<E>>
    ) -> Result<(), SynthesisError> 
    {
        assert_eq!(master_key.len(), self.Nb);

        let mut take_left_part = true;
    
        let (L_old, R_old) = self.hash_state.split_at(self.Nb);
        let (L_new) = AllocatedNum::hirose_init(cs, &R_old[0], R_old[1], R_old[2], R_old[3])?;
        let mut L = ...;
        let mut state = self.hash_state.clone();
        let mut key = master_key.clone();

    

        {

            // initial key-addition
            let mut init_cs = cs.namespace(|| format!("intial key-addition"));

            let mut modifier = master_key.last().unwrap().clone();
            let mut unpacked_modifier = modifier.decompose(&mut init_cs)?;

            for elem in &mut unpacked_modifier {
                *elem = self.sub_bytes(&mut init_cs, *elem)?;
            }

            modifier = AllocatedNum::compose(
                &unpacked_modifier[0], &unpacked_modifier[1], &unpacked_modifier[2], &unpacked_modifier[3], &mut init_cs
            )?;

            for i in 0..self.Nb {
                let (new_state, new_key) = AllocatedNum::add_update_round_key(&state[i], &key[i], &modifier, &mut init_cs)?;
                state[i] = new_state;
                key[i] = new_key;
                modifier = new_key;
            }
        }
            
        for round in 0..(self.Nr - 1) {
            let mut round_cs = cs.namespace(|| format!("round {}", round));

            for column in &mut state {
                let mut unpacked_column = column.decompose(&mut round_cs)?;

                for elem in &mut unpacked_column  {
                    *elem = self.sub_bytes(&mut round_cs, *elem)?;
                }
                
                *column = AllocatedNum::mix_columns(
                    &unpacked_column[0], &unpacked_column[1], &unpacked_column[2], &unpacked_column[3], &mut round_cs
                )?;
            }

            let mut modifier = key.last().unwrap().clone();
            let mut unpacked_modifier = modifier.decompose(&mut round_cs)?;

            for elem in &mut unpacked_modifier {
                *elem = self.sub_bytes(&mut round_cs, *elem)?;
            }

            modifier = AllocatedNum::compose(
                &unpacked_modifier[0], &unpacked_modifier[1], &unpacked_modifier[2], &unpacked_modifier[3], &mut round_cs
            )?;

            for i in 0..self.Nb {
                let (new_state, new_key) = AllocatedNum::add_update_round_key(&state[i], &key[i], &modifier, &mut round_cs)?;
                state[i] = new_state;
                key[i] = new_key;
                modifier = new_key;
            } 
        }

        // final round is a bit different
        {
            let mut final_round_cs = cs.namespace(|| format!("final_round"));

            for column in &mut state {
                let mut unpacked_column = column.decompose(&mut final_round_cs)?;

                for elem in &mut unpacked_column  {
                    *elem = self.sub_bytes(&mut final_round_cs, *elem)?;
                }

                *column = AllocatedNum::compose(
                    &unpacked_column[0], &unpacked_column[1], &unpacked_column[2], &unpacked_column[3], &mut final_round_cs
                )?;
            }

            for i in 0..self.Nb {
                self.hash_state[i] = AllocatedNum::davis_meyer_add_round_key(
                    &self.hash_state[i], &key[i], &state[i], &mut final_round_cs
                )?;
            }
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

            let mut input = vec![];
            for _ in 0..self.Nk {
                input.push(AllocatedNum::alloc(cs, || Ok(self.input))?);
            }

            let expected_output = AllocatedNum::alloc(cs, || Ok(self.expected_output))?;
            
            aes_gadget.absord(cs, input)?;

            let output = aes_gadget.squeeze(cs)?;
            output.equals(cs,  &expected_output)?;
        
            Ok(())
        }
    }

    #[test]
    fn test_DAVIS_MEYER_gadget() {

        let input = rand::thread_rng().gen();
        let expected_output = rand::thread_rng().gen();

        let Nb: usize = 5; 
        let Nk: usize = 5;
        let Nr: usize = 11; 
        let shift_offsets: Vec<usize> = vec![1, 2, 3];

        let test_circuit = TestCircuit::<Engine128> {
            input,
            expected_output,
            Nb,
            Nk,
            Nr,
            shift_offsets,
        };

        let mut cs = TestAssembly::<Engine128>::new(4);
        test_circuit.synthesize(&mut cs).expect("should synthesize");

        println!("Num constraints: {}", cs.num_gates());
        cs.print_statistics();
    }
}


