#[allow(non_camel_case_types)]
// here is the implementation of AES circuit partially based on STARK paper

use super::basic_gadgets::*;
use super::binary_field::BinaryField;
use super::cs::BinaryConstraintSystem as ConstraintSystem;
use super::cs::*;

use crate::bellman::SynthesisError;
use crate::bellman::pairing::ff::Field;
use rand::Rng;
use std::iter::FromIterator;

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
    
        let (L_old, R_old) = self.hash_state.split_at(self.Nb);
        let L_new = AllocatedNum::hirose_init(cs, &R_old[0], &R_old[1], &R_old[2], &R_old[3])?;
        let R_new = [R_old[0], R_old[1], R_old[2], R_old[3]];

        let mut l_hash_state = L_new.clone();
        let mut r_hash_state = R_new.clone();
        
        let mut l_key = [L_old[0], L_old[1], L_old[2], L_old[3]];
        let mut r_key = [master_key[0], master_key[1], master_key[2], master_key[3]];

        {
            // initial key-addition
            let mut init_cs = cs.namespace(|| format!("intial key-addition"));

            let mut modifier = r_key.last().unwrap().clone();
            let mut unpacked_modifier = modifier.decompose(&mut init_cs)?;

            for chunk in unpacked_modifier.chunks_mut(2) {
                let res = self.paired_sub_bytes(&mut init_cs, &chunk[0], &chunk[1])?;
                chunk[0] = res.0;
                chunk[1] = res.1;
            }

            modifier = AllocatedNum::compose(
                &unpacked_modifier[0], &unpacked_modifier[1], &unpacked_modifier[2], &unpacked_modifier[3], &mut init_cs
            )?;

            for i in 0..self.Nb {
                let [new_l_state, new_r_state, new_key] = AllocatedNum::wide_round_key_add_update(
                    &mut init_cs, &l_hash_state[i], &r_hash_state[i], &l_key[i], &modifier)?;
                
                l_hash_state[i] = new_l_state;
                r_hash_state[i] = new_r_state;
                l_key[i] = new_key;
                modifier = new_key;
            }
        }

        let mut take_left_part = false;
            
        for round in 0..(self.Nr - 1) {
            let mut round_cs = cs.namespace(|| format!("round {}", round));

            for column_chunk in l_hash_state.chunks_mut(2).chain(r_hash_state.chunks_mut(2)) {

                let res = AllocatedNum::paired_decompose(&mut round_cs, &column_chunk[0], &column_chunk[1])?;
                let mut x_column = res.0;
                let mut y_column = res.1;
                
                for (x, y) in x_column.iter_mut().zip(y_column.iter_mut()) {
                    let res = self.paired_sub_bytes(&mut round_cs, &x, &y)?;
                    *x = res.0;
                    *y = res.1;
                }
                
                let res = AllocatedNum::paired_mix_columns(
                    &mut round_cs,
                    &x_column[0], &x_column[1], &x_column[2], &x_column[3], 
                    &y_column[0], &y_column[1], &y_column[2], &y_column[3], 
                )?;

                column_chunk[0] = res.0;
                column_chunk[1] = res.1;
            }

            let (mut key, mut modifier) = if take_left_part { 
                (&mut l_key, r_key.last().unwrap().clone())
            } 
            else { 
                (&mut r_key,  l_key.last().unwrap().clone()) 
            };

            if round == self.Nr - 2 
            {        
                for i in 0..self.Nb {
                    let new_state = AllocatedNum::wide_round_key_add(
                        &mut round_cs, &l_hash_state[i], &r_hash_state[i], &key[i])?;
                    
                    l_hash_state[i] = new_state.0;
                    r_hash_state[1] = new_state.1;
                }
            } 
            else
            {
                let mut unpacked_modifier = modifier.decompose(&mut round_cs)?;

                for chunk in unpacked_modifier.chunks_mut(2) {
                    let res = self.paired_sub_bytes(&mut round_cs, &chunk[0], &chunk[1])?;
                    chunk[0] = res.0;
                    chunk[1] = res.1;
                }

                modifier = AllocatedNum::compose(
                    &unpacked_modifier[0], &unpacked_modifier[1], &unpacked_modifier[2], &unpacked_modifier[3], &mut round_cs
                )?;

                for i in 0..self.Nb {
                    let [new_l_state, new_r_state, new_key] = AllocatedNum::wide_round_key_add_update(
                        &mut round_cs, &l_hash_state[i], &r_hash_state[i], &key[i], &modifier)?;
                
                    l_hash_state[i] = new_l_state;
                    r_hash_state[i] = new_r_state;
                    key[i] = new_key;
                    modifier = new_key;
                } 
            }

            take_left_part ^= true;
            
        }

        // final round is a bit different
        {
            let mut final_round_cs = cs.namespace(|| format!("final_round"));

            for column_chunk in l_hash_state.chunks_mut(2).chain(r_hash_state.chunks_mut(2)) {

                let res = AllocatedNum::paired_decompose(&mut final_round_cs, &column_chunk[0], &column_chunk[1])?;
                let mut x_column = res.0;
                let mut y_column = res.1;

                for (x, y) in x_column.iter_mut().zip(y_column.iter_mut()) {
                    let res = self.paired_sub_bytes(&mut final_round_cs, &x, &y)?;
                    *x = res.0;
                    *y = res.1;
                }
                
                let res = AllocatedNum::paired_compose(
                    &mut final_round_cs,
                    &x_column[0], &x_column[1], &x_column[2], &x_column[3], 
                    &y_column[0], &y_column[1], &y_column[2], &y_column[3], 
                )?;

                column_chunk[0] = res.0;
                column_chunk[1] = res.1;
            }

            let key = if take_left_part { &l_key} else { &r_key };

            for i in 0..self.Nb {
                let res = AllocatedNum::wide_final_hash_update(
                    &mut final_round_cs, &L_new[i], &l_hash_state[i], &R_new[i], &r_hash_state[i], &key[i]
                )?;

                l_hash_state[i] = res.0;
                r_hash_state[i] = res.1;
            }
        }

        self.hash_state = Vec::from_iter(l_hash_state.iter().chain(r_hash_state.iter()).copied());

        Ok(())
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::test_assembly::TestAssembly;


    struct TestCircuit<E: Engine> {
        input: E::Fr,
        Nb: usize, 
        Nk: usize, 
        Nr: usize, 
    }

    impl<E: Engine> BinaryCircuit<E> for TestCircuit<E> {
        fn synthesize<CS: ConstraintSystem<E>>(
            &self,
            cs: &mut CS,
        ) -> Result<(), SynthesisError> 
        {
            let mut aes_gadget = {
                let mut allocation_cs = cs.namespace(|| "var's pre-allocation");
                HiroseGadget::<E>::new(&mut allocation_cs, self.Nb, self.Nk, self.Nr)
            };

            let mut input = vec![];
            for _ in 0..self.Nb {
                input.push(AllocatedNum::alloc(cs, || Ok(self.input))?);
            }
            
            aes_gadget.absord(cs, input)?;
        
            Ok(())
        }
    }

    #[test]
    fn test_Hirose_gadget() {

        let input = rand::thread_rng().gen();

        let Nb: usize = 4; 
        let Nk: usize = 8;
        let Nr: usize = 14; 

        let test_circuit = TestCircuit::<Engine128> {
            input,
            Nb,
            Nk,
            Nr,
        };

        let mut cs = TestAssembly::<Engine128>::new(8);
        test_circuit.synthesize(&mut cs).expect("should synthesize");

        println!("Num constraints: {}", cs.num_gates());
        cs.print_statistics();
    }
}


