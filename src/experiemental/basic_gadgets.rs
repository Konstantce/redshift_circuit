use super::gates::Variable;
use super::cs::BinaryConstraintSystem as ConstraintSystem;
use super::binary_field::BinaryField;
use super::cs::*;
use crate::bellman::SynthesisError;
use crate::bellman::pairing::ff::Field;
use crate::common::Assignment;
use arraymap::ArrayMap;
use rand::Rng;

#[derive(Debug)]
pub struct AllocatedNum<E: Engine> {
    value: Option<E::Fr>,
    variable: Variable
}

impl<E: Engine> Clone for AllocatedNum<E> {
    fn clone(&self) -> Self {
        AllocatedNum {
            value: self.value,
            variable: self.variable
        }
    }
}

impl<E: Engine> Copy for AllocatedNum<E> {}


impl<E: Engine> AllocatedNum<E> {
   
    pub fn alloc<CS, F>(
        cs: &mut CS,
        value: F,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>, F: FnOnce() -> Result<E::Fr, SynthesisError>
    {
        let mut new_value = None;
        let var = cs.alloc(|| {
            let tmp = value()?;
            new_value = Some(tmp);
            Ok(tmp)
        })?;

        Ok(AllocatedNum {
            value: new_value,
            variable: var
        })
    }

    pub fn alloc_input<CS, F>(
        cs: &mut CS,
        value: F,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>, F: FnOnce() -> Result<E::Fr, SynthesisError>
    {
        let mut new_value = None;
        let var = cs.alloc_input(|| {
            let tmp = value()?;
            new_value = Some(tmp);
            Ok(tmp)
        })?;

        Ok(AllocatedNum {
            value: new_value,
            variable: var
        })
    }

    // for testing purposes only

    pub fn alloc_random<CS>(
        cs: &mut CS,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let value : E::Fr = rand::thread_rng().gen();
        let var = cs.alloc(|| {
            Ok(value)
        })?;

        Ok(AllocatedNum {
            value: Some(value),
            variable: var
        })
    }

    pub fn get_value(&self) -> Option<E::Fr> {
        self.value
    }

    pub fn get_variable(&self) -> Variable {
        self.variable
    }

    pub fn add<CS>(
        &self,
        cs: &mut CS,
        other: &Self
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let var = cs.alloc(|| {
            let mut tmp = *self.value.get()?;
            tmp.add_assign(other.value.get()?);
            value = Some(tmp);
            Ok(tmp)
        })?;

        cs.new_add_gate(self.get_variable(), other.get_variable(), var)?;

        Ok(AllocatedNum {
            value,
            variable: var
        })
    }

    pub fn mul<CS>(
        &self,
        cs: &mut CS,
        other: &Self
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let var = cs.alloc(|| {
            let mut tmp = *self.value.get()?;
            tmp.mul_assign(other.value.get()?);
            value = Some(tmp);
            Ok(tmp)
        })?;

        cs.new_mul_gate(self.get_variable(), other.get_variable(), var)?;

        Ok(AllocatedNum {
            value,
            variable: var
        })
    }

    pub fn square<CS>(
        &self,
        cs: &mut CS
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let var = cs.alloc(|| {
            let mut tmp = *self.value.get()?;
            tmp.square();
            value = Some(tmp);
            Ok(tmp)
        })?;

        cs.new_mul_gate(self.get_variable(), self.get_variable(), var)?;

        Ok(AllocatedNum {
            value: value,
            variable: var
        })
    }

    // given element x, returns [x^2, x^4]
    pub fn pow4<CS>(
        &self,
        cs: &mut CS
    ) -> Result<[Self; 2], SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut x2_value = None;
        let mut x4_value = None;

        let x2_var = cs.alloc(|| {
            let mut tmp = *self.value.get()?;
            tmp.square();
            x2_value = Some(tmp);
            Ok(tmp)
        })?;

        let x4_var = cs.alloc(|| {
            let mut tmp = *x2_value.get()?;
            tmp.square();
            x4_value = Some(tmp);
            Ok(tmp)
        })?;

        cs.new_power4_gate(self.get_variable(), x2_var, x4_var)?;

        Ok([AllocatedNum {
                value: x2_value,
                variable: x2_var
            },

            AllocatedNum {
                value: x4_value,
                variable: x4_var
            },
        ])
    }

    pub fn ternary_add<CS>(
        cs: &mut CS,
        a: &Self,
        b: &Self,
        c: &Self,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let var = cs.alloc(|| {
            let mut tmp = *a.value.get()?;
            tmp.add_assign(b.value.get()?);
            tmp.add_assign(c.value.get()?);
            value = Some(tmp);
            Ok(tmp)
        })?;

        cs.new_ternary_addition_gate(a.get_variable(), b.get_variable(), c.get_variable(), var)?;

        Ok(AllocatedNum {
            value,
            variable: var
        })
    }

    pub fn linear_combination_gadget<CS>(
        cs: &mut CS,
        a: &Self,
        b: &Self,
        c1: &E::Fr,
        c2: &E::Fr,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let var = cs.alloc(|| {
            let mut tmp1 = *a.value.get()?;
            tmp1.mul_assign(c1);
            let mut tmp2 = *b.value.get()?;
            tmp2.mul_assign(c2);

            tmp1.add_assign(&tmp2);
            value = Some(tmp1);
            Ok(tmp1)
        })?;

        cs.new_linear_combination_gate(a.get_variable(), b.get_variable(), var, c1.clone(), c2.clone())?;

        Ok(AllocatedNum {
            value,
            variable: var
        })
    }

    pub fn long_linear_combination_gadget<CS>(
        cs: &mut CS,
        a: &Self,
        b: &Self,
        c: &Self,
        c1: &E::Fr,
        c2: &E::Fr,
        c3: &E::Fr,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let out_var = cs.alloc(|| {
            let mut tmp1 = *a.value.get()?;
            tmp1.mul_assign(c1);
            let mut tmp2 = *b.value.get()?;
            tmp2.mul_assign(c2);
            tmp1.add_assign(&tmp2);
            tmp2 = *c.value.get()?;
            tmp2.mul_assign(c3);
            tmp1.add_assign(&tmp2);

            value = Some(tmp1);
            Ok(tmp1)
        })?;

        let a_var = a.get_variable();
        let b_var = b.get_variable();
        let c_var = c.get_variable();
        cs.new_long_linear_combination_gate(a_var, b_var, c_var, out_var, c1.clone(), c2.clone(), c3.clone())?;

        Ok(AllocatedNum {
            value,
            variable: out_var
        })
    }

    pub fn selector_gadget<CS>(
        cs: &mut CS,
        cond: &Self,
        a: &Self,
        b: &Self,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let var = cs.alloc(|| {
            let cond_value = *cond.value.get()?;
            let a_value = *a.value.get()?;
            let b_value = *b.value.get()?;

            let tmp = match (cond_value == E::Fr::one(), cond_value == E::Fr::zero()) {
                (true, false) => a_value.clone(),
                (false, true) => b_value.clone(),
                (_, _) => unreachable!(),
            };

            value = Some(tmp);
            Ok(tmp)
        })?;

        cs.new_selector_gate(cond.get_variable(), a.get_variable(), b.get_variable(), var)?;

        Ok(AllocatedNum {
            value,
            variable: var
        })
    }

    pub fn equals<CS>(
        &self,
        cs: &mut CS,
        other: &Self
    ) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        
        cs.new_equality_gate(self.get_variable(), other.get_variable())?;
        Ok(())
    }

    // We also need inversion in Field which is implemented using  the following PAIR of MUL gates:
    // I * X = R
    // (1-R) * X = 0 => X * R = X
    // if X = 0 then R = 0
    // if X != 0 then R = 1 and I = X^{-1}
    // this gadget returns a pair R, I (I has no prescribed value if X = 0)

    pub fn extended_inv_gadget<CS>(
        &self,
        cs: &mut CS,
    ) -> Result<(Self, Self), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut flag_value = None;
        let mut inv_elem_value = None;

        let flag_var = cs.alloc(|| {
            let val = *self.value.get()?;
            let tmp = match val == E::Fr::zero() {
                true => E::Fr::zero(),
                false => E::Fr::one(),
            };

            flag_value = Some(tmp);
            Ok(tmp)
        })?;

        let inv_elem_var = cs.alloc(|| {
            let val = *self.value.get()?;
            let tmp = val.inverse();
            let tmp = tmp.get()?;

            inv_elem_value = Some(*tmp);
            Ok(*tmp)
        })?;

        // I * X = R
        // X * R = X
        cs.new_mul_gate(inv_elem_var, self.get_variable(), flag_var)?;
        cs.new_mul_gate(self.get_variable(), flag_var, self.get_variable())?;

        Ok(
            (
                AllocatedNum {
                    value: flag_value,
                    variable: flag_var
                },

                AllocatedNum {
                    value: inv_elem_value,
                    variable: inv_elem_var,
                }
            )
        )
    }

    // check subfield gadget: 
    // we check that this particluar element lies in GF(2^8) instead of the full field GF(2^128)
    // this is achieved with the help of Fermat's little theorem: 
    // we check that x^(2^8) = x

    pub fn check_subfield_gadget<CS>(
        cs: &mut CS,
        x: &Self,
        x8: &Self,
    ) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        cs.new_equality_gate(x.get_variable(), x8.get_variable())?;
        Ok(())
    }
   
    /// Deconstructs this allocated number x \in GF(2^128) into its
    /// GF(2^8) representation i.e
    /// x = x_0 * s + x_1 * s^2 + ... + x_(n-1) * s^(n-1)
    /// where all x_i \in GF(2^8) and s is fixed element of GF(2^128)
    /// NB: we do not check here that each x_i belongs to GH(2^128), 
    /// it should be done explicitely with the help of check_subfield_gadget
    
    pub fn unpack_128_into_8<CS>(
        &self,
        cs: &mut CS,
        // NB: s can be recalculated on the fly if really needed
        s: &E::Fr,
    ) -> Result<[Self; 16], SynthesisError>
        where CS: ConstraintSystem<E>
    {
        // TODO: we need to change basis first!
        let repr = self.value.map(|e| e.into_byte_repr());
        let mut values : [Option<E::Fr>; 16] = [None; 16];
        let mut allocated_nums: [Option<AllocatedNum<E>>; 16] = [None; 16];
        
        for (idx, (alloc_num, value)) in allocated_nums.iter_mut().zip(values.iter_mut()).enumerate() {
            let var = cs.alloc(|| {
                //let repr = repr.get()?;
                //let byte = repr[idx]; 
                //let tmp =  E::Fr::from_repr([byte as u32, 0, 0, 0]);
                let tmp = E::Fr::zero();
                
                // and here we need to return back to initial basis!
                *value = Some(tmp);
                Ok(tmp)
            })?;
            *alloc_num = Some(AllocatedNum {
                variable: var,
                value: *value,
            });
        }

        // we do also need several auxiliary variables as we using LongLinearCombinationGates 
        // that can sum up to only 3 elements 
        // NB: think how it can be reorganized with "looking forward" custom selector
        // y_0 = x_0 +  s * x_1 + s^2 * x_2
        // y_1 = y_0 + s^3 * x_3 + s^4 * x_4
        // y_2 = y_1 + s^5 * x_5 + s^6 * x_6
        // y_3 = y_2 + s^7 * x_7 + s^8 * x_8
        // y_4 = y_3 + s^9 * x_9 + s^10 * x_10
        // y_5 = y_4 + s^11 * x_11 + s^12 * x_12
        // y_6 = y_5 + s^13 * x_13 + s^14 * x_14
        // x = y_6 + s^15 * x_15

        let mut aux_y : [Option<Variable>; 7] = [None; 7];
        let mut slice_length = 3;

        for idx in 0..7 {
            aux_y[idx] = Some(cs.alloc(|| {
                // let mut repr = repr.get()?.clone();
                // for i in slice_length..16 {
                //     repr[i] = 0;
                // } 
                // let tmp =  Fr::from_byte_repr(repr);
                let tmp = E::Fr::zero();
 
                Ok(tmp)
            })?);
            slice_length += 2;
        }

        let mut coef = s.clone();
        let mut next_coef = coef.clone();
        next_coef.mul_assign(s);
        let mut cur_alloc_num_idx = 0;

        for idx in 0..8 {
            
            match idx {
                0 => {
                    cs.new_long_linear_combination_gate(
                        allocated_nums[0].unwrap().get_variable(),
                        allocated_nums[1].unwrap().get_variable(),
                        allocated_nums[2].unwrap().get_variable(),
                        aux_y[0].unwrap(),
                        E::Fr::one(),
                        coef,
                        next_coef,
                    )?;
                    cur_alloc_num_idx += 3;
                },

                7 => cs.new_linear_combination_gate(
                        aux_y[6].unwrap(),
                        allocated_nums[15].unwrap().get_variable(),
                        self.get_variable(),
                        E::Fr::one(),
                        coef,
                    )?,
                    
                _ => {
                    cs.new_long_linear_combination_gate(
                        aux_y[idx-1].unwrap(),
                        allocated_nums[cur_alloc_num_idx].unwrap().get_variable(),
                        allocated_nums[cur_alloc_num_idx + 1].unwrap().get_variable(),
                        aux_y[idx].unwrap(),
                        E::Fr::one(),
                        coef,
                        next_coef,
                    )?;
                    cur_alloc_num_idx += 2;
                }             
            }

            coef = next_coef.clone();
            next_coef.mul_assign(s);
        }

        let unwrapped = allocated_nums.map(|x| x.unwrap());
        Ok(unwrapped)
    }
        
    /// Inverse to the previosly defined operation:
    /// given separate elements x_i \in GF(2^8)
    /// pack them all in single x \in GF(2^128)
    
    pub fn pack_8_t0_128<CS>(
        cs: &mut CS,
        elems: [&Self; 16],
        s: &E::Fr,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let var = cs.alloc(|| {

            let mut running_sum = E::Fr::zero();
            let mut coef = E::Fr::one();

            for e in elems.iter() {
                let mut tmp = *e.value.get()?;
                tmp.mul_assign(&coef);

                running_sum.add_assign(&tmp);
                coef.mul_assign(&s);
            }

            value = Some(running_sum);
            Ok(running_sum)
        })?;

        // TODO: we need to change basis first!
        let repr = value.map(|e| e.into_byte_repr());

        let mut aux_y : [Option<Variable>; 7] = [None; 7];
        let mut slice_length = 3;

        for idx in 0..7 {
            aux_y[idx] = Some(cs.alloc(|| {
                // let mut repr = repr.get()?.clone();
                // for i in slice_length..16 {
                //     repr[i] = 0;
                // } 
                // let tmp =  Fr::from_byte_repr(repr);
                let tmp = E::Fr::zero();
 
                Ok(tmp)
            })?);
            slice_length += 2;
        }

        let mut coef = s.clone();
        let mut next_coef = coef.clone();
        next_coef.mul_assign(s);
        let mut cur_alloc_num_idx = 0;

        for idx in 0..8 {
            
            match idx {
                0 => {
                    cs.new_long_linear_combination_gate(
                        elems[0].get_variable(),
                        elems[1].get_variable(),
                        elems[2].get_variable(),
                        aux_y[0].unwrap(),
                        E::Fr::one(),
                        coef,
                        next_coef,
                    )?;
                    cur_alloc_num_idx += 3;
                },

                7 => cs.new_linear_combination_gate(
                        aux_y[6].unwrap(),
                        elems[15].get_variable(),
                        var,
                        E::Fr::one(),
                        coef,
                    )?,
                    
                _ => {
                    cs.new_long_linear_combination_gate(
                        aux_y[idx-1].unwrap(),
                        elems[cur_alloc_num_idx].get_variable(),
                        elems[cur_alloc_num_idx + 1].get_variable(),
                        aux_y[idx].unwrap(),
                        E::Fr::one(),
                        coef,
                        next_coef,
                    )?;
                    cur_alloc_num_idx += 2;
                }             
            }

            coef = next_coef.clone();
            next_coef.mul_assign(s);
        }

        Ok(AllocatedNum {
            value,
            variable: var
        })
    }

    pub fn unpack_32_into_8<CS>(
        &self,
        cs: &mut CS,
        // NB: s can be recalculated on the fly if really needed
        s: &E::Fr,
    ) -> Result<[Self; 4], SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut allocated_nums: [Option<AllocatedNum<E>>; 4] = [None; 4];
        
        for alloc_num in allocated_nums.iter_mut() {
            let var = cs.alloc(|| {
                Ok(E::Fr::zero())
            })?;
            *alloc_num = Some(AllocatedNum {
                variable: var,
                value: Some(E::Fr::zero()),
            });
        }

        // we do also need several auxiliary variables as we using LongLinearCombinationGates 
        // that can sum up to only 3 elements 
        // NB: think how it can be reorganized with "looking forward" custom selector
        // y = x_0 +  s * x_1 + s^2 * x_2
        // x = y + s^3 * x_3

        let aux_y = cs.alloc(|| {
            Ok(E::Fr::zero())
        })?;

        let s1 = s.clone();
        let mut s2 = s1.clone();
        s2.mul_assign(&s1);
        let mut s3 = s2;
        s3.mul_assign(&s1);

        cs.new_long_linear_combination_gate(
            allocated_nums[0].unwrap().get_variable(),
            allocated_nums[1].unwrap().get_variable(),
            allocated_nums[2].unwrap().get_variable(),
            aux_y,
            E::Fr::one(),
            s1,
            s2,
        )?;

        cs.new_linear_combination_gate(
            aux_y,
            allocated_nums[3].unwrap().get_variable(),
            self.get_variable(),
            E::Fr::one(),
            s3,
        )?;
       
        let unwrapped = allocated_nums.map(|x| x.unwrap());
        Ok(unwrapped)
    }

    pub fn pack_8_t0_32<CS>(
        cs: &mut CS,
        elems: [&Self; 4],
        s: &E::Fr,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let var = cs.alloc(|| {

            let mut running_sum = E::Fr::zero();
            let mut coef = E::Fr::one();

            for e in elems.iter() {
                let mut tmp = *e.value.get()?;
                tmp.mul_assign(&coef);

                running_sum.add_assign(&tmp);
                coef.mul_assign(&s);
            }

            value = Some(running_sum);
            Ok(running_sum)
        })?;

        let aux_y = cs.alloc(|| {
            Ok(E::Fr::zero())
        })?;

        let s1 = s.clone();
        let mut s2 = s1.clone();
        s2.mul_assign(&s1);
        let mut s3 = s2;
        s3.mul_assign(&s1);

        cs.new_long_linear_combination_gate(
            elems[0].get_variable(),
            elems[1].get_variable(),
            elems[2].get_variable(),
            aux_y,
            E::Fr::one(),
            s1,
            s2,
        )?;

        cs.new_linear_combination_gate(
            aux_y,
            elems[3].get_variable(),
            var,
            E::Fr::one(),
            s3,
        )?;
       
        Ok(AllocatedNum {
            value,
            variable: var
        })
    }

    pub fn unpack_128_into_32<CS>(
        &self,
        cs: &mut CS,
        // NB: s can be recalculated on the fly if really needed
        s: &E::Fr,
    ) -> Result<[Self; 4], SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut allocated_nums: [Option<AllocatedNum<E>>; 4] = [None; 4];
        
        for alloc_num in allocated_nums.iter_mut() {
            let var = cs.alloc(|| {
                Ok(E::Fr::zero())
            })?;
            *alloc_num = Some(AllocatedNum {
                variable: var,
                value: Some(E::Fr::zero()),
            });
        }

        // we do also need several auxiliary variables as we using LongLinearCombinationGates 
        // that can sum up to only 3 elements 
        // NB: think how it can be reorganized with "looking forward" custom selector
        // y = x_0 +  s * x_1 + s^2 * x_2
        // x = y + s^3 * x_3

        let aux_y = cs.alloc(|| {
            Ok(E::Fr::zero())
        })?;

        let s1 = s.clone();
        let mut s2 = s1.clone();
        s2.mul_assign(&s1);
        let mut s3 = s2;
        s3.mul_assign(&s1);

        cs.new_long_linear_combination_gate(
            allocated_nums[0].unwrap().get_variable(),
            allocated_nums[1].unwrap().get_variable(),
            allocated_nums[2].unwrap().get_variable(),
            aux_y,
            E::Fr::one(),
            s1,
            s2,
        )?;

        cs.new_linear_combination_gate(
            aux_y,
            allocated_nums[3].unwrap().get_variable(),
            self.get_variable(),
            E::Fr::one(),
            s3,
        )?;
       
        let unwrapped = allocated_nums.map(|x| x.unwrap());
        Ok(unwrapped)
    }

    pub fn pack_32_t0_128<CS>(
        cs: &mut CS,
        elems: [&Self; 4],
        s: &E::Fr,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut value = None;

        let var = cs.alloc(|| {

            let mut running_sum = E::Fr::zero();
            let mut coef = E::Fr::one();

            for e in elems.iter() {
                let mut tmp = *e.value.get()?;
                tmp.mul_assign(&coef);

                running_sum.add_assign(&tmp);
                coef.mul_assign(&s);
            }

            value = Some(running_sum);
            Ok(running_sum)
        })?;

        let aux_y = cs.alloc(|| {
            Ok(E::Fr::zero())
        })?;

        let s1 = s.clone();
        let mut s2 = s1.clone();
        s2.mul_assign(&s1);
        let mut s3 = s2;
        s3.mul_assign(&s1);

        cs.new_long_linear_combination_gate(
            elems[0].get_variable(),
            elems[1].get_variable(),
            elems[2].get_variable(),
            aux_y,
            E::Fr::one(),
            s1,
            s2,
        )?;

        cs.new_linear_combination_gate(
            aux_y,
            elems[3].get_variable(),
            var,
            E::Fr::one(),
            s3,
        )?;
       
        Ok(AllocatedNum {
            value,
            variable: var
        })
    } 
}
        

