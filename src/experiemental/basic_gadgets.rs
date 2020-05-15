use super::gates::Variable;
use super::cs::BinaryConstraintSystem as ConstraintSystem;
use super::binary_field::BinaryField256 as Fr;
use super::cs::*;
use crate::bellman::SynthesisError;
use crate::bellman::pairing::ff::Field;
use crate::common::Assignment;


pub struct AllocatedNum {
    value: Option<Fr>,
    variable: Variable
}

impl Clone for AllocatedNum {
    fn clone(&self) -> Self {
        AllocatedNum {
            value: self.value,
            variable: self.variable
        }
    }
}


impl AllocatedNum {
   
    pub fn alloc<CS, F>(
        mut cs: CS,
        value: F,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem, F: FnOnce() -> Result<Fr, SynthesisError>
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
        mut cs: CS,
        value: F,
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem, F: FnOnce() -> Result<Fr, SynthesisError>
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

    pub fn get_value(&self) -> Option<Fr> {
        self.value
    }

    pub fn get_variable(&self) -> Variable {
        self.variable
    }

    pub fn mul<CS>(
        &self,
        mut cs: CS,
        other: &Self
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem
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
        mut cs: CS
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem
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

    // given element x, returns [x^2, x^4, x^8]
    pub fn pow8<CS>(
        &self,
        mut cs: CS
    ) -> Result<[Self; 3], SynthesisError>
        where CS: ConstraintSystem
    {
        let mut x2_value = None;
        let mut x4_value = None;
        let mut x8_value = None;

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

        let x8_var = cs.alloc(|| {
            let mut tmp = *x4_value.get()?;
            tmp.square();
            x8_value = Some(tmp);
            Ok(tmp)
        })?;

        cs.new_power8_gate(self.get_variable(), x2_var, x4_var, x8_var)?;

        Ok([AllocatedNum {
                value: value,
                variable: var
            },

            AllocatedNum {
                value: value,
                variable: var
            },

            AllocatedNum {
                value: value,
                variable: var
            },
        ])
    }

    pub fn ternary_add<CS>(
        &self,
        mut cs: CS,
        other: &Self
    ) -> Result<Self, SynthesisError>
        where CS: ConstraintSystem
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

    
    
//     // out = c_1 * a + c_2 * b
//     LinearCombinationGate([Variable; 3], [Coeff; 2]),
    
//     /// Takes two allocated numbers (a, b) and returns
//     /// a if the condition is true, and otherwise.
//     /// usually implemented using single constraint:
//     /// a * condition + b*(1-condition) = c ->
//     /// (a - b) * condition = c - b
//     /// the arr contains: [condition, a, b, c]
//     SelectorGate([Variable; 4]),

//     /// asserts a = b 
//     EqualityGate([Variable; 2]),

//     // We also need inversion in Field which is implemented using  the following PAIR of MUL gates:
// //  I * X = R
// //  (1-R) * X = 0 => X * R = X
// // if X = 0 then R = 0
// // if X != 0 then R = 1 and I = X^{-1}

    
//     /// Deconstructs this allocated number into its
//     /// boolean representation in little-endian bit
//     /// order, requiring that the representation
//     /// strictly exists "in the field" (i.e., a
//     /// congruency is not allowed.)
//     pub fn into_bits_le_strict<CS>(
//         &self,
//         mut cs: CS
//     ) -> Result<Vec<Boolean>, SynthesisError>
//         where CS: ConstraintSystem<E>
//     {
//         pub fn kary_and<E, CS>(
//             mut cs: CS,
//             v: &[AllocatedBit]
//         ) -> Result<AllocatedBit, SynthesisError>
//             where E: Engine,
//                   CS: ConstraintSystem<E>
//         {
//             assert!(v.len() > 0);

//             // Let's keep this simple for now and just AND them all
//             // manually
//             let mut cur = None;

//             for (i, v) in v.iter().enumerate() {
//                 if cur.is_none() {
//                     cur = Some(v.clone());
//                 } else {
//                     cur = Some(AllocatedBit::and(
//                         cs.namespace(|| format!("and {}", i)),
//                         cur.as_ref().unwrap(),
//                         v
//                     )?);
//                 }
//             }

//             Ok(cur.expect("v.len() > 0"))
//         }

//         // We want to ensure that the bit representation of a is
//         // less than or equal to r - 1.
//         let mut a = self.value.map(|e| BitIterator::new(e.into_repr()));
//         let mut b = E::Fr::char();
//         b.sub_noborrow(&1.into());

//         let mut result = vec![];

//         // Runs of ones in r
//         let mut last_run = None;
//         let mut current_run = vec![];

//         let mut found_one = false;
//         let mut i = 0;
//         for b in BitIterator::new(b) {
//             let a_bit = a.as_mut().map(|e| e.next().unwrap());

//             // Skip over unset bits at the beginning
//             found_one |= b;
//             if !found_one {
//                 // a_bit should also be false
//                 a_bit.map(|e| assert!(!e));
//                 continue;
//             }

//             if b {
//                 // This is part of a run of ones. Let's just
//                 // allocate the boolean with the expected value.
//                 let a_bit = AllocatedBit::alloc(
//                     cs.namespace(|| format!("bit {}", i)),
//                     a_bit
//                 )?;
//                 // ... and add it to the current run of ones.
//                 current_run.push(a_bit.clone());
//                 result.push(a_bit);
//             } else {
//                 if current_run.len() > 0 {
//                     // This is the start of a run of zeros, but we need
//                     // to k-ary AND against `last_run` first.

//                     if last_run.is_some() {
//                         current_run.push(last_run.clone().unwrap());
//                     }
//                     last_run = Some(kary_and(
//                         cs.namespace(|| format!("run ending at {}", i)),
//                         &current_run
//                     )?);
//                     current_run.truncate(0);
//                 }

//                 // If `last_run` is true, `a` must be false, or it would
//                 // not be in the field.
//                 //
//                 // If `last_run` is false, `a` can be true or false.

//                 let a_bit = AllocatedBit::alloc_conditionally(
//                     cs.namespace(|| format!("bit {}", i)),
//                     a_bit,
//                     &last_run.as_ref().expect("char always starts with a one")
//                 )?;
//                 result.push(a_bit);
//             }

//             i += 1;
//         }

//         // char is prime, so we'll always end on
//         // a run of zeros.
//         assert_eq!(current_run.len(), 0);

//         // Now, we have `result` in big-endian order.
//         // However, now we have to unpack self!

//         let mut lc = LinearCombination::zero();
//         let mut coeff = E::Fr::one();

//         for bit in result.iter().rev() {
//             lc = lc + (coeff, bit.get_variable());

//             coeff.double();
//         }

//         lc = lc - self.variable;

//         cs.enforce(
//             || "unpacking constraint",
//             |lc| lc,
//             |lc| lc,
//             |_| lc
//         );

//         // Convert into booleans, and reverse for little-endian bit order
//         Ok(result.into_iter().map(|b| Boolean::from(b)).rev().collect())
//     }

//     /// Convert the allocated number into its little-endian representation.
//     /// Note that this does not strongly enforce that the commitment is
//     /// "in the field."
//     pub fn into_bits_le<CS>(
//         &self,
//         mut cs: CS
//     ) -> Result<Vec<Boolean>, SynthesisError>
//         where CS: ConstraintSystem<E>
//     {
//         let bits = boolean::field_into_allocated_bits_le(
//             &mut cs,
//             self.value
//         )?;

//         let mut lc = LinearCombination::zero();
//         let mut coeff = E::Fr::one();

//         for bit in bits.iter() {
//             lc = lc + (coeff, bit.get_variable());

//             coeff.double();
//         }

//         lc = lc - self.variable;

//         cs.enforce(
//             || "unpacking constraint",
//             |lc| lc,
//             |lc| lc,
//             |_| lc
//         );

//         Ok(bits.into_iter().map(|b| Boolean::from(b)).collect())
//     }

    

//     /// Takes two allocated numbers (a, b) and returns
//     /// a if the condition is true, and b
//     /// otherwise.
//     /// Most often to be used with b = 0
//     pub fn conditionally_select<CS>(
//         mut cs: CS,
//         a: &Self,
//         b: &Self,
//         condition: &Boolean
//     ) -> Result<(Self), SynthesisError>
//         where CS: ConstraintSystem<E>
//     {
//         let c = Self::alloc(
//             cs.namespace(|| "conditional select result"),
//             || {
//                 if *condition.get_value().get()? {
//                     Ok(*a.value.get()?)
//                 } else {
//                     Ok(*b.value.get()?)
//                 }
//             }
//         )?;

//         // a * condition + b*(1-condition) = c ->
//         // a * condition - b*condition = c - b

//         cs.enforce(
//             || "conditional select constraint",
//             |lc| lc + a.variable - b.variable,
//             |_| condition.lc(CS::one(), E::Fr::one()),
//             |lc| lc + c.variable - b.variable
//         );

//         Ok(c)
//     }

//     /// Takes two allocated numbers (a, b) and returns
//     /// allocated boolean variable with value `true`
//     /// if the `a` and `b` are equal, `false` otherwise.
//     pub fn equals<CS>(
//         mut cs: CS,
//         a: &Self,
//         b: &Self
//     ) -> Result<boolean::Boolean, SynthesisError>
//         where E: Engine,
//             CS: ConstraintSystem<E>
//     {
//         // Allocate and constrain `r`: result boolean bit. 
//         // It equals `true` if `a` equals `b`, `false` otherwise

//         let r_value = match (a.get_value(), b.get_value()) {
//             (Some(a), Some(b))  => Some(a == b),
//             _                   => None,
//         };

//         let r = boolean::AllocatedBit::alloc(
//             cs.namespace(|| "r"), 
//             r_value
//         )?;

//         let delta = Self::alloc(
//             cs.namespace(|| "delta"), 
//             || {
//                 let a_value = *a.get_value().get()?;
//                 let b_value = *b.get_value().get()?;

//                 let mut delta = a_value;
//                 delta.sub_assign(&b_value);

//                 Ok(delta)
//             }
//         )?;

//         // 
//         cs.enforce(
//             || "delta = (a - b)",
//             |lc| lc + a.get_variable() - b.get_variable(),
//             |lc| lc + CS::one(),
//             |lc| lc + delta.get_variable(),
//         );

//         let delta_inv = Self::alloc(
//             cs.namespace(|| "delta_inv"), 
//             || {
//                 let delta = *delta.get_value().get()?;

//                 if delta.is_zero() {
//                     Ok(E::Fr::one()) // we can return any number here, it doesn't matter
//                 } else {
//                     Ok(delta.inverse().unwrap())
//                 }
//             }
//         )?;

//         // Allocate `t = delta * delta_inv`
//         // If `delta` is non-zero (a != b), `t` will equal 1
//         // If `delta` is zero (a == b), `t` cannot equal 1

//         let t = Self::alloc(
//             cs.namespace(|| "t"),
//             || {
//                 let mut tmp = *delta.get_value().get()?;
//                 tmp.mul_assign(&(*delta_inv.get_value().get()?));

//                 Ok(tmp)
//             }
        
//         )?;

//         // Constrain allocation: 
//         // t = (a - b) * delta_inv
//         cs.enforce(
//             || "t = (a - b) * delta_inv",
//             |lc| lc + a.get_variable() - b.get_variable(),
//             |lc| lc + delta_inv.get_variable(),
//             |lc| lc + t.get_variable(),
//         );

//         // Constrain: 
//         // (a - b) * (t - 1) == 0
//         // This enforces that correct `delta_inv` was provided, 
//         // and thus `t` is 1 if `(a - b)` is non zero (a != b )
//         cs.enforce(
//             || "(a - b) * (t - 1) == 0",
//             |lc| lc + a.get_variable() - b.get_variable(),
//             |lc| lc + t.get_variable() - CS::one(),
//             |lc| lc
//         );

//         // Constrain: 
//         // (a - b) * r == 0
//         // This enforces that `r` is zero if `(a - b)` is non-zero (a != b)
//         cs.enforce(
//             || "(a - b) * r == 0",
//             |lc| lc + a.get_variable() - b.get_variable(),
//             |lc| lc + r.get_variable(),
//             |lc| lc
//         );

//         // Constrain: 
//         // (t - 1) * (r - 1) == 0
//         // This enforces that `r` is one if `t` is not one (a == b)
//         cs.enforce(
//             || "(t - 1) * (r - 1) == 0",
//             |lc| lc + t.get_variable() - CS::one(),
//             |lc| lc + r.get_variable() - CS::one(),
//             |lc| lc
//         );

//         Ok(boolean::Boolean::from(r))
//     }

    
// }