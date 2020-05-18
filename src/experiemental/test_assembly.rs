use crate::bellman::pairing::ff::Field;
use crate::bellman::SynthesisError;
use std::marker::PhantomData;

use super::cs::*;
use super::gates::*;
use super::binary_field::BinaryField;


pub struct TestAssembly<E: Engine> {
    m: usize,
    n: usize,
    input_gates: Vec<Gate<E::Fr>>,
    aux_gates: Vec<Gate<E::Fr>>,

    num_inputs: usize,
    num_aux: usize,

    input_assingments: Vec<E::Fr>,
    aux_assingments: Vec<E::Fr>,
    is_finalized: bool,

    constraints_per_namespace: Vec<(String, usize)>,
    cur_namespace_idx: usize,
}


impl<E: Engine> BinaryConstraintSystem<E> for TestAssembly<E> {

    type Root = Self;

    // allocate a variable
    fn alloc<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError> 
    {
        let value = value()?;

        self.num_aux += 1;
        let index = self.num_aux;
        self.aux_assingments.push(value);

        // println!("Allocated variable Aux({}) with value {}", index, value);

        Ok(Variable(Index::Aux(index)))
    }

    // allocate an input variable
    fn alloc_input<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError> 
    {
        let value = value()?;

        self.num_inputs += 1;
        let index = self.num_inputs;
        self.input_assingments.push(value);

        let input_var = Variable(Index::Input(index));
        let gate = Gate::new_enforce_constant_gate(input_var, value);

        self.input_gates.push(gate);

        Ok(input_var)

    }

    fn get_value(&self, var: Variable) -> Result<E::Fr, SynthesisError> {
        let value = match var {
            Variable(Index::Aux(0)) => {
                E::Fr::zero()
                // return Err(SynthesisError::AssignmentMissing);
            }
            Variable(Index::Input(0)) => {
                return Err(SynthesisError::AssignmentMissing);
            }
            Variable(Index::Input(input)) => {
                self.input_assingments[input - 1]
            },
            Variable(Index::Aux(aux)) => {
                self.aux_assingments[aux - 1]
            }
        };

        Ok(value)
    }

    fn get_dummy_variable(&self) -> Variable {
        self.dummy_variable()
    }

    fn new_enforce_constant_gate(&mut self, variable: Variable, constant: E::Fr) -> Result<(), SynthesisError> {

        let gate = Gate::new_enforce_constant_gate(variable, constant);
        self.aux_gates.push(gate);
        self.n += 1;
        self.constraints_per_namespace[self.cur_namespace_idx].1 += 1;

        Ok(())
    }

    fn new_add_gate(&mut self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError> {

        let gate = Gate::new_add_gate(left, right, output);
        self.aux_gates.push(gate);
        self.n += 1;
        self.constraints_per_namespace[self.cur_namespace_idx].1 += 1;

        Ok(())
    }

    fn new_mul_gate(&mut self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError> {

        let gate = Gate::new_mul_gate(left, right, output);
        self.aux_gates.push(gate);
        self.n += 1;
        self.constraints_per_namespace[self.cur_namespace_idx].1 += 1;

        Ok(())
    }

    fn new_power4_gate(&mut self, x: Variable, x2: Variable, x4: Variable) -> Result<(), SynthesisError> {

        let gate = Gate::new_power4_gate(x, x2, x4);
        self.aux_gates.push(gate);
        self.n += 1;
        self.constraints_per_namespace[self.cur_namespace_idx].1 += 1;

        Ok(())
    }    

    fn new_ternary_addition_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable) -> Result<(), SynthesisError> 
    {
        let gate = Gate::new_ternary_addition_gate(a, b, c, out);
        self.aux_gates.push(gate);
        self.n += 1;
        self.constraints_per_namespace[self.cur_namespace_idx].1 += 1;

        Ok(())
    }

    fn new_linear_combination_gate(
        &mut self, a: Variable, b: Variable, out: Variable, c_1: E::Fr, c_2: E::Fr) -> Result<(), SynthesisError> 
    {
        let gate = Gate::new_linear_combination_gate(a, b, out, Coeff::Full(c_1), Coeff::Full(c_2));
        self.aux_gates.push(gate);
        self.n += 1;
        self.constraints_per_namespace[self.cur_namespace_idx].1 += 1;

        Ok(())
    }

    fn new_long_linear_combination_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable, 
        c_1: E::Fr, c_2: E::Fr, c_3: E::Fr) -> Result<(), SynthesisError> 
    {
        let gate = Gate::new_long_linear_combination_gate(
            a, b, c, out, Coeff::Full(c_1), Coeff::Full(c_2), Coeff::Full(c_3));
        self.aux_gates.push(gate);
        self.n += 1;
        self.constraints_per_namespace[self.cur_namespace_idx].1 += 1;

        Ok(())
    }

    fn new_selector_gate(
        &mut self, cond: Variable, a: Variable, b: Variable, out: Variable) -> Result<(), SynthesisError> {

        let gate = Gate::new_selector_gate(cond, a, b, out);
        self.aux_gates.push(gate);
        self.n += 1;
        self.constraints_per_namespace[self.cur_namespace_idx].1 += 1;

        Ok(())
    }

    fn new_equality_gate(&mut self, left: Variable, right: Variable) -> Result<(), SynthesisError> {

        let gate = Gate::new_equality_gate(left, right);
        self.aux_gates.push(gate);
        self.n += 1;
        self.constraints_per_namespace[self.cur_namespace_idx].1 += 1;

        Ok(())
    }

    fn push_namespace<NR, N>(&mut self, name_func: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let namespace : String = name_func().into();
        self.constraints_per_namespace.push((namespace, 0));
        self.cur_namespace_idx = self.constraints_per_namespace.len() - 1;
    }

    fn pop_namespace(&mut self) {
        self.cur_namespace_idx = 0;
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}


impl<E: Engine> TestAssembly<E> {
    pub fn new() -> Self {
        let tmp = Self {
            n: 0,
            m: 0,
            input_gates: vec![],
            aux_gates: vec![],

            num_inputs: 0,
            num_aux: 0,

            input_assingments: vec![],
            aux_assingments: vec![],

            is_finalized: false,
            constraints_per_namespace: vec![("uncategorized".to_string(), 0)],
            cur_namespace_idx: 0,
        };

        tmp
    }

    pub fn new_with_size_hints(num_inputs: usize, num_aux: usize) -> Self {
        let tmp = Self {
            n: 0,
            m: 0,
            input_gates: Vec::with_capacity(num_inputs),
            aux_gates: Vec::with_capacity(num_aux),

            num_inputs: 0,
            num_aux: 0,

            input_assingments: Vec::with_capacity(num_inputs),
            aux_assingments: Vec::with_capacity(num_aux),

            is_finalized: false,
            constraints_per_namespace: vec![("uncategorized".to_string(), 0)],
            cur_namespace_idx: 0,
        };

        tmp
    }

    // return variable that is not in a constraint formally, but has some value
    fn dummy_variable(&self) -> Variable {
        Variable(Index::Aux(0))
    }

    pub fn is_satisfied(&self) -> bool {
        // expect a small number of inputs
        for (i, gate) in self.input_gates.iter().enumerate()
        {
            match gate {
                Gate::ConstantGate(variable, value) => {
                    let expected_value = self.get_value(*variable).expect("must get a variable value");
                    if expected_value != *value {
                        println!("Unsatisfied at input gate nom. {}", i+1);
                        println!("Input value = {}, Const value = {}", expected_value, *value);
                        return false;
                     }
                },
                _ => unreachable!(),
            }
        }

        for (i, gate) in self.aux_gates.iter().enumerate()
        {
            match gate {

                Gate::ConstantGate(variable, value) => {
                    let expected_value = self.get_value(*variable).expect("must get a variable value");
                    if expected_value != *value {
                        println!("Unsatisfied at Constant gate nom. {}", i+1);
                        println!("Input value = {}, Const value = {}", expected_value, *value);
                        return false;
                    }
                },

                Gate::AddGate(var_arr) => {
                    let a_val = self.get_value(var_arr[0]).expect("must get a variable value");
                    let b_val = self.get_value(var_arr[1]).expect("must get a variable value");
                    let c_val = self.get_value(var_arr[2]).expect("must get a variable value");
                    
                    let mut temp = a_val.clone();
                    temp.add_assign(&b_val);
                    if temp != c_val {
                        println!("Unsatisfied at Add gate nom. {}", i+1);
                        println!("A = {}, B = {}, OUT = {}", a_val, b_val, c_val);
                        return false;
                    }
                },

                Gate::MulGate(var_arr) => {
                    let a_val = self.get_value(var_arr[0]).expect("must get a variable value");
                    let b_val = self.get_value(var_arr[1]).expect("must get a variable value");
                    let c_val = self.get_value(var_arr[2]).expect("must get a variable value");
                    
                    let mut temp = a_val.clone();
                    temp.mul_assign(&b_val);
                    if temp != c_val {
                        println!("Unsatisfied at Mul gate nom. {}", i+1);
                        println!("A = {}, B = {}, OUT = {}", a_val, b_val, c_val);
                        return false;
                    }
                },

                Gate::Power4Gate(var_arr) => {
                    let x = self.get_value(var_arr[0]).expect("must get a variable value");
                    let x2 = self.get_value(var_arr[1]).expect("must get a variable value");
                    let x4 = self.get_value(var_arr[2]).expect("must get a variable value");

                    let mut temp = x.clone();
                    for elem in [x2, x4].iter() {
                        temp.square();
                        if temp != *elem {
                            println!("Unsatisfied at Power8 gate nom. {}", i+1);
                            println!("X = {}, X^2 = {}", temp, *elem);
                            return false;
                        }
                    }
                },

                Gate::TernaryAdditionGate(var_arr) => {
                    let a_val = self.get_value(var_arr[0]).expect("must get a variable value");
                    let b_val = self.get_value(var_arr[1]).expect("must get a variable value");
                    let c_val = self.get_value(var_arr[2]).expect("must get a variable value");
                    let out = self.get_value(var_arr[3]).expect("must get a variable value");
                    
                    let mut temp = a_val.clone();
                    temp.add_assign(&b_val);
                    temp.add_assign(&c_val);

                    if temp != out {
                        println!("Unsatisfied at TernaryAdditionGate gate nom. {}", i+1);
                        println!("A = {}, B = {}, C = {}, OUT = {}", a_val, b_val, c_val, out);
                        return false;
                    }
                },
    
                Gate::LinearCombinationGate(var_arr, coeff_var) => {
                    
                    let a_val = self.get_value(var_arr[0]).expect("must get a variable value");
                    let b_val = self.get_value(var_arr[1]).expect("must get a variable value");
                    let out = self.get_value(var_arr[2]).expect("must get a variable value");

                    let c0 = coeff_var[0].unpack();
                    let c1 = coeff_var[0].unpack();

                    let mut temp1 = a_val.clone();
                    temp1.mul_assign(&c0);
                    let mut temp2 = b_val.clone();
                    temp2.mul_assign(&c1);
                    temp1.add_assign(&temp2);

                    if temp1 != out {
                        println!("Unsatisfied at LinearCombination Gate gate nom. {}", i+1);
                        println!("A = {}, B = {}, C1 = {}, C2 = {}, OUT = {}", a_val, b_val, c0, c1, out);
                        return false;
                    }  
                },

                Gate::LongLinearCombinationGate(var_arr, coeff_var) => {
                    
                    let a_val = self.get_value(var_arr[0]).expect("must get a variable value");
                    let b_val = self.get_value(var_arr[1]).expect("must get a variable value");
                    let c_val = self.get_value(var_arr[2]).expect("must get a variable value");
                    let out = self.get_value(var_arr[3]).expect("must get a variable value");

                    let c0 = coeff_var[0].unpack();
                    let c1 = coeff_var[0].unpack();
                    let c2 = coeff_var[0].unpack();

                    let mut temp1 = a_val.clone();
                    temp1.mul_assign(&c0);
                    let mut temp2 = b_val.clone();
                    temp2.mul_assign(&c1);
                    temp1.add_assign(&temp2);
                    temp2 = c_val.clone();
                    temp2.mul_assign(&c2);
                    temp1.add_assign(&temp2);

                    if temp1 != out {
                        println!("Unsatisfied at LongLinearCombination Gate gate nom. {}", i+1);
                        println!("X = {}, Y = {}, Z = {}, C1 = {}, C2 = {}, C3 = {}, OUT = {}", 
                            a_val, b_val, c_val, c0, c1, c2, out);
                        return false;
                    }  
                },
    
                Gate::SelectorGate(var_arr) => {

                    let cond = self.get_value(var_arr[0]).expect("must get a variable value");
                    let a = self.get_value(var_arr[1]).expect("must get a variable value");
                    let b = self.get_value(var_arr[2]).expect("must get a variable value");
                    let out = self.get_value(var_arr[3]).expect("must get a variable value");

                    let zero = E::Fr::zero();
                    let one = E::Fr::one();

                    if (cond != zero) && (cond != one) {
                        println!("Condition is not boolean at Selector Gate gate nom. {}", i+1);
                        println!("COND = {}", cond);
                        return false;
                    }

                    let mut  flag = false;
                    if cond == one {
                        flag = true;
                    }

                    let expected = match flag {
                        true => a,
                        false => b,
                    };

                    if expected != out {
                        println!("Unsatisfied at Selector Gate gate nom. {}", i+1);
                        println!("COND = {}, A = {}, B = {}, OUT = {}", flag, a, b, out);
                        return false;
                    }
                },

                Gate::EqualityGate(var_arr) => {

                    let a = self.get_value(var_arr[0]).expect("must get a variable value");
                    let b = self.get_value(var_arr[1]).expect("must get a variable value");

                    if a != b {
                        println!("Unsatisfied at Equality Gate gate nom. {}", i+1);
                        println!("A = {}, B = {}", a, b);
                        return false;
                    }
                },
              
                _ => {
                    println!("Unknown type of Gate nom. {}", i+1);
                    return false;
                }
            }
        };
            
        true
    }

    pub fn num_gates(&self) -> usize {
        self.input_gates.len() + self.aux_gates.len()
    }

    pub fn print_statistics(&self) {
        println!("Total number of constraints:", i+1);
    }
}
