use crate::bellman::pairing::ff::Field;
use crate::bellman::SynthesisError;
use std::marker::PhantomData;

use super::cs::*;
use super::gates::*;
use super::binary_field::BinaryField256 as Fr;


pub struct TestAssembly {
    m: usize,
    n: usize,
    input_gates: Vec<Gate>,
    aux_gates: Vec<Gate>,

    num_inputs: usize,
    num_aux: usize,

    input_assingments: Vec<Fr>,
    aux_assingments: Vec<Fr>,
    is_finalized: bool
}

impl BinaryConstraintSystem for TestAssembly {
    // allocate a variable
    fn alloc<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Fr, SynthesisError> 
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
        F: FnOnce() -> Result<Fr, SynthesisError> 
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

    fn get_value(&self, var: Variable) -> Result<Fr, SynthesisError> {
        let value = match var {
            Variable(Index::Aux(0)) => {
                Fr::zero()
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

    fn new_enforce_constant_gate(&self, variable: Variable, constant: Fr) -> Result<(), SynthesisError> {

        let gate = Gate::new_enforce_constant_gate(variable, constant);
        self.aux_gates.push(gate);
        self.n += 1;

        Ok(())
    }

    fn new_mul_gate(&self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError> {

        let gate = Gate::new_mul_gate(left, right, output);
        self.aux_gates.push(gate);
        self.n += 1;

        Ok(())
    }

    fn new_power8_gate(&self, x: Variable, x2: Variable, x4: Variable, x8: Variable) -> Result<(), SynthesisError> {

        let gate = Gate::new_power8_gate(x, x2, x4, x8);
        self.aux_gates.push(gate);
        self.n += 1;

        Ok(())
    }    
}


impl TestAssembly {
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
        };

        tmp
    }

    // return variable that is not in a constraint formally, but has some value
    fn dummy_variable(&self) -> Variable {
        Variable(Index::Aux(0))
    }

    pub fn is_satisfied(&self, in_a_middle: bool) -> bool {
        // expect a small number of inputs
        for (i, gate) in self.input_gates.iter().enumerate()
        {
            let Gate::<E::Fr> {
                variables: [a_var, b_var, c_var],
                coefficients: [q_l, q_r, q_o, q_m, q_c, q_c_next]
            } = *gate;

            let q_l = q_l.unpack();
            let q_r = q_r.unpack();
            let q_o = q_o.unpack();
            let q_m = q_m.unpack();
            let q_c = q_c.unpack();
            let q_c_next = q_c_next.unpack();

            assert!(q_c.is_zero(), "should not hardcode a constant into the input gate");
            assert!(q_c_next.is_zero(), "input gates should not link to the next gate");

            let a_value = self.get_value(a_var).expect("must get a variable value");
            let b_value = self.get_value(b_var).expect("must get a variable value");
            let c_value = self.get_value(c_var).expect("must get a variable value");

            let input_value = self.input_assingments[i];
            let mut res = input_value;
            res.negate();

            let mut tmp = q_l;
            tmp.mul_assign(&a_value);
            res.add_assign(&tmp);

            let mut tmp = q_r;
            tmp.mul_assign(&b_value);
            res.add_assign(&tmp);

            let mut tmp = q_o;
            tmp.mul_assign(&c_value);
            res.add_assign(&tmp);

            let mut tmp = q_m;
            tmp.mul_assign(&a_value);
            tmp.mul_assign(&b_value);
            res.add_assign(&tmp);

            if !res.is_zero() {
                println!("Unsatisfied at input gate {}: {:?}", i+1, gate);
                println!("A value = {}, B value = {}, C value = {}", a_value, b_value, c_value);
                return false;
            }
        }

        for (i, gate_pair) in self.aux_gates.windows(2).enumerate()
        {
            let this_gate = gate_pair[0];
            let next_gate = &gate_pair[1];

            let Gate::<E::Fr> {
                variables: [a_var, b_var, c_var],
                coefficients: [q_l, q_r, q_o, q_m, q_c, q_c_next]
            } = this_gate;

            let q_l = q_l.unpack();
            let q_r = q_r.unpack();
            let q_o = q_o.unpack();
            let q_m = q_m.unpack();
            let q_c = q_c.unpack();
            let q_c_next = q_c_next.unpack();

            let a_value = self.get_value(a_var).expect("must get a variable value");
            let b_value = self.get_value(b_var).expect("must get a variable value");
            let c_value = self.get_value(c_var).expect("must get a variable value");
            
            let next_gate_c_var = *next_gate.c_wire();
            let c_next_value = self.get_value(next_gate_c_var).expect("must get a variable value");

            let mut res = q_c;

            let mut tmp = q_l;
            tmp.mul_assign(&a_value);
            res.add_assign(&tmp);

            let mut tmp = q_r;
            tmp.mul_assign(&b_value);
            res.add_assign(&tmp);

            let mut tmp = q_o;
            tmp.mul_assign(&c_value);
            res.add_assign(&tmp);

            let mut tmp = q_m;
            tmp.mul_assign(&a_value);
            tmp.mul_assign(&b_value);
            res.add_assign(&tmp);

            let mut tmp = q_c_next;
            tmp.mul_assign(&c_next_value);
            res.add_assign(&tmp);

            if !res.is_zero() {
                println!("Unsatisfied at aux gate {}", i+1);
                println!("Gate {:?}", this_gate);
                println!("A = {}, B = {}, C = {}", a_value, b_value, c_value);
                return false;
            }
        }

        if !in_a_middle {
            let i = self.aux_gates.len();
            let last_gate = *self.aux_gates.last().unwrap();

            let Gate::<E::Fr> {
                variables: [a_var, b_var, c_var],
                coefficients: [q_l, q_r, q_o, q_m, q_c, q_c_next]
            } = last_gate;

            let q_l = q_l.unpack();
            let q_r = q_r.unpack();
            let q_o = q_o.unpack();
            let q_m = q_m.unpack();
            let q_c = q_c.unpack();
            let q_c_next = q_c_next.unpack();

            let a_value = self.get_value(a_var).expect("must get a variable value");
            let b_value = self.get_value(b_var).expect("must get a variable value");
            let c_value = self.get_value(c_var).expect("must get a variable value");

            assert!(q_c_next.is_zero(), "last gate should not be linked to the next one");

            let mut res = q_c;

            let mut tmp = q_l;
            tmp.mul_assign(&a_value);
            res.add_assign(&tmp);

            let mut tmp = q_r;
            tmp.mul_assign(&b_value);
            res.add_assign(&tmp);

            let mut tmp = q_o;
            tmp.mul_assign(&c_value);
            res.add_assign(&tmp);

            let mut tmp = q_m;
            tmp.mul_assign(&a_value);
            tmp.mul_assign(&b_value);
            res.add_assign(&tmp);

            if !res.is_zero() {
                println!("Unsatisfied at aux gate {}", i+1);
                println!("Gate {:?}", last_gate);
                println!("A = {}, B = {}, C = {}", a_value, b_value, c_value);
                return false;
            }
        }

        true
    }

    pub fn num_gates(&self) -> usize {
        self.input_gates.len() + self.aux_gates.len()
    }
}
