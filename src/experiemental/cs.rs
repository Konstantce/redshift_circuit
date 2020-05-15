use super::binary_field::BinaryField256 as Fr;
use super::gates::{Gate, Variable};

use crate::bellman::SynthesisError;


pub trait BinaryCircuit {
    fn synthesize<CS: BinaryConstraintSystem>(&self, cs: &mut CS) -> Result<(), SynthesisError>;
}

pub trait BinaryConstraintSystem {

    // allocate a variable
    fn alloc<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Fr, SynthesisError>;

    // allocate an input variable
    fn alloc_input<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Fr, SynthesisError>;

    fn get_value(&self, _variable: Variable) -> Result<Fr, SynthesisError> { 
        Err(SynthesisError::AssignmentMissing)
    }
  
    fn get_dummy_variable(&self) -> Variable;

    fn new_enforce_constant_gate(&self, variable: Variable, constant: Fr) -> Result<(), SynthesisError>;
    fn new_mul_gate(&self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError>;
    fn new_power8_gate(&self, x: Variable, x2: Variable, x4: Variable, x8: Variable) -> Result<(), SynthesisError>; 
}
