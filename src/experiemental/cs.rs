use super::binary_field::*;
use super::gates::{Gate, Variable};

use crate::bellman::SynthesisError;


pub trait Engine {
    type Fr: BinaryField;
}

pub struct Engine128;
impl Engine for Engine128 {
    type Fr = BinaryField128;
}

pub struct Engine160;
impl Engine for Engine160 {
    type Fr = BinaryField128;
}


pub struct Engine192;
impl Engine for Engine192 {
    type Fr = BinaryField192;
}

pub struct Engine256;
impl Engine for Engine256 {
    type Fr = BinaryField256;
}


pub trait BinaryCircuit<E: Engine> {
    fn synthesize<CS: BinaryConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError>;
}


pub trait BinaryConstraintSystem<E: Engine> {

    type Root: BinaryConstraintSystem<E>;

    // allocate a variable
    fn alloc<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>;

    // allocate an input variable
    fn alloc_input<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>;

    fn get_value(&self, _variable: Variable) -> Result<E::Fr, SynthesisError> { 
        Err(SynthesisError::AssignmentMissing)
    }
  
    fn get_dummy_variable(&self) -> Variable;

    fn new_enforce_constant_gate(&mut self, variable: Variable, constant: E::Fr) -> Result<(), SynthesisError>;
    fn new_add_gate(&mut self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError>;
    fn new_mul_gate(&mut self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError>;
    fn new_power4_gate(&mut self, x: Variable, x2: Variable, x4: Variable) -> Result<(), SynthesisError>;
    fn new_ternary_addition_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable) -> Result<(), SynthesisError>;
    fn new_linear_combination_gate(
        &mut self, a: Variable, b: Variable, out: Variable, c_1: E::Fr, c_2: E::Fr) -> Result<(), SynthesisError>;
    fn new_long_linear_combination_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable, 
        c_1: E::Fr, c_2: E::Fr, c_3: E::Fr) -> Result<(), SynthesisError>;
    fn new_selector_gate(&mut self, cond: Variable, a: Variable, b: Variable, out: Variable) -> Result<(), SynthesisError>;
    fn new_equality_gate(&mut self, left: Variable, right: Variable) -> Result<(), SynthesisError>;

    /// Create a new (sub)namespace and enter into it. Not intended
    /// for downstream use; use `namespace` instead.
    fn push_namespace<NR, N>(&mut self, name_fn: N)
        where NR: Into<String>, N: FnOnce() -> NR;

    /// Exit out of the existing namespace. Not intended for
    /// downstream use; use `namespace` instead.
    fn pop_namespace(&mut self);

    /// Gets the "root" constraint system, bypassing the namespacing.
    /// Not intended for downstream use; use `namespace` instead.
    fn get_root(&mut self) -> &mut Self::Root;

    /// Begin a namespace for this constraint system.
    fn namespace<'a, NR, N>(
        &'a mut self,
        name_fn: N
    ) -> Namespace<'a, E, Self::Root>
        where NR: Into<String>, N: FnOnce() -> NR
    {
        self.get_root().push_namespace(name_fn);

        Namespace(self.get_root(), std::marker::PhantomData)
    }

    fn new_decompose_gate(
        &mut self, P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Result<(), SynthesisError>;
    
    fn new_compose_gate(
        &mut self, P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Result<(), SynthesisError>;
    
    fn new_inv_select_gate(
        &mut self, x: Variable, x_inv: Variable, flag: Variable, out: Variable
    ) -> Result<(), SynthesisError>;

    fn new_sub_bytes_gate(
        &mut self, x: Variable, x4: Variable, x16: Variable, x64: Variable, out: Variable
    ) -> Result<(), SynthesisError>;

    fn new_mix_column_gate(
        &mut self, OUT: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Result<(), SynthesisError>;

    fn new_add_update_round_key_gate(
        &mut self, P_old: Variable, P_new: Variable, K_old: Variable, K_new: Variable, temp: Variable
    ) -> Result<(), SynthesisError>;
}


/// This is a "namespaced" constraint system which borrows a constraint system (pushing
/// a namespace context) and, when dropped, pops out of the namespace context.
pub struct Namespace<'a, E: Engine, CS: BinaryConstraintSystem<E> + 'a>(&'a mut CS, std::marker::PhantomData<E>);

impl<'cs, E: Engine, CS: BinaryConstraintSystem<E>> BinaryConstraintSystem<E> for Namespace<'cs, E, CS> {
    
    type Root = CS::Root;

    fn alloc<F>(
        &mut self,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>,
    {
        self.0.alloc(f)
    }

    fn alloc_input<F>(
        &mut self,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>,
    {
        self.0.alloc_input(f)
    }

    fn get_value(&self, variable: Variable) -> Result<E::Fr, SynthesisError> { 
        self.0.get_value(variable)
    }
  
    fn get_dummy_variable(&self) -> Variable {
        self.0.get_dummy_variable()
    }

    fn new_enforce_constant_gate(&mut self, variable: Variable, constant: E::Fr) -> Result<(), SynthesisError> {
        self.0.new_enforce_constant_gate(variable, constant)
    }

    fn new_add_gate(&mut self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError> {
        self.0.new_add_gate(left, right, output)
    }

    fn new_mul_gate(&mut self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError> {
        self.0.new_mul_gate(left, right, output)
    }

    fn new_power4_gate(&mut self, x: Variable, x2: Variable, x4: Variable) -> Result<(), SynthesisError> {
        self.0.new_power4_gate(x, x2, x4)
    }

    fn new_ternary_addition_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable) -> Result<(), SynthesisError> 
    {
        self.0.new_ternary_addition_gate(a, b, c, out)
    }
    fn new_linear_combination_gate(
        &mut self, a: Variable, b: Variable, out: Variable, c_1: E::Fr, c_2: E::Fr) -> Result<(), SynthesisError>
    {
        self.0.new_linear_combination_gate(a, b, out, c_1, c_2)
    }

    fn new_long_linear_combination_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable, 
        c_1: E::Fr, c_2: E::Fr, c_3: E::Fr) -> Result<(), SynthesisError>
    {
        self.0.new_long_linear_combination_gate(a, b, c, out, c_1, c_2, c_3)
    }

    fn new_selector_gate(&mut self, cond: Variable, a: Variable, b: Variable, out: Variable) -> Result<(), SynthesisError>
    {
        self.0.new_selector_gate(cond, a, b, out)
    }

    fn new_equality_gate(&mut self, left: Variable, right: Variable) -> Result<(), SynthesisError> 
    {
        self.0.new_equality_gate(left, right)
    }

    // Downstream users who use `namespace` will never interact with these
    // functions and they will never be invoked because the namespace is
    // never a root constraint system.

    fn push_namespace<NR, N>(&mut self, _: N)
        where NR: Into<String>, N: FnOnce() -> NR
    {
        panic!("only the root's push_namespace should be called");
    }

    fn pop_namespace(&mut self)
    {
        panic!("only the root's pop_namespace should be called");
    }

    fn get_root(&mut self) -> &mut Self::Root
    {
        self.0.get_root()
    }

    fn new_decompose_gate(
        &mut self, P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Result<(), SynthesisError> 
    {
        self.0.new_decompose_gate(P, P0, P1, P2, P3)
    }
    
    fn new_compose_gate(
        &mut self, P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Result<(), SynthesisError>
    {
        self.0.new_compose_gate(P, P0, P1, P2, P3)
    }
    
    fn new_inv_select_gate(
        &mut self, x: Variable, x_inv: Variable, flag: Variable, out: Variable
    ) -> Result<(), SynthesisError>
    {
        self.0.new_inv_select_gate(x, x_inv, flag, out)
    }

    fn new_sub_bytes_gate(
        &mut self, x: Variable, x4: Variable, x16: Variable, x64: Variable, out: Variable
    ) -> Result<(), SynthesisError>
    {
        self.0.new_sub_bytes_gate(x, x4, x16, x64, out)
    }

    fn new_mix_column_gate(
        &mut self, OUT: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Result<(), SynthesisError>
    {
        self.0.new_mix_column_gate(OUT, P0, P1, P2, P3)
    }

    fn new_add_update_round_key_gate(
        &mut self, P_old: Variable, P_new: Variable, K_old: Variable, K_new: Variable, temp: Variable
    ) -> Result<(), SynthesisError>
    {
        self.0.new_add_update_round_key_gate(P_old, P_new, K_old, K_new, temp)
    }
}


impl<'a, E: Engine, CS: BinaryConstraintSystem<E>> Drop for Namespace<'a, E, CS> {
    fn drop(&mut self) {
        self.get_root().pop_namespace()
    }
}


/// Convenience implementation of BinaryConstraintSystem for mutable references to constraint systems.
impl<'cs, E: Engine, CS: BinaryConstraintSystem<E>> BinaryConstraintSystem<E> for &'cs mut CS {
    
    type Root = CS::Root;

    fn alloc<F>(
        &mut self,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>
    {
        (**self).alloc(f)
    }

    fn alloc_input<F>(
        &mut self,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>
    {
        (**self).alloc_input(f)
    }

    fn get_value(&self, variable: Variable) -> Result<E::Fr, SynthesisError> { 
        (**self).get_value(variable)
    }
  
    fn get_dummy_variable(&self) -> Variable {
        (**self).get_dummy_variable()
    }

    fn new_enforce_constant_gate(&mut self, variable: Variable, constant: E::Fr) -> Result<(), SynthesisError> {
        (**self).new_enforce_constant_gate(variable, constant)
    }

    fn new_add_gate(&mut self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError> {
        (**self).new_add_gate(left, right, output)
    }

    fn new_mul_gate(&mut self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError> {
        (**self).new_mul_gate(left, right, output)
    }

    fn new_power4_gate(&mut self, x: Variable, x2: Variable, x4: Variable) -> Result<(), SynthesisError> {
        (**self).new_power4_gate(x, x2, x4)
    }

    fn new_ternary_addition_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable) -> Result<(), SynthesisError> 
    {
        (**self).new_ternary_addition_gate(a, b, c, out)
    }
    fn new_linear_combination_gate(
        &mut self, a: Variable, b: Variable, out: Variable, c_1: E::Fr, c_2: E::Fr) -> Result<(), SynthesisError>
    {
        (**self).new_linear_combination_gate(a, b, out, c_1, c_2)
    }

    fn new_long_linear_combination_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable, 
        c_1: E::Fr, c_2: E::Fr, c_3: E::Fr) -> Result<(), SynthesisError>
    {
        (**self).new_long_linear_combination_gate(a, b, c, out, c_1, c_2, c_3)
    }

    fn new_selector_gate(&mut self, cond: Variable, a: Variable, b: Variable, out: Variable) -> Result<(), SynthesisError>
    {
        (**self).new_selector_gate(cond, a, b, out)
    }

    fn new_equality_gate(&mut self, left: Variable, right: Variable) -> Result<(), SynthesisError> 
    {
        (**self).new_equality_gate(left, right)
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
        where NR: Into<String>, N: FnOnce() -> NR
    {
        (**self).push_namespace(name_fn)
    }

    fn pop_namespace(&mut self)
    {
        (**self).pop_namespace()
    }

    fn get_root(&mut self) -> &mut Self::Root
    {
        (**self).get_root()
    }

    fn new_decompose_gate(
        &mut self, P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Result<(), SynthesisError> 
    {
        (**self).new_decompose_gate(P, P0, P1, P2, P3)
    }
    
    fn new_compose_gate(
        &mut self, P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Result<(), SynthesisError>
    {
        (**self).new_compose_gate(P, P0, P1, P2, P3)
    }
    
    fn new_inv_select_gate(
        &mut self, x: Variable, x_inv: Variable, flag: Variable, out: Variable
    ) -> Result<(), SynthesisError>
    {
        (**self).new_inv_select_gate(x, x_inv, flag, out)
    }

    fn new_sub_bytes_gate(
        &mut self, x: Variable, x4: Variable, x16: Variable, x64: Variable, out: Variable
    ) -> Result<(), SynthesisError>
    {
        (**self).new_sub_bytes_gate(x, x4, x16, x64, out)
    }

    fn new_mix_column_gate(
        &mut self, OUT: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Result<(), SynthesisError>
    {
        (**self).new_mix_column_gate(OUT, P0, P1, P2, P3)
    }

    fn new_add_update_round_key_gate(
        &mut self, P_old: Variable, P_new: Variable, K_old: Variable, K_new: Variable, temp: Variable
    ) -> Result<(), SynthesisError>
    {
        (**self).new_add_update_round_key_gate(P_old, P_new, K_old, K_new, temp)
    }
}
