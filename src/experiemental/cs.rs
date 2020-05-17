use super::binary_field::BinaryField256 as Fr;
use super::gates::{Gate, Variable};

use crate::bellman::SynthesisError;


pub trait BinaryCircuit {
    fn synthesize<CS: BinaryConstraintSystem>(&self, cs: &mut CS) -> Result<(), SynthesisError>;
}


pub trait BinaryConstraintSystem {

    type Root: BinaryConstraintSystem;

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

    fn new_enforce_constant_gate(&mut self, variable: Variable, constant: Fr) -> Result<(), SynthesisError>;
    fn new_mul_gate(&mut self, left: Variable, right: Variable, output: Variable) -> Result<(), SynthesisError>;
    fn new_power4_gate(&mut self, x: Variable, x2: Variable, x4: Variable) -> Result<(), SynthesisError>;
    fn new_ternary_addition_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable) -> Result<(), SynthesisError>;
    fn new_linear_combination_gate(
        &mut self, a: Variable, b: Variable, out: Variable, c_1: Fr, c_2: Fr) -> Result<(), SynthesisError>;
    fn new_long_linear_combination_gate(
        &mut self, a: Variable, b: Variable, c: Variable, out: Variable, c_1: Fr, c_2: Fr, c_3: Fr) -> Result<(), SynthesisError>;
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
    ) -> Namespace<'a, Self::Root>
        where NR: Into<String>, N: FnOnce() -> NR
    {
        self.get_root().push_namespace(name_fn);

        Namespace(self.get_root())
    }
}


/// This is a "namespaced" constraint system which borrows a constraint system (pushing
/// a namespace context) and, when dropped, pops out of the namespace context.
pub struct Namespace<'a, CS: BinaryConstraintSystem + 'a>(&'a mut CS);

impl<'cs, CS: BinaryConstraintSystem> BinaryConstraintSystem for Namespace<'cs, CS> {
    
    type Root = CS::Root;

    fn alloc<F>(
        &mut self,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        self.0.alloc(annotation, f)
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        annotation: A,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        self.0.alloc_input(annotation, f)
    }

    fn enforce<A, AR, LA, LB, LC>(
        &mut self,
        annotation: A,
        a: LA,
        b: LB,
        c: LC
    )
        where A: FnOnce() -> AR, AR: Into<String>,
              LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
              LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
              LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>
    {
        self.0.enforce(annotation, a, b, c)
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
}

impl<'a, E: Engine, CS: ConstraintSystem<E>> Drop for Namespace<'a, E, CS> {
    fn drop(&mut self) {
        self.get_root().pop_namespace()
    }
}

/// Convenience implementation of ConstraintSystem<E> for mutable references to
/// constraint systems.
impl<'cs, E: Engine, CS: ConstraintSystem<E>> ConstraintSystem<E> for &'cs mut CS {
    type Root = CS::Root;

    fn one() -> Variable {
        CS::one()
    }

    fn alloc<F, A, AR>(
        &mut self,
        annotation: A,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        (**self).alloc(annotation, f)
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        annotation: A,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        (**self).alloc_input(annotation, f)
    }

    fn enforce<A, AR, LA, LB, LC>(
        &mut self,
        annotation: A,
        a: LA,
        b: LB,
        c: LC
    )
        where A: FnOnce() -> AR, AR: Into<String>,
              LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
              LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
              LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>
    {
        (**self).enforce(annotation, a, b, c)
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
}
