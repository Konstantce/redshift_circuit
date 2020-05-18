use super::binary_field::BinaryField;
use std::ops::Neg;
use crate::bellman::pairing::ff::Field;

use enum_map::Enum;
use std::error::Error;
use std::fmt;


pub enum Coeff<Fr: BinaryField> {
    Zero,
    One,
    NegativeOne,
    Full(Fr),
}

impl<Fr: BinaryField> std::fmt::Debug for Coeff<Fr> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Coeff::Zero => {
                write!(f, "Coeff 0")
            },
            Coeff::One => {
                write!(f, "Coeff 1")
            },
            Coeff::NegativeOne => {
                write!(f, "Coeff -1")
            },
            Coeff::Full(c) => {
                write!(f, "Coeff {:?}", c)
            },
        }
    }
}

impl<Fr: BinaryField> Coeff<Fr> {
    pub fn multiply(&self, with: &mut Fr) {
        match self {
            Coeff::Zero => {
                *with = Fr::zero();
            },
            Coeff::One => {},
            Coeff::NegativeOne => {
                with.negate();
            },
            Coeff::Full(val) => {
                with.mul_assign(val);
            }
        }
    }

    pub fn new(coeff: Fr) -> Self {  
        let mut negative_one = Fr::one();
        negative_one.negate();

        if coeff.is_zero() {
            Coeff::Zero
        } else if coeff == Fr::one() {
            Coeff::One
        } else if coeff == negative_one {
            Coeff::NegativeOne
        } else {
            Coeff::Full(coeff)
        }
    }

    pub fn unpack(&self) -> Fr {
        match self {
            Coeff::Zero => {
                Fr::zero()
            },
            Coeff::One => {
                Fr::one()
            },
            Coeff::NegativeOne => {
                let mut tmp = Fr::one();
                tmp.negate();

                tmp
            },
            Coeff::Full(c) => {
                *c
            },
        }
    }
}

impl<Fr: BinaryField> Copy for Coeff<Fr> {}
impl<Fr: BinaryField> Clone for Coeff<Fr> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Fr: BinaryField> Neg for Coeff<Fr> {
    type Output = Coeff<Fr>;

    fn neg(self) -> Self {
        match self {
            Coeff::Zero => Coeff::Zero,
            Coeff::One => Coeff::NegativeOne,
            Coeff::NegativeOne => Coeff::One,
            Coeff::Full(mut a) => {
                a.negate();
                Coeff::Full(a)
            }
        }
    }
}


/// Represents a variable in our constraint system.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Variable(pub(crate) Index);

impl Variable {
    /// This constructs a variable with an arbitrary index.
    /// Circuit implementations are not recommended to use this.
    pub fn new_unchecked(idx: Index) -> Variable {
        Variable(idx)
    }

    /// This returns the index underlying the variable.
    /// Circuit implementations are not recommended to use this.
    pub fn get_unchecked(&self) -> Index {
        self.0
    }
}

/// Represents the index of either an input variable or
/// auxillary variable.
#[derive(Copy, Clone, PartialEq, Debug, Hash, Eq)]
pub enum Index {
    Input(usize),
    Aux(usize)
}

/// used for statistics
#[derive(Enum)]
pub enum GateType {
    EmptyGate,
    ConstantGate,
    AddGate,
    MulGate,
    Power4Gate,
    TernaryAdditionGate,
    LinearCombinationGate,
    LongLinearCombinationGate,
    SelectorGate,
    EqualityGate,
}


impl fmt::Display for GateType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match self {
            GateType::EmptyGate => "Empty Gate",
            GateType::ConstantGate => "Constant Gate",
            GateType::AddGate => "Addition Gate",
            GateType::MulGate => "Multiplication Gate",
            GateType::Power4Gate => "Power4 Gate",
            GateType::TernaryAdditionGate => "Ternary Addition Gate",
            GateType::LinearCombinationGate => "Linear Combination Gate",
            GateType::LongLinearCombinationGate => "Long Linear Combination Gate",
            GateType::SelectorGate => "Selector Gate",
            GateType::EqualityGate => "Equality Gate",
        };
        
        write!(f, "{}", description)
    }
}

pub enum Gate<Fr: BinaryField> {
    
    EmptyGate,

    // x = c
    ConstantGate(Variable, Fr),

    // out = a + b
    AddGate([Variable; 3]),
    
    // out = a * b
    MulGate([Variable; 3]),
    
    // given element x, returns [x, x^2, x^4]
    Power4Gate([Variable; 3]),
    
    // out = a + b + c
    TernaryAdditionGate([Variable; 4]),
    
    // out = c_1 * a + c_2 * b
    LinearCombinationGate([Variable; 3], [Coeff<Fr>; 2]),

    // out = c_1 * a + c_2 * b + c_3 * c
    LongLinearCombinationGate([Variable; 4], [Coeff<Fr>; 3]),
    
    /// Takes two allocated numbers (a, b) and returns
    /// a if the condition is true, and otherwise.
    /// usually implemented using single constraint:
    /// a * condition + b*(1-condition) = c ->
    /// (a - b) * condition = c - b
    /// the arr contains: [condition, a, b, c]
    SelectorGate([Variable; 4]),

    /// asserts a = b 
    EqualityGate([Variable; 2]),
}

// We also need inversion in Field which is implemented using  the following PAIR of MUL gates:
//  I * X = R
//  (1-R) * X = 0 => X * R = X
// if X = 0 then R = 0
// if X != 0 then R = 1 and I = X^{-1}


impl<Fr: BinaryField> Gate<Fr> {
    pub(crate) fn new_empty_gate() -> Self {
        Self::EmptyGate
    }

    pub(crate) fn new_enforce_constant_gate(variable: Variable, constant: Fr) -> Self {
        Self::ConstantGate(variable, constant)
    }

    pub(crate) fn new_add_gate(left: Variable, right: Variable, output: Variable) -> Self {
        Self::AddGate([left, right, output])
    }

    pub(crate) fn new_mul_gate(left: Variable, right: Variable, output: Variable) -> Self {
        Self::MulGate([left, right, output])
    }

    pub(crate) fn new_power4_gate(x: Variable, x2: Variable, x4: Variable) -> Self {
        Self::Power4Gate([x, x2, x4])
    }

    pub(crate) fn new_ternary_addition_gate(a: Variable, b: Variable, c: Variable, out: Variable) -> Self {
        Self::TernaryAdditionGate([a, b, c, out])
    }

    pub(crate) fn new_linear_combination_gate(
        a: Variable, b: Variable, out: Variable, c_1: Coeff<Fr>, c_2: Coeff<Fr>) -> Self 
    {
        Self::LinearCombinationGate([a, b, out], [c_1, c_2])
    }

    pub(crate) fn new_long_linear_combination_gate(
        a: Variable, b: Variable, c: Variable, out: Variable, c_1: Coeff<Fr>, c_2: Coeff<Fr>, c_3: Coeff<Fr>) -> Self 
    {
        Self::LongLinearCombinationGate([a, b, c, out], [c_1, c_2, c_3])
    }

    pub(crate) fn new_selector_gate(cond: Variable, a: Variable, b: Variable, out: Variable) -> Self {
        Self::SelectorGate([cond, a, b, out])
    }

    pub(crate) fn new_equality_gate(left: Variable, right: Variable) -> Self {
        Self::EqualityGate([left, right])
    }

    pub(crate) fn gate_type(&self) -> GateType {
        let res = match self {
            Gate::EmptyGate => GateType::EmptyGate,
            Gate::ConstantGate(_, _) => GateType::ConstantGate,
            Gate::AddGate(_) => GateType::AddGate,
            Gate::MulGate(_) => GateType::MulGate,
            Gate::Power4Gate(_) => GateType::Power4Gate,
            Gate::TernaryAdditionGate(_) => GateType::TernaryAdditionGate,
            Gate::LinearCombinationGate(_, _) => GateType::LinearCombinationGate,
            Gate::LongLinearCombinationGate(_, _) => GateType::LongLinearCombinationGate,
            Gate::SelectorGate(_) => GateType::SelectorGate,
            Gate::EqualityGate(_) => GateType::EqualityGate,
            _ => unreachable!(),
        };

        res
    }
}