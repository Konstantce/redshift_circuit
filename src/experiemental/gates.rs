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
    // generation 1 gates (general purpose gates)
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

    // generation 2 gates (used in Davis-Meyer version of AES hash)
    DecomposeGate,
    ComposeGate,
    InvSelectorGate,
    SubBytesGate,
    MixClolumnsGate,
    RoundKeyAddUpdateGate,

    // generation 3 gates (used in Hirose)

    HiroseInitGate,
    WideRoundKeyAddUpdateGate,
    WideComposeDecompose,
    PairedInvSelectorGate,
    PairedSubBytesGate,
    PairedDecomposeGate,
    PairedComposeGate,
    PairedMixColumnsGate,
    WideFinalHashUpdateGate,
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

            GateType::DecomposeGate => "Decomposition Gate",
            GateType::ComposeGate => "Composition Gate",
            GateType::InvSelectorGate => "InvSelector Gate",
            GateType::SubBytesGate => "SubBytes Gate",
            GateType::MixClolumnsGate => "MixColumnGate",
            GateType::RoundKeyAddUpdateGate => "RoundKeyAddUpdateGate",

            GateType::HiroseInitGate => "Hirose Initiation Gate",
            GateType::WideRoundKeyAddUpdateGate => "WideRoundKeyUpdate Gate",
            GateType::WideComposeDecompose => "WideComposeDecompose Gate",
            GateType::PairedInvSelectorGate => "Paired InvSelector Gate",
            GateType::PairedSubBytesGate => "Paired SubBytes Gate",
            GateType::PairedDecomposeGate => "Paired Decompose Gate",
            GateType::PairedComposeGate => "Paired Compose Gate",
            GateType::PairedMixColumnsGate => "Paired MixColumns Gate",
            GateType::WideFinalHashUpdateGate => "Paired WideFinalHashUpdate Gate",
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

    // Used in more optimized version of constraint system (of width 4)
    // used for 192-bit field with Davis-Meyer of Rijndael
    // let call it CS version 2

    // arguments are [P, P0, P1, P2, P3]
    // we use P, P1, P2, P3 in this step and assume that P0 will be defined in the next state
    // this gadget asserts that
    // P = c0 * P0 + c1 * P1 + c2 * P2 + c3 * P3
    // for some predefined constants [c0, c1, c3, c3]
    // used for splitting 32-bit element into 4 bytes
    DecomposeGate([Variable; 5]),

    // inverse to the previous operation: 
    // arguments are the same: [P, P0, P1, P2, P3] as well as the asserion check
    // however, this time we assume that P3 is defined on the previous step
    ComposeGate([Variable; 5]),

    // InvSelect gadget: returns x^{-1} if x is invertible or zero instead
    // for width four the state is (x, x_inv, flag, out)
    // the transition functions on this row are: 
    // x_inv * x = flag
    // x * flag = X
    // out = x_inv * flag + x * (1 - flag)
    InvSelectorGate([Variable; 4]),

    // used for SubBytes : uses x from previous state (it's the first argument)
    // current state is (y1, y2, y3, out)
    // the transition functions are: 
    // y1 = x^4, y2 = y1^4=x^16, y2 = y1^4 = x^64, 
    // subfield check: x = y2^4 = x^256
    // out = \sum c_i x^{2^i}, for i \in [0, 7] - final result of SubBytes(x)
    SubBytesGate([Variable; 5]),

    // MixClolumnGadget: arguments are [OUT, P0, P1, P2, P3]
    // as in composeGadget we assume that P3 was defined on previous row
    // this gadget does simultaneous matrix multiplicatin   
    // [Q0, Q1, Q2, Q3]^(T)  = M * [P0, P1, P2, P3] ^ (T)
    // and composition: OUT = Q = Q0 * + Q1 * s + Q2 * s^2 + Q3 * s^3  
    // so it reduces to some linear combination of P0, P1, P2, P3
    MixColumnsGate([Variable; 5]),

    //simultaneous AddRoundKey + GenerateNextRoundLey
    // let temp = SubBytes(Rot(Key))
    // then with the state (P_old, P_new, K_old, K_new) (temp is a hidden variable)
    // we have P_new = P_old + K_old
    // K_new = K_old + temp and continet
    // NB: there is a special workflow for the final round though!
    RoundKeyAddUpdateGate([Variable; 5]),

    //---------------------------------------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------------------------------------

    // this used for 128-bit field and Hirose Hash construction with 256bit output
    // her state width is 8

    // Hirose starts with L (Left) = R (right) + c, where c - constant
    // both L and R contains 4 columns
    // state is (L0, L1, L2, L3, R0, R1, R2, R3)
    // Pi (init) = Qi + c_i
    HiroseInitGate([Variable; 8]),

    // for HiroseSheme the key is th same for both "subciphers"
    // so we may simultaneouly add to P and Q by the same round key and update the key
    // the state is [P_old, Q_old, K_old, P_new, Q_new, K_new, temp]
    // P_new = P_old + K_old
    // Q_new = Q_old + K_old
    // K_new = K_old + temp
    WideRoundKeyAddUpdateGate([Variable; 7]),

    // we exploit the fact that with 8 registers at our exposal, the packed variables P and
    // it's component parts may be located on a single row
    // state is [P, P0, P1, P2, P3]
    WideComposeDecompose([Variable; 5]),

    // same as ordinary InvSelect gadget, but process two elements simultaneously
    // state is (x1, x1_inv, flag_x1, out_x1, x2, x2_inv, flag_x2, out_x2)
    // i.e. two separated InvSelect gadgets are packed into single gate
    PairedInvSelectorGate([Variable; 8]),

    // the same situation as with WideInvSelectorGate except with the following additional remark:
    // the state transitions functions' degree should not exceed the width of state
    // that's why in the usual InvSelectorGadget y1 =x^4, y2 = y1^4 and so forth
    // now y1 = x1^8, y2 = y1^8, z1 = x2^8, z2 = z1^8, so there is enough space for (x1, x2) on the row
    // current state is (x1, y1, y2, out_x1, x2, z1, z2, out_x2)
    PairedSubBytesGate([Variable; 8]),

    // arguments are [P, P0, P1, P2, P3, Q, Q0, Q1, Q2, Q3]
    // we use P, P1, P2, P3, Q, Q1, Q2, Q3 in this step 
    // and assume that P0, Q0 will be defined in the next state (for example in PairedInvSelectorGate)
    PairedDecomposeGate([Variable; 10]),

    // inverse to the previous operation: 
    // arguments are the same: [P, P0, P1, P2, P3, Q, Q0, Q1, Q2, Q3]
    // however, this time we assume that (P3, Q3) were defined on the previous row
    PairedComposeGate([Variable; 10]),

    // MixClolumnGadget: arguments are [OUT_P, P0, P1, P2, P3, OUT_Q, Q0, Q1, Q2, Q3]
    // as in PairedComposeGadget we assume that (P3, Q3) were defined on the row
    PairedMixColumnsGate([Variable; 10]),

    // in the final key addition there is no need to update the key:
    // [L, R] is the "state" of Hirose constuction (Left and Right) before goint into AES routine
    // [P_old, P_new, K] are the values of P, Q, right after executing AES and before final key addition
    // [P_new, Q_new] is final hash digest (new value of L, R)
    // the state is : [L, P_old, P_new, R, Q_old, Q_new, K]
    //the transition function are actually the following: 
    // P_new = L + P_old + K
    // Q_new = R + Q_old + K
    WideFinalHashUpdateGate([Variable; 7]),
}


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

            Gate::DecomposeGate(_) => GateType::DecomposeGate,
            Gate::ComposeGate(_) => GateType::ComposeGate,
            Gate::InvSelectorGate(_) => GateType::InvSelectorGate,
            Gate::SubBytesGate(_) => GateType::SubBytesGate,
            Gate::MixColumnsGate(_) => GateType::MixClolumnsGate,
            Gate::RoundKeyAddUpdateGate(_) => GateType::RoundKeyAddUpdateGate,

            Gate::HiroseInitGate(_) => GateType::HiroseInitGate,
            Gate::WideRoundKeyAddUpdateGate(_) => GateType::WideRoundKeyAddUpdateGate,
            Gate::WideComposeDecompose(_) => GateType::WideComposeDecompose,
            Gate::PairedInvSelectorGate(_) => GateType::PairedInvSelectorGate,
            Gate::PairedSubBytesGate(_) => GateType::PairedSubBytesGate,
            Gate::PairedDecomposeGate(_) => GateType::PairedDecomposeGate,
            Gate::PairedComposeGate(_) => GateType::PairedComposeGate,
            Gate::PairedMixColumnsGate(_) => GateType::PairedMixColumnsGate,
            Gate::WideFinalHashUpdateGate(_) => GateType::WideFinalHashUpdateGate,

            _ => unreachable!(),
        };

        res
    }

    pub(crate) fn new_decompose_gate(P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable) -> Self {
        Self::DecomposeGate([P, P0, P1, P2, P3])
    }

    pub(crate) fn new_compose_gate(P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable) -> Self {
        Self::ComposeGate([P, P0, P1, P2, P3])
    }

    pub(crate) fn new_inv_select_gate(x: Variable, x_inv: Variable, flag: Variable, out: Variable) -> Self {
        Self::InvSelectorGate([x, x_inv, flag, out])
    }

    pub(crate) fn new_sub_bytes_gate(x: Variable, x4: Variable, x16: Variable, x64: Variable, out: Variable) -> Self {
        Self::SubBytesGate([x, x4, x16, x64, out])
    }

    pub(crate) fn new_mix_columns_gate(OUT: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable) -> Self {
        Self::MixColumnsGate([OUT, P0, P1, P2, P3])
    }

    pub(crate) fn new_add_update_round_key_gate(
        P_old: Variable, P_new: Variable, K_old: Variable, K_new: Variable, temp: Variable) -> Self {
        
        Self::RoundKeyAddUpdateGate([P_old, P_new, K_old, K_new, temp])
    }

    pub(crate) fn new_hirose_init_gate(
        L0: Variable, L1: Variable, L2: Variable, L3: Variable, 
        R0: Variable, R1: Variable, R2: Variable, R3: Variable,
    ) -> Self {
        Self::HiroseInitGate([L0, L1, L2, L3, R0, R1, R2, R3])
    }

    pub(crate) fn new_wide_round_key_add_update(
        P_old: Variable, Q_old: Variable, K_old: Variable, 
        P_new: Variable, Q_new: Variable, K_new: Variable, 
        K_modifier: Variable
    ) -> Self {
        Self::WideRoundKeyAddUpdateGate([P_old, Q_old, K_old, P_new, Q_new, K_new, K_modifier])
    }

    pub(crate) fn new_wide_compose_decompose_gate(
        P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable
    ) -> Self {
        Self::WideComposeDecompose([P, P0, P1, P2, P3])
    }

    pub(crate) fn new_paired_inv_select_gate(
        x: Variable, x_inv: Variable, flag_x: Variable, out_x: Variable,
        y: Variable, y_inv: Variable, flag_y: Variable, out_y: Variable,
    ) -> Self {
        Self::PairedInvSelectorGate([x, x_inv, flag_x, out_x, y, y_inv, flag_y, out_y])
    } 

    pub(crate) fn new_paired_sub_bytes_gate(
        x: Variable, l1: Variable, l2: Variable, out_x: Variable,
        y: Variable, n1: Variable, n2: Variable, out_y: Variable,
    ) -> Self {
        Self::PairedSubBytesGate([x,l1, l2, out_x, y, n1, n2, out_y])
    }

    pub(crate) fn new_paired_decompose_gate(
        P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable,
        Q: Variable, Q0: Variable, Q1: Variable, Q2: Variable, Q3: Variable
    ) -> Self {
        Self::PairedDecomposeGate([P, P0, P1, P2, P3, Q, Q0, Q1, Q2, Q3])
    }

    pub(crate) fn new_paired_compose_gate(
        P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable,
        Q: Variable, Q0: Variable, Q1: Variable, Q2: Variable, Q3: Variable
    ) -> Self {
        Self::PairedComposeGate([P, P0, P1, P2, P3, Q, Q0, Q1, Q2, Q3])
    }

    pub(crate) fn new_paired_mix_columns_gate(
        OUT_P: Variable, P0: Variable, P1: Variable, P2: Variable, P3: Variable,
        OUT_Q: Variable, Q0: Variable, Q1: Variable, Q2: Variable, Q3: Variable
    ) -> Self {
        Self::PairedMixColumnsGate([OUT_P, P0, P1, P2, P3, OUT_Q, Q0, Q1, Q2, Q3])
    }

    // in the final key addition there is no need to update the key:
    // [L, R] is the "state" of Hirose constuction (Left and Right) before goint into AES routine
    // [P_old, P_new, K] are the values of P, Q, right after executing AES and before final key addition
    // [P_new, Q_new] is final hash digest (new value of L, R)
    // the state is : [L, P_old, P_new, R, Q_old, Q_new, K]
    //the transition function are actually the following: 
    // P_new = L + P_old + K
    // Q_new = R + Q_old + K
    pub(crate) fn new_wide_final_hash_update_gate(
        L: Variable, P_old: Variable, P_new: Variable,
        R: Variable, Q_old: Variable, Q_new: Variable,
        K: Variable
    ) -> Self {
        Self::WideFinalHashUpdateGate([L, P_old, P_new, R, Q_old, Q_new, K])
    }
}