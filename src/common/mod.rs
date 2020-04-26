pub mod boolean;
pub mod multieq;
pub mod uint32;
pub mod num;
pub mod lookup;
pub mod multipack;


use bellman::{
    SynthesisError,
    Engine,
    ConstraintSystem
};

pub trait Assignment<T> {
    fn get(&self) -> Result<&T, SynthesisError>;
}

impl<T> Assignment<T> for Option<T> {
    fn get(&self) -> Result<&T, SynthesisError> {
        match *self {
            Some(ref v) => Ok(v),
            None => Err(SynthesisError::AssignmentMissing)
        }
    }
}

pub fn log2_floor(num: usize) -> usize {
    assert!(num > 0);
    let mut pow: usize = 0;

    while (1 << (pow+1)) <= num {
        pow += 1;
    }
    pow
}

pub fn find_by_label<X: Clone>(label: Label, arr: &Vec<Labeled<X>>) -> Result<X, SynthesisError> {

    arr.iter().find(|elem| elem.label == label).map(|elem| elem.data.clone()).ok_or(SynthesisError::Unknown)
}

// TODO: better replace by tag = ENUM
pub type Label = &'static str;

pub type OracleHeight = usize;
pub type CosetSize = usize;

pub struct Labeled<T> {
    pub label: Label,
    pub data: T,
}

impl<T> Labeled<T> {
    pub fn new(label: Label, data: T) -> Self {
        Labeled {label, data}
    }
}

pub type LabeledVec<T> = Vec<Labeled<T>>;


pub trait FromStream<E: Engine, SPP> : Sized {

    fn from_stream<CS, I>(cs: CS, iter: &mut I, params : SPP) -> Result<Self, SynthesisError> 
    where CS: ConstraintSystem<E>, I: Iterator<Item = Option<E::Fr>>;
}


impl<E: Engine, T: FromStream<E, ()>> FromStream<E, (usize)> for Vec<T> {
    fn from_stream<CS: ConstraintSystem<E>, I: Iterator<Item = Option<E::Fr>>>(
        mut cs: CS,
        iter: &mut I,
        count: usize,
    ) -> Result<Self, SynthesisError> 
    {
        let arr : Result<Vec<_>, _> = (0..count).map(|_| { 
            let e = T::from_stream(cs.namespace(|| ""), iter, () );
            e
        }).collect();
        arr
    }
}
