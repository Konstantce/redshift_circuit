use super::*;

use std::collections::HashMap;
use std::fmt::Write;
use std::collections::HashSet;


#[derive(Debug)]
enum NamedObject {
    Constraint(usize),
    Var(Variable),
    Namespace
}

/// Constraint system for testing purposes.
pub struct NamingDependentConstraintSystem<E: Engine> {
    named_objects: HashMap<String, NamedObject>,
    current_namespace: Vec<String>,
    constraints: Vec<(
        LinearCombination<E>,
        LinearCombination<E>,
        LinearCombination<E>,
        String
    )>,
    inputs: Vec<(E::Fr, String)>,
    aux: Vec<(E::Fr, String)>
}

impl<E: Engine> NamingDependentConstraintSystem<E> {
    pub fn new() -> NamingDependentConstraintSystem<E> {
        let mut map = HashMap::new();
        map.insert("ONE".into(), NamedObject::Var(NamingDependentConstraintSystem::<E>::one()));

        NamingDependentConstraintSystem {
            named_objects: map,
            current_namespace: vec![],
            constraints: vec![],
            inputs: vec![(E::Fr::one(), "ONE".into())],
            aux: vec![]
        }
    }

    pub fn pretty_print(&self) -> String {
        let mut s = String::new();

        let negone = {
            let mut tmp = E::Fr::one();
            tmp.negate();
            tmp
        };

        let powers_of_two = (0..E::Fr::NUM_BITS).map(|i| {
            E::Fr::from_str("2").unwrap().pow(&[i as u64])
        }).collect::<Vec<_>>();

        let pp = |s: &mut String, lc: &LinearCombination<E>| {
            write!(s, "(").unwrap();
            let mut is_first = true;
            for (var, coeff) in proc_lc::<E>(lc.as_ref()) {
                if coeff == negone {
                    write!(s, " - ").unwrap();
                } else if !is_first {
                    write!(s, " + ").unwrap();
                }
                is_first = false;

                if coeff != E::Fr::one() && coeff != negone {
                    for (i, x) in powers_of_two.iter().enumerate() {
                        if x == &coeff {
                            write!(s, "2^{} . ", i).unwrap();
                            break;
                        }
                    }

                    write!(s, "{} . ", coeff).unwrap();
                }

                match var.0.get_unchecked() {
                    Index::Input(i) => {
                        write!(s, "`{}`", &self.inputs[i].1).unwrap();
                    },
                    Index::Aux(i) => {
                        write!(s, "`{}`", &self.aux[i].1).unwrap();
                    }
                }
            }
            if is_first {
                // Nothing was visited, print 0.
                write!(s, "0").unwrap();
            }
            write!(s, ")").unwrap();
        };

        for &(ref a, ref b, ref c, ref name) in &self.constraints {
            write!(&mut s, "\n").unwrap();

            write!(&mut s, "{}: ", name).unwrap();
            pp(&mut s, a);
            write!(&mut s, " * ").unwrap();
            pp(&mut s, b);
            write!(&mut s, " = ").unwrap();
            pp(&mut s, c);
        }

        write!(&mut s, "\n").unwrap();

        s
    }

    pub fn find_unconstrained(&self) -> String {
        let mut s = String::new();
        let pp = |hm: & mut HashSet<String>, lc: &LinearCombination<E>| {
            for (var, coeff) in proc_lc::<E>(lc.as_ref()) {
                match var.0.get_unchecked() {
                    Index::Input(i) => {
                        let v = self.inputs[i].clone();
                        hm.insert(v.1);
                    },
                    Index::Aux(i) => {
                        let v = self.aux[i].clone();
                        hm.insert(v.1);
                    }
                }
            }
        };

        let i_max = self.constraints.len();

        let mut set = HashSet::new();
        for &(ref a, ref b, ref c, ref _name) in &self.constraints {

            pp(&mut set, a);
            pp(&mut set, b);
            pp(&mut set, c);
        }

        for inp in self.inputs.iter() {
            if set.get(&inp.1).is_none() {
                write!(&mut s, "\n").unwrap();
                write!(&mut s, "{}", inp.1).unwrap();
                write!(&mut s, "\n").unwrap();
            }
        }

        for inp in self.aux.iter() {
            if set.get(&inp.1).is_none() {
                write!(&mut s, "\n").unwrap();
                write!(&mut s, "{}", inp.1).unwrap();
                write!(&mut s, "\n").unwrap();
            }
        }

        s
    }

    pub fn hash(&self) -> String {
        let mut h = Blake2s::new(32);
        {
            let mut buf = [0u8; 24];

            BigEndian::write_u64(&mut buf[0..8], self.inputs.len() as u64);
            BigEndian::write_u64(&mut buf[8..16], self.aux.len() as u64);
            BigEndian::write_u64(&mut buf[16..24], self.constraints.len() as u64);
            h.update(&buf);
        }

        for constraint in &self.constraints {
            hash_lc::<E>(constraint.0.as_ref(), &mut h);
            hash_lc::<E>(constraint.1.as_ref(), &mut h);
            hash_lc::<E>(constraint.2.as_ref(), &mut h);
        }

        let mut s = String::new();
        for b in h.finalize().as_ref() {
            s += &format!("{:02x}", b);
        }

        s
    }

    pub fn which_is_unsatisfied(&self) -> Option<&str> {
        for &(ref a, ref b, ref c, ref path) in &self.constraints {
            let mut a = eval_lc::<E>(a.as_ref(), &self.inputs, &self.aux);
            let b = eval_lc::<E>(b.as_ref(), &self.inputs, &self.aux);
            let c = eval_lc::<E>(c.as_ref(), &self.inputs, &self.aux);

            a.mul_assign(&b);

            if a != c {
                return Some(&*path)
            }
        }

        None
    }

    pub fn is_satisfied(&self) -> bool
    {
        self.which_is_unsatisfied().is_none()
    }

    pub fn num_constraints(&self) -> usize
    {
        self.constraints.len()
    }

    pub fn set(&mut self, path: &str, to: E::Fr)
    {
        match self.named_objects.get(path) {
            Some(&NamedObject::Var(ref v)) => {
                match v.get_unchecked() {
                    Index::Input(index) => self.inputs[index].0 = to,
                    Index::Aux(index) => self.aux[index].0 = to
                }
            }
            Some(e) => panic!("tried to set path `{}` to value, but `{:?}` already exists there.", path, e),
            _ => panic!("no variable exists at path: {}", path)
        }
    }

    pub fn verify(&self, expected: &[E::Fr]) -> bool
    {
        assert_eq!(expected.len() + 1, self.inputs.len());

        for (a, b) in self.inputs.iter().skip(1).zip(expected.iter())
        {
            if &a.0 != b {
                return false
            }
        }

        return true;
    }

    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    pub fn get_input(&mut self, index: usize, path: &str) -> E::Fr
    {
        let (assignment, name) = self.inputs[index].clone();

        assert_eq!(path, name);

        assignment
    }

    pub fn get(&mut self, path: &str) -> E::Fr
    {
        match self.named_objects.get(path) {
            Some(&NamedObject::Var(ref v)) => {
                match v.get_unchecked() {
                    Index::Input(index) => self.inputs[index].0,
                    Index::Aux(index) => self.aux[index].0
                }
            }
            Some(e) => panic!("tried to get value of path `{}`, but `{:?}` exists there (not a variable)", path, e),
            _ => panic!("no variable exists at path: {}", path)
        }
    }

    fn set_named_obj(&mut self, path: String, to: NamedObject) {
        if self.named_objects.contains_key(&path) {
            panic!("tried to create object at existing path: {}", path);
        }

        self.named_objects.insert(path, to);
    }
}

impl<E: Engine> ConstraintSystem<E> for NamingDependentConstraintSystem<E> {
    type Root = Self;

    fn alloc<F, A, AR>(
        &mut self,
        annotation: A,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        let index = self.aux.len();
        let path = compute_path(&self.current_namespace, annotation().into());
        self.aux.push((f()?, path.clone()));
        let var = Variable::new_unchecked(Index::Aux(index));
        self.set_named_obj(path, NamedObject::Var(var));

        Ok(var)
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        annotation: A,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        let index = self.inputs.len();
        let path = compute_path(&self.current_namespace, annotation().into());
        self.inputs.push((f()?, path.clone()));
        let var = Variable::new_unchecked(Index::Input(index));
        self.set_named_obj(path, NamedObject::Var(var));

        Ok(var)
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
        let path = compute_path(&self.current_namespace, annotation().into());
        let index = self.constraints.len();
        self.set_named_obj(path.clone(), NamedObject::Constraint(index));

        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        self.constraints.push((a, b, c, path));
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where NR: Into<String>, N: FnOnce() -> NR
    {
        let name = name_fn().into();
        let path = compute_path(&self.current_namespace, name.clone());
        self.set_named_obj(path.clone(), NamedObject::Namespace);
        self.current_namespace.push(name);
    }

    fn pop_namespace(&mut self)
    {
        assert!(self.current_namespace.pop().is_some());
    }

    fn get_root(&mut self) -> &mut Self::Root
    {
        self
    }
}

#[test]
fn test_cs() {
    use bellman::pairing::bls12_381::{Bls12, Fr};
    use bellman::pairing::ff::PrimeField;

    let mut cs = NamingDependentConstraintSystem::<Bls12>::new();
    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 0);
    let a = cs.namespace(|| "a").alloc(|| "var", || Ok(Fr::from_str("10").unwrap())).unwrap();
    let b = cs.namespace(|| "b").alloc(|| "var", || Ok(Fr::from_str("4").unwrap())).unwrap();
    let c = cs.alloc(|| "product", || Ok(Fr::from_str("40").unwrap())).unwrap();

    cs.enforce(
        || "mult",
        |lc| lc + a,
        |lc| lc + b,
        |lc| lc + c
    );
    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 1);

    cs.set("a/var", Fr::from_str("4").unwrap());

    let one = NamingDependentConstraintSystem::<Bls12>::one();
    cs.enforce(
        || "eq",
        |lc| lc + a,
        |lc| lc + one,
        |lc| lc + b
    );

    assert!(!cs.is_satisfied());
    assert!(cs.which_is_unsatisfied() == Some("mult"));

    assert!(cs.get("product") == Fr::from_str("40").unwrap());

    cs.set("product", Fr::from_str("16").unwrap());
    assert!(cs.is_satisfied());

    {
        let mut cs = cs.namespace(|| "test1");
        let mut cs = cs.namespace(|| "test2");
        cs.alloc(|| "hehe", || Ok(Fr::one())).unwrap();
    }

    assert!(cs.get("test1/test2/hehe") == Fr::one());
}
