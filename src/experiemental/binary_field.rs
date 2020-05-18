#[cfg(all(feature="simd", target_arch="x86_64"))]
use std::arch::x86_64;

use crate::bellman::pairing::ff::Field;

use std::error::Error;
use std::fmt;
use std::mem;
use std::io::{self, Read, Write};

extern crate byteorder;
extern crate rand;

use crate::num_bigint::BigUint;


#[derive(Debug)]
pub struct BitIterator<E> {
    t: E,
    n: usize,
}

impl<E: AsRef<[u64]>> BitIterator<E> {
    pub fn new(t: E) -> Self {
        let n = t.as_ref().len() * 64;

        BitIterator { t, n }
    }
}

impl<E: AsRef<[u64]>> Iterator for BitIterator<E> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            let part = self.n / 64;
            let bit = self.n - (64 * part);

            Some(self.t.as_ref()[part] & (1 << bit) > 0)
        }
    }
}


#[derive(Debug)]
pub struct BitView<'a, E> {
    arr: &'a mut E,
    pos: usize,
    block_size: usize,
}

impl<'a, E: AsMut<[u32]>> BitView<'a, E> {
    pub fn new(t: &'a mut E) -> Self {
        
        let block_size : usize = 32;
        let pos = t.as_mut().len() * block_size - 1;
        BitView{
            arr: t, 
            pos, 
            block_size,
        }
    }

    pub fn next_one_pos(&mut self) -> Option<usize> {

        let mut block = self.pos / self.block_size;
        let mut bit = self.pos % self.block_size;
        let mut found = false;

        while !found {
            if (self.arr.as_mut()[block] >> bit) & 1 != 0 {
                found = true
            }
            else {
                match bit {
                    0 => {
                        if block > 0 {
                            block -= 1;
                            bit = 31;
                        }
                        else {
                            break;
                        }
                    }
                    _ => bit -= 1
                }
            }
        }

        let res = match found {
            false => None,
            true => Some(block * self.block_size + bit),
        };

        res
    }

    pub fn toggle_bit_at_pos(&mut self, pos: usize) {
        let block = pos / self.block_size;
        let bit = pos % self.block_size;
        self.arr.as_mut()[block] ^= 1 << bit;
    }
}

// Galois field(2^128) with generator poly f(x)=x^{128}+x^{77}+x^{35}+x^{11}+1
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq)]
pub struct BinaryField128
{
    repr: [u32; 4],
}


impl ::std::fmt::Debug for BinaryField128
{
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "0x")?;
        for i in self.repr.iter().rev() {
            write!(f, "{:016x}", *i)?;
        }

        Ok(())
    }
}

impl ::rand::Rand for BinaryField128 {
    #[inline(always)]
    fn rand<R: ::rand::Rng>(rng: &mut R) -> Self {
        BinaryField128{ repr: rng.gen()}
    }
}

impl ::std::fmt::Display for BinaryField128 {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "0b")?;
        for i in self.repr.iter().rev() {
            write!(f, "{:032b}", *i)?;
        }

        Ok(())
    }
}


impl BinaryField128 {

    pub fn num_bits(&self) -> u32 {
        128
    }

    pub fn capacity(&self) -> u32 {
        128
    }

    /// Writes this `PrimeFieldRepr` as a big endian integer.
    pub fn write_be<W: Write>(&self, mut writer: W) -> io::Result<()> {
        use byteorder::{BigEndian, WriteBytesExt};

        for digit in self.repr.as_ref().iter().rev() {
            writer.write_u32::<BigEndian>(*digit)?;
        }

        Ok(())
    }

    /// Reads a big endian integer into this representation.
    pub fn read_be<R: Read>(&mut self, mut reader: R) -> io::Result<()> {
        use byteorder::{BigEndian, ReadBytesExt};

        for digit in self.repr.as_mut().iter_mut().rev() {
            *digit = reader.read_u32::<BigEndian>()?;
        }

        Ok(())
    }

    /// Writes this `PrimeFieldRepr` as a little endian integer.
    pub fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        use byteorder::{LittleEndian, WriteBytesExt};

        for digit in self.repr.as_ref().iter() {
            writer.write_u32::<LittleEndian>(*digit)?;
        }

        Ok(())
    }

    /// Reads a little endian integer into this representation.
    pub fn read_le<R: Read>(&mut self, mut reader: R) -> io::Result<()> {
        use byteorder::{LittleEndian, ReadBytesExt};

        for digit in self.repr.as_mut().iter_mut() {
            *digit = reader.read_u32::<LittleEndian>()?;
        }

        Ok(())
    }
  
    pub fn from_repr(repr: [u32; 4]) -> Self {
        Self { repr }
    }

    pub fn into_repr(&self) -> [u32; 4] {
        self.repr.clone()
    }

    pub fn from_byte_repr(byte_repr: [u8; 16]) -> Self {
        let mut repr : [u32; 4] = [0; 4];
        for (input, output) in byte_repr.chunks(4).zip(repr.iter_mut()) {
            let mut temp : [u8; 4] = [0; 4];
            
            // it's Rust, and is is far from being perfect
            for (x, y) in input.iter().zip(temp.iter_mut()) {
                *y = *x;
            }

            *output = unsafe { 
                std::mem::transmute::<[u8; 4], u32>(temp) 
            }.to_le()
        }
        Self {repr}
    }

    pub fn into_byte_repr(&self) -> [u8; 16] {
        let mut byte_repr : [u8; 16] = [0; 16];
        for (input, output) in self.repr.iter().zip(byte_repr.chunks_mut(4)) {
            let temp = unsafe { 
                std::mem::transmute::<u32, [u8; 4]>(input.to_le()) 
            };
            output.clone_from_slice(&temp);
        }
        byte_repr
    }
}


unsafe fn add_ptr_len(
    dst: *mut u64,
    src: *const u64,
    num_limbs: usize
) {
    for i in 0..num_limbs {
        let dst_ptr = dst.offset(i as isize);
        let src_ptr = src.offset(i as isize);
        *dst_ptr ^= *src_ptr;
    }
}


impl Field for BinaryField128 {

    fn zero() -> Self {
        Self { repr : [0, 0, 0, 0]}
    }

    fn one() -> Self {
        Self { repr : [1, 0, 0, 0]}
    }

    /// Returns true iff this element is zero.
    fn is_zero(&self) -> bool {
        self.repr.iter().all(|x| *x == 0)
    }

    /// Squares this element.
    fn square(&mut self) {
        let temp = self.clone();
        self.mul_assign(&temp);
    }

    /// Doubles this element.
    fn double(&mut self) {
        let temp = self.clone();
        self.add_assign(&temp);
    }

    /// Negates this element.
    fn negate(&mut self) {
        //do nothing
    }

    /// Adds another element to this element.
    fn add_assign(&mut self, other: &Self) {
        for (a, b) in self.repr.iter_mut().zip(other.repr.iter()) {
            *a ^= b;
        }
    }

    /// Subtracts another element from this element.
    fn sub_assign(&mut self, other: &Self) {
        self.add_assign(other)
    }

    /// Multiplies another element by this element.
    fn mul_assign(&mut self, other: &Self) {

        if self.is_zero() || other.is_zero()
        {
            *self = Self::zero();
            return;
        }

        // we are working in standard polynomial basis
        let mut raw_res = [0u32; 8];
        let left = BigUint::from_slice(&self.repr[..]);
        let right = BigUint::from_slice(&other.repr[..]);
        let int_res = left * right;
        let res_bytes = int_res.to_bytes_le();

        for (output, input) in raw_res.iter_mut().zip(res_bytes.chunks(4))
        {
            *output = input[0] as u32 + ((input[1] as u32) << 8) + ((input[2] as u32) << 16) + ((input[3] as u32) << 24);
        }

        {
            // recall that out generator polynomial is f(x)=x^{128}+x^{77}+x^{35}+x^{11}+1
            // corresponding distance betrween nearby indexes are 128 - 77 = 51, 77-35=42, 35-11=24, 11-1=10

            let mut bit_view = BitView::new(&mut raw_res);
            let mut high_bit_pos = bit_view.next_one_pos().unwrap();

            while high_bit_pos >= 128 {
                let mut cur_pos = high_bit_pos;
                bit_view.toggle_bit_at_pos(cur_pos);

                for diff in [51usize, 42usize, 24usize, 10usize].iter() {
                    cur_pos -= diff;
                    bit_view.toggle_bit_at_pos(cur_pos);
                }

                high_bit_pos = bit_view.next_one_pos().unwrap();
            }
        }
        
        self.repr.copy_from_slice(&raw_res[0..4]);
    }

    /// Exponentiates this element by a power of the base prime modulus via
    /// the Frobenius automorphism.
    fn frobenius_map(&mut self, power: usize) {
        unimplemented!();
    }

    /// Computes the multiplicative inverse of this element, if nonzero.
    fn inverse(&self) -> Option<Self> {
        let res = match self.is_zero() {
            true => None,
            false => {
                // cardinality of multiplicative subgroup is 2^n - 1 
                // to get inverse of alpha raise to 2^n - 2
                
                let exp = [0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];
                Some(self.pow(&exp))
            },
        };

        res
    }

    /// Exponentiates this element by a number represented with `u64` limbs,
    /// least significant digit first.
    fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        let mut res = Self::one();

        let mut found_one = false;

        for i in BitIterator::new(exp) {
            if found_one {
                res.square();
            } else {
                found_one = i;
            }

            if i {
                res.mul_assign(self);
            }
        }

        res
    }
}








