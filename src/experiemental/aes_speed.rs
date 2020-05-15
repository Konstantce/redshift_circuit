
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;
use crate::lazy_static;
use bellman::multicore::*;


lazy_static! {
    static ref IV : [u8; 16] = [201, 188, 213, 95, 239, 147, 188, 147, 229, 63, 10, 70, 95, 120, 76, 255];
}

pub type BLOCK = [u8; 16];
pub type ELEM = (BLOCK, BLOCK);


struct AesHasher
{
    state: BLOCK,
}

impl AesHasher 
{
    pub fn new() -> Self {
        AesHasher {
            state: IV.clone(),
        }
    }

    pub fn absorb(&mut self, input: &[u8; 16]) 
    {
        let key = GenericArray::from_slice(input);
        let mut block = GenericArray::clone_from_slice(&self.state);
        let cipher = Aes128::new(&key);

        // Encrypt block in-place
        cipher.encrypt_block(&mut block);

        for (a, b) in self.state.iter_mut().zip(block) {
            *a ^= b;
        }
    }

    pub fn squeeze(self) -> [u8; 16]
    {
        self.state
    }
}
    

pub struct AES256Tree {
    pub size: usize,
    pub values_per_leaf: usize,
    pub nodes: Vec<BLOCK>,
}


impl AES256Tree {
    
    fn hash_into_leaf(values: &[ELEM]) -> BLOCK {
        let mut hasher = AesHasher::new();
        for (low, high) in values.iter() {
            hasher.absorb(low);
            hasher.absorb(high)
        }
        hasher.squeeze()
    }

    pub fn log2_floor(num: usize) -> u32 {
        assert!(num > 0);

        let mut pow = 0;

        while (1 << (pow+1)) <= num {
            pow += 1;
        }

        pow
    }

    fn size(&self) -> usize {
        self.size
    }

    fn create(values: &[ELEM], size: usize, values_per_leaf: usize) -> Self {

        assert!(values_per_leaf.is_power_of_two());
        assert!(values.len() == size * values_per_leaf);

        let num_nodes = size;
        let mut nodes = vec![BLOCK::default(); num_nodes];

        let worker = Worker::new();
        let mut leaf_hashes = vec![BLOCK::default(); num_nodes];
        {
            worker.scope(leaf_hashes.len(), |scope, chunk| {
                for (i, lh) in leaf_hashes.chunks_mut(chunk)
                                .enumerate() {
                    scope.spawn(move |_| {
                        let base_idx = i*chunk;
                        for (j, lh) in lh.iter_mut().enumerate() {
                            let idx = base_idx + j;
                            let values_start = idx * values_per_leaf;
                            let values_end = values_start + values_per_leaf;
                            *lh = Self::hash_into_leaf(&values[values_start..values_end]);
                        }
                    });
                }
            });
        }

        // leafs are now encoded and hashed, so let's make a tree

        let num_levels = Self::log2_floor(num_nodes) as usize;
        let mut nodes_for_hashing = &mut nodes[..];

        // separately hash last level, which hashes leaf hashes into first nodes
        {
            let _level = num_levels-1;
            let inputs = &mut leaf_hashes[..];
            let (_, outputs) = nodes_for_hashing.split_at_mut(nodes_for_hashing.len()/2);
            assert!(outputs.len() * 2 == inputs.len());
            assert!(outputs.len().is_power_of_two());

            worker.scope(outputs.len(), |scope, chunk| {
                for (o, i) in outputs.chunks_mut(chunk)
                                .zip(inputs.chunks(chunk*2)) {
                    scope.spawn(move |_| {
                        for (o, i) in o.iter_mut().zip(i.chunks(2)) {
                            let mut hasher = AesHasher::new();
                            hasher.absorb(&i[0]);
                            hasher.absorb(&i[1]);
                            *o = hasher.squeeze();
                        }
                    });
                }
            });
        }

        for _ in (0..(num_levels-1)).rev() {
            // do the trick - split
            let (next_levels, inputs) = nodes_for_hashing.split_at_mut(nodes_for_hashing.len()/2);
            let (_, outputs) = next_levels.split_at_mut(next_levels.len() / 2);
            assert!(outputs.len() * 2 == inputs.len());
            assert!(outputs.len().is_power_of_two());

            worker.scope(outputs.len(), |scope, chunk| {
                for (o, i) in outputs.chunks_mut(chunk)
                                .zip(inputs.chunks(chunk*2)) {
                    scope.spawn(move |_| {
                        for (o, i) in o.iter_mut().zip(i.chunks(2)) {
                            let mut hasher = AesHasher::new();
                            hasher.absorb(&i[0]);
                            hasher.absorb(&i[1]);
                            *o = hasher.squeeze();
                        }
                    });
                }
            });

            nodes_for_hashing = next_levels;
        }

        Self {
            size: size,
            values_per_leaf: values_per_leaf,
            nodes: nodes,
        }
    }
}


#[test]
fn test_aes_tree() {

    use std::time::{Duration, Instant};
    use rand::{XorShiftRng, SeedableRng, Rand, Rng};

    const SIZE: usize = 1048576;
    const VALUES_PER_LEAF: usize = 4;

    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let values : Vec<ELEM> = (0..(SIZE * VALUES_PER_LEAF)).map(|_| {
        ELEM::rand(rng)
    }).collect();

    let now = Instant::now();
    let tree = AES256Tree::create(&values[..], SIZE, VALUES_PER_LEAF);

    println!("AES MerkleTreeConstruction of size {} took {}s", SIZE, now.elapsed().as_secs());
}