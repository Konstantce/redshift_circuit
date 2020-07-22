use bellman::pairing::{
    Engine,
};
use bellman::{
    SynthesisError,
    ConstraintSystem,
};

use bellman::pairing::ff::{
    Field,
    PrimeField,
};

use common::num::*;
use common::boolean::*;

// the representation of board of size N x N is encoded as a single field element
// which is internally unpacked into N x N matrix of "1" and "0", 
// where "1" stands for composite parts of battleships (or the whole ship in the case of a single-deck ship)
// here is the example encoding of possible board of size 10 x 10 with 4 single-deck ships, 3 double-deck ships,
// 2 3-deck ships and, 1 4-deck ships (which correspon to standard board size and standard number of ships):
// 1010110000
// 0000000000
// 0110101010
// 0000101010
// 1110001010
// 0000100010
// 0000000000
// 0010000000
// 0000000000
// 0000000000

pub struct FriUtilsGadget<E: Engine> {
    // these parameters are changed when passing to next domain
    domain_size: usize,
    log_domain_size: usize,
    omega: E::Fr,
    omega_inv: E::Fr,
    layer: usize,
    first_pass: bool,

    // these parameters are constant for current UtilsGadget
    collapsing_factor: usize,
    wrapping_factor: usize,
    initial_domain_size: usize,
    initial_log_domain_size: usize,
    initial_omega: E::Fr,
    initial_omega_inv: E::Fr,
    coset_factor: E::Fr,
    num_iters: usize,
    two: E::Fr,
    two_inv: E::Fr,
    // remaining data is filled in on the first passing through all layers
    // it is reused on next acess to the same arrays

    // may be it is a dirty Hack(
    // contains inversed generators of the layers
    // simplu to reuse them on each iteration of FRI queries
    constrainted_omega_inv_arr: Vec<AllocatedNum<E>>,
    constrainted_top_level_omega: Option<AllocatedNum<E>>,
    constrainted_bottom_level_omega: Option<AllocatedNum<E>>,
    constrainted_coset_factor: Option<AllocatedNum<E>>,

    _marker: std::marker::PhantomData<E>,
}


impl<E: Engine> FriUtilsGadget<E> {

    pub fn get_domain_size(&self) -> usize {
        self.domain_size
    }

    pub fn get_log_domain_size(&self) -> usize {
        self.log_domain_size
    }

    pub fn get_collapsing_factor(&self) -> usize {
        self.collapsing_factor
    }

    pub fn get_cur_height(&self) -> usize {
        self.log_domain_size - self.collapsing_factor
    }

    pub fn get_coset_factor<CS>(&mut self, mut cs: CS) -> Result<&AllocatedNum<E>, SynthesisError> 

BattleshipGameParams game_params{ 10, 10, 4, 3, 2, 1 };
	const size_t PADDING_LEN = 4; //because 104 divides 8, and the size of battlefield is 100 = 10 x 10

	std::string valid_battlefield = "b"
		;

	std::string first_invalid_battlefield = "b"
		"1010110000"
		"0000000000"
		"0110101000"
		"0000101000"
		"1110001000"
		"0000100000"
		"0110000000"
		"0000111100"
		"0000000000"
		"0000000000";

	std::string second_invalid_battlefield = "b"
		"1010110000"
		"0000000000"
		"0110101010"
		"0000101000"
		"1110001000"
		"0000100000"
		"0001000000"
		"0001000000"
		"0001000000"
		"0001000000";

	std::string str_refs[3] = {valid_battlefield, first_invalid_battlefield,
		second_invalid_battlefield };

	auto str_converter = [](const std::string& str) -> std::string
	{
		size_t len = (str.size() - 1) / 8;
		std::string result = std::string(len, 'x');
		for (unsigned i = 0; i < len; i++)
		{
			char c = 0;
			for (unsigned j = 0; j < 8; j++)
			{
				c *= 2;
				c += (str[1 + 8 * i + j] == '1' ? 1 : 0);
			}
			result[i] = c;
		}
		return result;
	};

	for (auto& str_elem : str_refs)
	{
		gadget battlefield(str_elem, 10 * 10, false);
		
		std::string salt_str = str_converter(str_elem + std::string(PADDING_LEN, '0')) + "1234";
		std::string hex_digest;
		picosha2::hash256_hex_string(salt_str, hex_digest);
		gadget public_hash(hex_digest, 256, true);
		gadget salt(0x31323334, 32, false);
		gadget comparison = start_battleship_game(battlefield, salt, public_hash,
			game_params, PADDING_LEN);

		check(comparison);
	}