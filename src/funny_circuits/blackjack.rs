void check_blackjack()
{
	unsigned int NUM_OF_CARDS = 52;
	unsigned BITS_PER_CARD = 6;

	std::vector<unsigned> initial_permutation;
	for (unsigned i = 1; i <= NUM_OF_CARDS; i++)
	{
		initial_permutation.emplace_back(i);
	}

	std::random_device rd;
	std::mt19937 g(rd());

	std::vector<unsigned> dealer_shuffle = initial_permutation;
	std::vector<unsigned> player_shuffle = initial_permutation;
	std::shuffle(dealer_shuffle.begin(), dealer_shuffle.end(), g);
	std::shuffle(player_shuffle.begin(), player_shuffle.end(), g);

	std::uniform_int_distribution<unsigned> distribution(0, NUM_OF_CARDS - 1);
	unsigned index = distribution(g);  
	unsigned num = player_shuffle[dealer_shuffle[index]];

	gadget index_gadget = gadget(index, BITS_PER_CARD, true);
	gadget num_gadget = gadget(num, BITS_PER_CARD, true);


	auto convert_shuffle_to_str = [BITS_PER_CARD](const std::vector<unsigned>& vec) -> std::string
	{
		std::string result(vec.size() * BITS_PER_CARD + 1, 'x');
		result[0] = 'b';
		unsigned index = BITS_PER_CARD;
		for (auto elem : vec)
		{
			for (unsigned j = 0; j < BITS_PER_CARD; j++)
			{
				result[index] = (elem % 2 ? '1' : '0');
				elem /= 2;
				index--;
			}
			index += BITS_PER_CARD * 2;
		}
		return result;
	};

	auto dealer_shuffle_str = convert_shuffle_to_str(dealer_shuffle);
	auto player_shuffle_str = convert_shuffle_to_str(player_shuffle);
	gadget dealer_shuffle_str_gadget = gadget(dealer_shuffle_str, NUM_OF_CARDS * BITS_PER_CARD, false);
	gadget player_shuffle_str_gadget = gadget(player_shuffle_str, NUM_OF_CARDS * BITS_PER_CARD, true);

	size_t len = (dealer_shuffle_str.size() - 1) / 8;
	std::string salted_str = std::string(len, 'x');
	for (unsigned i = 0; i < len; i++)
	{
		char c = 0;
		for (unsigned j = 0; j < 8; j++)
		{
			c *= 2;
			c += (dealer_shuffle_str[1 + 8 * i + j] == '1' ? 1 : 0);
		}
		salted_str[i] = c;
	}

	std::string salt_str = "1234";
	std::string hex_digest;
	picosha2::hash256_hex_string(salted_str + salt_str, hex_digest);
	gadget dealer_commitment_gadget(hex_digest, 256, true);
	gadget salt_gadget(0x31323334, 32, false);


	gadget result = blackjack_dealer_proof(num_gadget, index_gadget, dealer_commitment_gadget,
		player_shuffle_str_gadget, dealer_shuffle_str_gadget, salt_gadget, NUM_OF_CARDS, BITS_PER_CARD);

	check(result);
}
