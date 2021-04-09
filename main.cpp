// main.cpp
#include <string>
#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <memory>
#include <vector>
#include <iomanip> // remove
#include <bitset> // remove
#include <iostream> // remove after debugging
#include <array>
#include <fstream>
#include <string>

constexpr std::size_t hash_size = { 8ULL };

typedef std::uint8_t byte_t;
typedef std::array<std::uint32_t, hash_size> hash_values_t;

constexpr static byte_t one_shifted{ 1 << 7 };
constexpr static std::size_t long_int_size{ sizeof(std::uint64_t) };

// first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19
constexpr static hash_values_t start_hash_values =
{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311
constexpr static std::uint32_t round_constants[] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
/*
// todo: check T
template <typename T>
class SelfDeletingPtr
{
private:
	T* ptr{nullptr};
public:
	SelfDeletingPtr() : ptr(nullptr) {}
	explicit SelfDeletingPtr(T&& obj)
	{
		ptr = new T{std::forward<T>(obj)}; // todo: check for proper constructor
	}
	SelfDeletingPtr(const SelfDeletingPtr&) = delete;
	SelfDeletingPtr(SelfDeletingPtr&& obj) noexcept
	{
		release();
		ptr = std::move(obj.ptr);
		obj.ptr = nullptr;
	}
	~SelfDeletingPtr()
	{
		release();
	}
	SelfDeletingPtr& operator=(const SelfDeletingPtr&) = delete;
	SelfDeletingPtr& operator=(SelfDeletingPtr&&) noexcept
	{
		release();
		ptr = std::move(obj.ptr);
		obj.ptr = nullptr;
	}
	void release()
	{
		if (ptr != nullptr)
		{
			delete ptr;
			ptr = nullptr;
		}
	}
}*/

// todo: do better, faster!
void str_to_byte_array(const std::string& str, std::vector<byte_t>& ba)
{
	size_t str_len = str.length();
	if (str_len > ba.size())
	{
		throw std::runtime_error("Passed byte array is too small.");
	}
	for (size_t i = 0; i < str_len; ++i)
	{
		ba[i] = static_cast<byte_t>(str[i]);
	}
}

template <typename T>
constexpr T rotl(T value, std::size_t count)
{
    constexpr std::size_t mask = CHAR_BIT * sizeof(T) - 1;
    count &= mask;
    return (value << count) | (value >> (-count & mask));
}

template <typename T>
constexpr T rotr(T value, std::size_t count)
{
    constexpr std::size_t mask = CHAR_BIT * sizeof(T) - 1;
    count &= mask;
    return (value >> count) | (value << (-count & mask));
}

template <typename T>
constexpr T to_int(byte_t* bytes)
{
    constexpr std::size_t nbytes = sizeof(T);
    T result = 0;
    for (std::size_t i = 0; i < nbytes; ++i)
    {
        result |= static_cast<T>(*(bytes + i)) << (3ULL - i) * 8;
    }
    return result;
}

hash_values_t sha256(const std::string& str)
{
	size_t i, j, k;
	const size_t str_len = str.length();
	const size_t padded_len = (((str_len + 8) >> 6/* str_len in bits / 512 */) + 1) << 6; // todo: check formula
	const size_t nchunks = padded_len >> 6;
	std::vector<byte_t> padded(padded_len, 0);
	str_to_byte_array(str, padded);
	padded[str_len] = one_shifted;
	std::uint64_t original_bit_len = str_len << 3 /* x8 */;
	size_t start_offset = 4; // todo: use constexpr init? -> use lambda!
	if constexpr (long_int_size == 8)
	{
		start_offset = 8;
	}
	for (i = padded_len - start_offset, j = 7; i < padded_len; ++i, --j)
	{
		padded[i] = static_cast<byte_t>(original_bit_len >> (j * 8));
	}
	// create message schedule
	// split padded into 512-bit-blocks (32bit each)
	std::vector<std::vector<std::uint32_t>> chunks(nchunks);
	j = 0;
	std::uint32_t s0, s1, ch, maj, temp1, temp2;
	std::uint32_t a, b, c, d, e, f, g, h;
	hash_values_t hash_values = start_hash_values;
	for (i = 0; i < nchunks; ++i)
	{
		auto& chunk = chunks[i];
		chunk.reserve(64);
		for (k = 0;j < /*64 / 4 = 16 -> i * 16*/ ((i + 1) << 4); ++j, ++k)
		{
			chunk.emplace_back(to_int<std::uint32_t>(&padded[j<<2]));
		}
		// initialize the remaining 48 32bits with zeros
		chunk.insert(chunk.cend(), 48, 0);
		// modification of the zero-ed
		for (k = 16; k < 64; ++k)
		{
			s0 = rotr(chunk[k-15], 7) ^ rotr(chunk[k-15], 18) ^ (chunk[k-15] >> 3);
			s1 = rotr(chunk[k-2], 17) ^ rotr(chunk[k-2], 19) ^ (chunk[k-2] >> 10);
			chunk[k] = chunk[k-16] + s0 + chunk[k-7] + s1;
		}
		// compression
		a = hash_values[0];
		b = hash_values[1];
		c = hash_values[2];
		d = hash_values[3];
		e = hash_values[4];
		f = hash_values[5];
		g = hash_values[6];
		h = hash_values[7];
		for (k = 0; k < 64; ++k)
		{
			s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			ch = (e & f) ^ ((~e) & g);
			temp1 = h + s1 + ch + round_constants[k] + chunk[k];
			s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			maj = (a & b) ^ (a & c) ^ (b & c);
			temp2 = s0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		// modify hash values
		hash_values[0] += a;
		hash_values[1] += b;
		hash_values[2] += c;
		hash_values[3] += d;
		hash_values[4] += e;
		hash_values[5] += f;
		hash_values[6] += g;
		hash_values[7] += h;
	}
	return hash_values;
}

int main(const int argc, const char** argv)
{
	if (argc < 2)
	{
		std::cerr << "Filename missing.\n";
		return -1;
	}
	const std::string filename{ argv[1] };
	std::string message{};
	std::fstream file;
	bool check = false;
	std::clog << "opening " << filename << " ...\n";
	if (argc > 2 && (std::strcmp(argv[2], "-c") || std::strcmp(argv[2], "--check")))
	{
		check = true;
		file.open(filename, std::ios_base::in | std::ios_base::binary);
	}
	else
	{
		file.open(filename, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
	}
	if (file.fail())
	{
		std::cerr << "Failed opening " << filename << ".\n";
		return -2;
	}
	std::cout << "Enter message: ";
	std::getline(std::cin, message);
	std::clog << "calculating hash values ...\n";
	hash_values_t hash = sha256(message);
	if (check)
	{
		std::clog << "reading from " << filename << " ...\n";
		hash_values_t cmp_hash;
		file.read(reinterpret_cast<char*>(&cmp_hash), hash_size * sizeof(std::uint32_t));
		if (file.fail() || file.bad())
		{
			std::cerr << "Error while reading from " << filename << ".\n";
			if (file.is_open())
			{
				file.close();
			}
			return -3;
		}
		if (hash == cmp_hash)
		{
			std::cout << "Correct!\n";
		}
		else
		{
			std::cout << "Not correct!\n";
		}
	}
	else
	{
		std::clog << "writing to " << filename << " ...\n";
		file.write(reinterpret_cast<const char*>(&hash[0]), hash_size * sizeof(std::uint32_t));
	}
	file.close();
	
	return 0;
}
