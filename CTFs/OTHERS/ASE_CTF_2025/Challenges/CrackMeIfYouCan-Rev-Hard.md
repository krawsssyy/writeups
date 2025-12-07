# Building and necessary packages

Password cracking challenge, with a highly obfuscated binary.
The given password is cross-checked via a given hash (SHA256 then RC4 encrypted). The solution stands in using rockyou.txt for cracking the password.

# Main challenge code - main.cpp

```C++
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <cstring>

static std::string toHexLower(const std::vector<unsigned char>& bytes) {
	std::ostringstream oss;
	oss.setf(std::ios::hex, std::ios::basefield);
	oss << std::nouppercase << std::setfill('0');
	for (unsigned char b : bytes) {
		oss << std::setw(2) << static_cast<int>(b);
	}
	return oss.str();
}

// Junk helpers
static inline __attribute__((always_inline)) uint32_t junk_rot(uint32_t x) { return (x << 3) | (x >> 29); }
static inline __attribute__((always_inline)) uint32_t junk_affine(uint32_t x) { return x * 2654435761u + 0x9e3779b9u; }
static inline __attribute__((always_inline)) uint32_t junk_sbox(uint32_t x) { x ^= (x >> 13); x *= 0x85ebca6bu; x ^= (x >> 16); return x; }
static inline __attribute__((always_inline)) uint32_t junk_noise(uint32_t a, uint32_t b) { return (a ^ junk_rot(b)) + 0x13u; }
static inline __attribute__((always_inline)) uint32_t junk_lcg(uint32_t x) { return 1664525u * x + 1013904223u; }
static inline __attribute__((always_inline)) uint32_t junk_parity(uint32_t x) { x ^= x >> 16; x ^= x >> 8; x ^= x >> 4; return (0x6996u >> (x & 0xF)) & 1u; }
static inline __attribute__((always_inline)) uint32_t junk_fold(uint32_t x) { return (x & 0xFFFFu) ^ (x >> 16); }
static inline __attribute__((always_inline)) uint32_t junk_swap(uint32_t x) { return (x << 16) | (x >> 16); }
static inline __attribute__((always_inline)) uint32_t junk_mix3(uint32_t a, uint32_t b, uint32_t c) { return junk_sbox(a) ^ junk_affine(b) ^ junk_rot(c); }
static inline __attribute__((always_inline)) uint32_t junk_hashlen(size_t n) { return junk_affine(static_cast<uint32_t>(n)) ^ 0xA5A5A5A5u; }
static inline __attribute__((always_inline)) uint32_t junk_byteacc(const std::string& s) { uint32_t v = 0; for (unsigned char ch : s) v = junk_lcg(v) ^ ch; return v; }
static inline __attribute__((always_inline)) uint32_t junk_crcish(uint32_t x) { for (int i = 0; i < 8; ++i) x = (x >> 1) ^ (-(int)(x & 1u) & 0xEDB88320u); return x; }
static inline __attribute__((always_inline)) uint32_t junk_bswap32(uint32_t x) { return (x >> 24) | ((x >> 8) & 0x0000FF00u) | ((x << 8) & 0x00FF0000u) | (x << 24); }
static inline __attribute__((always_inline)) uint32_t junk_roll(uint32_t a, uint32_t b) { uint32_t s = (b & 31u); return (a << s) | (a >> (32u - s)); }
static inline __attribute__((always_inline)) uint32_t junk_spread(uint32_t x) { x ^= x * 0x45d9f3bu; x ^= x * 0x27d4eb2du; return x; }
static inline __attribute__((always_inline)) uint32_t junk_twist(uint32_t x) { return (x ^ (x >> 5) ^ (x << 7)) + 0x13579BDFu; }
static inline __attribute__((always_inline)) uint32_t junk_mask(uint32_t x) { return (x & 0x0F0F0F0Fu) ^ ((x >> 4) & 0x0F0F0F0Fu); }
static inline __attribute__((always_inline)) uint32_t junk_perm(uint32_t x) { return ((x & 0x33333333u) << 2) | ((x & 0xCCCCCCCCu) >> 2); }
static inline __attribute__((always_inline)) uint32_t junk_pmix(uint32_t a, uint32_t b) { return junk_spread(a) + junk_perm(b ^ 0x24F3BC19u); }
static inline __attribute__((always_inline)) uint32_t junk_scramble2(uint32_t x) { x ^= junk_bswap32(x); x = junk_affine(x); return x ^ junk_mask(x); }
static inline __attribute__((always_inline)) uint32_t junk_shuf3(uint32_t a, uint32_t b, uint32_t c) { return junk_roll(a ^ b, c) ^ junk_spread(c); }
static inline __attribute__((always_inline)) uint32_t junk_tau(uint32_t x) { return (x ^ (x >> 11)) * 0x9E3779B1u; }
static inline __attribute__((always_inline)) uint32_t junk_phi(uint32_t x) { return x + 0x61C88647u; }

// SHA-256 helper
static inline __attribute__((always_inline)) uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_init_state(uint32_t s[8]) {
	s[0] = 0x6a09e667u; s[1] = 0xbb67ae85u; s[2] = 0x3c6ef372u; s[3] = 0xa54ff53au;
	s[4] = 0x510e527fu; s[5] = 0x9b05688cu; s[6] = 0x1f83d9abu; s[7] = 0x5be0cd19u;
	volatile uint32_t j = junk_phi(s[0] ^ s[1]);
	j ^= junk_tau(s[2] ^ s[3]);
	volatile uint32_t sink = j; (void)sink;
}

static void sha256_prepare_block(const uint8_t block[64], uint32_t w[64]) {
	volatile uint32_t junk = 0x51E2B97Du;
	junk ^= junk_rot(junk_phi(junk));
	for (int i = 0; i < 16; ++i) {
		w[i] = (static_cast<uint32_t>(block[i * 4 + 0]) << 24) | (static_cast<uint32_t>(block[i * 4 + 1]) << 16)
			| (static_cast<uint32_t>(block[i * 4 + 2]) << 8) | (static_cast<uint32_t>(block[i * 4 + 3]));
		junk ^= junk_sbox(w[i]);
		junk = junk_scramble2(junk ^ w[i]);
		junk ^= junk_mask(junk_bswap32(w[i]));
	}
	for (int i = 16; i < 64; ++i) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		junk ^= junk_affine(w[i]);
		junk = junk_shuf3(junk, s0, s1);
		junk ^= junk_pmix(w[i - 1], w[i - 5]);
	}
	volatile uint32_t sink = junk; (void)sink;
}

static void sha256_compress(uint32_t state[8], const uint32_t w[64]) {
	static const uint32_t K[64] = {
		0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
		0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
		0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
		0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
		0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
		0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
		0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
		0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
	};
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
	volatile uint32_t junk = junk_mix3(a, b, c) ^ junk_perm(state[4]);
	for (int i = 0; i < 64; ++i) {
		uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t temp1 = h + S1 + ch + K[i] + w[i];
		uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = S0 + maj;

		junk ^= junk_noise(K[i], w[i]);
		junk ^= junk_spread(temp1 ^ junk_bswap32(temp2));
		junk = junk_twist(junk) ^ junk_roll(junk, (i & 7u));

		h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
	}
	state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e; state[5] += f; state[6] += g; state[7] += h;
	volatile uint32_t sink = junk; (void)sink;
}

static void sha256_process_chunk(uint32_t state[8], const uint8_t block[64]) {
	uint32_t w[64];
	volatile uint32_t j = junk_bswap32(block[0] | (static_cast<uint32_t>(block[1]) << 8));
	sha256_prepare_block(block, w);
	j ^= junk_spread(w[0] ^ w[15]);
	sha256_compress(state, w);
	volatile uint32_t sink = j; (void)sink;
}

static void sha256_compute(const uint8_t* data, size_t len, uint8_t out[32]) {
	uint32_t state[8];
	sha256_init_state(state);
	volatile uint32_t junk = junk_hashlen(len) ^ junk_tau(static_cast<uint32_t>(len));
	size_t i = 0;
	while (len - i >= 64) {
		sha256_process_chunk(state, data + i);
		i += 64;
		junk ^= junk_lcg(static_cast<uint32_t>(i));
		junk = junk_shuf3(junk, state[(i >> 6) & 7], state[((i >> 6) + 3) & 7]);
	}
	uint8_t block[128];
	size_t rem = len - i;
	if (rem) std::memcpy(block, data + i, rem);
	block[rem++] = 0x80;
	if (rem > 56) {
		std::memset(block + rem, 0, 64 - rem);
		sha256_process_chunk(state, block);
		rem = 0;
	}
	std::memset(block + rem, 0, 56 - rem);
	uint64_t bitlen = static_cast<uint64_t>(len) * 8ull;
	for (int j = 7; j >= 0; --j) block[56 + (7 - j)] = static_cast<uint8_t>((bitlen >> (j * 8)) & 0xFF);
	sha256_process_chunk(state, block);
	for (int k = 0; k < 8; ++k) {
		out[k * 4 + 0] = static_cast<uint8_t>((state[k] >> 24) & 0xFF);
		out[k * 4 + 1] = static_cast<uint8_t>((state[k] >> 16) & 0xFF);
		out[k * 4 + 2] = static_cast<uint8_t>((state[k] >> 8) & 0xFF);
		out[k * 4 + 3] = static_cast<uint8_t>((state[k]) & 0xFF);
	}
	volatile uint32_t sink = junk; (void)sink;
}

static std::string sha256_hex(const std::string& input) {
	std::vector<unsigned char> digest(32);
	sha256_compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), digest.data());
	return toHexLower(digest);
}

static std::vector<unsigned char> rc4_encrypt(const std::string& key, const std::string& data) {
    std::vector<unsigned char> S(256);
    for (int i = 0; i < 256; ++i) S[i] = static_cast<unsigned char>(i);
    unsigned int jx = 0;
    for (int i = 0; i < 256; ++i) {
        jx = (jx + S[i] + static_cast<unsigned char>(key[i % key.size()])) & 0xFFu;
        std::swap(S[i], S[jx]);
        volatile uint32_t t = junk_rot(junk_affine(S[i] ^ S[jx] ^ static_cast<unsigned char>(i)));
        (void)t;
    }
    std::vector<unsigned char> out;
    out.reserve(data.size());
    unsigned int ix = 0; jx = 0;
    for (size_t idx = 0; idx < data.size(); ++idx) {
        ix = (ix + 1) & 0xFFu;
        jx = (jx + S[ix]) & 0xFFu;
        std::swap(S[ix], S[jx]);
        unsigned char K = S[(S[ix] + S[jx]) & 0xFFu];
        unsigned char c = static_cast<unsigned char>(data[idx]);
        out.push_back(static_cast<unsigned char>(c ^ K));
        if ((idx & 3u) == 0) {
            volatile uint32_t m = junk_crcish(junk_bswap32(K) ^ junk_lcg(ix ^ jx));
            (void)m;
        }
    }
    return out;
}

static inline __attribute__((always_inline)) void junkTick(volatile uint32_t& s) {
	s = ((s << 5) | (s >> 27)) + 0x13u;
	s ^= 0xA3B1u;
	s += (s >> 7);
}

static inline __attribute__((always_inline)) uint32_t junkMixLen(uint32_t acc, size_t len) {
	acc ^= static_cast<uint32_t>(len * 2654435761u);
	acc = (acc << 7) ^ (acc >> 3) ^ 0x9e3779b9u;
	return acc;
}

int main() {
	volatile uint32_t j = 0xC0FFEEu;
	j = junk_rot(j);
    const std::string expectedHex = "03570087f6d12a5c8f42c8c30614a5ca9dcfa63f66d913a6c5b472e7430ad739cd96765909875629edd369b5ec2b7faf5718cd08bb531b9d14d0bcbdd7022ed4";
    const std::string rc4Key = "gr00t_gr00t_keep_l00k1ng";
	j ^= junk_hashlen(expectedHex.size());
	j = junk_mix3(j, junk_affine(123u), junk_swap(0xABCDu));

	std::cout << "Enter password: ";
	j = junk_lcg(j);
	std::string pw;
	if (!std::getline(std::cin, pw)) {
		j ^= junk_byteacc("err");
		std::cerr << "Input error." << std::endl;
		volatile uint32_t sink = j; (void)sink;
		return 1;
	}
	j ^= junk_byteacc(pw);
	j = junk_noise(j, junk_parity(static_cast<uint32_t>(pw.size())));

    std::string got;
	try {
		j = junk_rot(j);
		got = sha256_hex(pw);
		j ^= junk_hashlen(got.size());
		j = junk_crcish(j);
	}
	catch (const std::exception& ex) {
		j ^= junk_affine(0xBADu);
		std::cerr << "Error!" << std::endl;
		volatile uint32_t sink = j; (void)sink;
		return 1;
	}

    // RC4 over the hex string; compare hex of ciphertext to expectedHex
    auto rc4Bytes = rc4_encrypt(rc4Key, got);
    j ^= junk_byteacc(std::string(rc4Bytes.begin(), rc4Bytes.end()));
    std::string rc4Hex = toHexLower(rc4Bytes);

    if (rc4Hex == expectedHex) {
		j = junk_mix3(j, 0x12345678u, 0x9ABCDEF0u);
		std::cout << "Correct!" << std::endl;
		volatile uint32_t sink = j; (void)sink;
		return 0;
	}
	j = junk_lcg(j);
	std::cout << "Incorrect." << std::endl;
	volatile uint32_t sink = j; (void)sink;
	return 1;
}
```

# Solver

```Python
#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path

def try_password(binary: str, password: str, timeout: float = 2.5) -> tuple[bool, str, str, int]:
    try:
        cp = subprocess.run(
            [binary],
            input=password,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        ok = ("Incorrect" not in cp.stdout)
        return ok, cp.stdout, cp.stderr, cp.returncode
    except subprocess.TimeoutExpired as e:
        return False, "", f"timeout: {e}", -1
    except FileNotFoundError as e:
        sys.exit(2)

def main() -> int:
    p = argparse.ArgumentParser(description="Bruteforcer")
    p.add_argument("--binary", default="./chall", help="target binary")
    p.add_argument("--wordlist", default="rockyou.txt", help="wordlist")
    args = p.parse_args()

    wl_path = Path(args.wordlist)
    if not wl_path.exists():
        print(f"error: wordlist not found: {wl_path}")
        return 2

    tried = 0
    with wl_path.open("r", encoding="latin-1", errors="ignore") as f:
        for line in f:
            pw = line.rstrip("\r\n")
            if not pw:
                continue
            tried += 1
            if tried % 10000 == 0:
            	print(f"At attempt {tried}")
            ok, out, err, rc = try_password(args.binary, pw, timeout=3)
            if ok:
                print("SUCCESS")
                print(f"password: {pw}")
                return 0

    print("No password found.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

# Challenge description

Name: `Crack me if you can`

Description:
```
Our intern accidentally deleted all of our databases, with backups. That logged everybody out and no one can access the systems. The only system remaining is the legacy authenticator written by our insane senior, which nobody can understand. Can you break that insanity and get us access back to our systems? Flag will be the MD5 of the password (`ISMCTF{md5(password)}).
```

Password: `downwithhackerz`
Flag: `ISMCTF{66e8a9183004e1493c66db98b63e9965}`
Difficulty: `Hard`
Points: `42`
Category: `Reverse Engineering`
Hint 1 - 7 points: `Disassemble the binary in IDA/Ghidra and use debugging to step through all statements, letting the values and strings decrypt themselves.`
Hint 2 - 14 points: `Start your analysis at the std::cout related instructions, following the printed messages and search for specific values/structures that might hint towards the algorithms used. Look at specific dwords used and cross-reference them back to their algorithms.`
Hint 3 - 21 points: `The program checks for a password, then does a SHA256 over it, and RC4 encrypts the digest and checks it against a hardcoded value. How about cracking a password with the most known password list? :)`