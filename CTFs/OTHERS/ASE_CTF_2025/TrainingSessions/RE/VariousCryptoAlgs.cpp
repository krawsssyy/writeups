#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <vector>
#include <array>
#include <string>

using std::uint8_t;
using std::uint32_t;
using std::size_t;

void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label;
    for (auto b : data) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
}


namespace AES128 {

    using std::uint8_t;

    static const uint8_t sbox[256] = { // regular sbox
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    static const uint8_t rsbox[256] = { // inverse sbox
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };

    static const uint8_t Rcon[11] = {
        0x00, // unused
        0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
    };

    static uint8_t xtime(uint8_t x) {
        return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }

    static uint8_t mul(uint8_t x, uint8_t y) {
        uint8_t r = 0;
        while (y) {
            if (y & 1) r ^= x;
            x = xtime(x);
            y >>= 1;
        }
        return r;
    }

    void SubBytes(uint8_t* state) {
        for (int i = 0; i < 16; ++i)
            state[i] = sbox[state[i]];
    }

    void InvSubBytes(uint8_t* state) {
        for (int i = 0; i < 16; ++i)
            state[i] = rsbox[state[i]];
    }

    void ShiftRows(uint8_t* state) {
        uint8_t tmp[16];
        // row 0
        tmp[0] = state[0]; tmp[4] = state[4]; tmp[8] = state[8]; tmp[12] = state[12];
        // row 1
        tmp[1] = state[5]; tmp[5] = state[9]; tmp[9] = state[13]; tmp[13] = state[1];
        // row 2
        tmp[2] = state[10]; tmp[6] = state[14]; tmp[10] = state[2]; tmp[14] = state[6];
        // row 3
        tmp[3] = state[15]; tmp[7] = state[3]; tmp[11] = state[7]; tmp[15] = state[11];
        std::memcpy(state, tmp, 16);
    }

    void InvShiftRows(uint8_t* state) {
        uint8_t tmp[16];
        // row 0
        tmp[0] = state[0]; tmp[4] = state[4]; tmp[8] = state[8]; tmp[12] = state[12];
        // row 1
        tmp[1] = state[13]; tmp[5] = state[1]; tmp[9] = state[5]; tmp[13] = state[9];
        // row 2
        tmp[2] = state[10]; tmp[6] = state[14]; tmp[10] = state[2]; tmp[14] = state[6];
        // row 3
        tmp[3] = state[7]; tmp[7] = state[11]; tmp[11] = state[15]; tmp[15] = state[3];
        std::memcpy(state, tmp, 16);
    }

    void MixColumns(uint8_t* state) {
        for (int c = 0; c < 4; ++c) {
            uint8_t* col = state + 4 * c;
            uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
            col[0] = (uint8_t)(mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3);
            col[1] = (uint8_t)(a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3);
            col[2] = (uint8_t)(a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3));
            col[3] = (uint8_t)(mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2));
        }
    }

    void InvMixColumns(uint8_t* state) {
        for (int c = 0; c < 4; ++c) {
            uint8_t* col = state + 4 * c;
            uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
            col[0] = (uint8_t)(mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9));
            col[1] = (uint8_t)(mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13));
            col[2] = (uint8_t)(mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11));
            col[3] = (uint8_t)(mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14));
        }
    }

    void AddRoundKey(uint8_t* state, const uint8_t* roundKey) {
        for (int i = 0; i < 16; ++i)
            state[i] ^= roundKey[i];
    }

    // key expansion: 16-byte key -> 176-byte round keys
    void KeyExpansion(const uint8_t* key, uint8_t* roundKeys) {
        std::memcpy(roundKeys, key, 16);
        uint8_t temp[4];
        int bytesGenerated = 16;
        int rconIter = 1;

        while (bytesGenerated < 176) {
            for (int i = 0; i < 4; ++i)
                temp[i] = roundKeys[bytesGenerated - 4 + i];

            if (bytesGenerated % 16 == 0) {
                // rotate word
                uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                // substitute word
                for (int i = 0; i < 4; ++i)
                    temp[i] = sbox[temp[i]];
                // Rcon
                temp[0] ^= Rcon[rconIter++];
            }

            for (int i = 0; i < 4; ++i) {
                roundKeys[bytesGenerated] =
                    roundKeys[bytesGenerated - 16] ^ temp[i];
                bytesGenerated++;
            }
        }
    }

    void EncryptBlock(const uint8_t* in, uint8_t* out, const uint8_t* roundKeys) {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        AddRoundKey(state, roundKeys); // round 0

        for (int round = 1; round <= 9; ++round) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, roundKeys + 16 * round);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, roundKeys + 160); // round 10

        std::memcpy(out, state, 16);
    }

    void DecryptBlock(const uint8_t* in, uint8_t* out, const uint8_t* roundKeys) {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        AddRoundKey(state, roundKeys + 160);
        InvShiftRows(state);
        InvSubBytes(state);

        for (int round = 9; round >= 1; --round) {
            AddRoundKey(state, roundKeys + 16 * round);
            InvMixColumns(state);
            InvShiftRows(state);
            InvSubBytes(state);
        }

        AddRoundKey(state, roundKeys);
        std::memcpy(out, state, 16);
    }

    // ECB mode (no padding)

    std::vector<uint8_t> encrypt_ecb(const std::vector<uint8_t>& plaintext,
                                     const std::array<uint8_t, 16>& key) {
        if (plaintext.empty() || (plaintext.size() % 16) != 0)
            throw std::runtime_error("AES-ECB: plaintext size must be a non-zero multiple of 16 bytes");

        uint8_t roundKeys[176];
        KeyExpansion(key.data(), roundKeys);

        std::vector<uint8_t> out(plaintext.size());
        uint8_t block_in[16];
        uint8_t block_out[16];

        for (size_t offset = 0; offset < plaintext.size(); offset += 16) {
            std::memcpy(block_in, &plaintext[offset], 16);
            EncryptBlock(block_in, block_out, roundKeys);
            std::memcpy(&out[offset], block_out, 16);
        }

        return out;
    }

    std::vector<uint8_t> decrypt_ecb(const std::vector<uint8_t>& ciphertext,
                                     const std::array<uint8_t, 16>& key) {
        if (ciphertext.empty() || (ciphertext.size() % 16) != 0)
            throw std::runtime_error("AES-ECB: ciphertext size must be a non-zero multiple of 16 bytes");

        uint8_t roundKeys[176];
        KeyExpansion(key.data(), roundKeys);

        std::vector<uint8_t> out(ciphertext.size());
        uint8_t block_in[16];
        uint8_t block_out[16];

        for (size_t offset = 0; offset < ciphertext.size(); offset += 16) {
            std::memcpy(block_in, &ciphertext[offset], 16);
            DecryptBlock(block_in, block_out, roundKeys);
            std::memcpy(&out[offset], block_out, 16);
        }

        return out;
    }

    // CBC mode with PKCS#7 padding

    std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& plaintext,
        const std::array<uint8_t, 16>& key,
        const std::array<uint8_t, 16>& iv) {
        uint8_t roundKeys[176];
        KeyExpansion(key.data(), roundKeys);

        // PKCS#7 padding
        std::vector<uint8_t> padded = plaintext;
        size_t padLen = 16 - (padded.size() % 16);
        if (padLen == 0) padLen = 16;
        padded.insert(padded.end(), padLen, static_cast<uint8_t>(padLen));

        std::vector<uint8_t> out;
        out.reserve(padded.size());

        uint8_t prev[16];
        std::memcpy(prev, iv.data(), 16);

        uint8_t block[16];
        uint8_t enc[16];

        for (size_t offset = 0; offset < padded.size(); offset += 16) {
            std::memcpy(block, &padded[offset], 16);
            // XOR with previous ciphertext (or IV for first block)
            for (int i = 0; i < 16; ++i)
                block[i] ^= prev[i];

            EncryptBlock(block, enc, roundKeys);
            out.insert(out.end(), enc, enc + 16);

            std::memcpy(prev, enc, 16);
        }

        return out;
    }

    std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& ciphertext,
        const std::array<uint8_t, 16>& key,
        const std::array<uint8_t, 16>& iv) {
        if (ciphertext.empty() || ciphertext.size() % 16 != 0)
            throw std::runtime_error("CBC ciphertext size must be multiple of 16");

        uint8_t roundKeys[176];
        KeyExpansion(key.data(), roundKeys);

        std::vector<uint8_t> tmp;   // includes padding
        tmp.reserve(ciphertext.size());

        uint8_t prev[16];
        std::memcpy(prev, iv.data(), 16);

        uint8_t block[16];
        uint8_t dec[16];

        for (size_t offset = 0; offset < ciphertext.size(); offset += 16) {
            std::memcpy(block, &ciphertext[offset], 16);
            DecryptBlock(block, dec, roundKeys);

            // XOR with previous ciphertext / IV
            for (int i = 0; i < 16; ++i)
                dec[i] ^= prev[i];

            tmp.insert(tmp.end(), dec, dec + 16);
            std::memcpy(prev, block, 16);
        }

        // Remove PKCS#7 padding
        if (tmp.empty())
            throw std::runtime_error("CBC decrypt: empty plaintext after decrypt");

        uint8_t padLen = tmp.back();
        if (padLen == 0 || padLen > 16 || padLen > tmp.size())
            throw std::runtime_error("CBC decrypt: invalid padding");

        for (size_t i = 0; i < padLen; ++i) {
            if (tmp[tmp.size() - 1 - i] != padLen)
                throw std::runtime_error("CBC decrypt: bad padding bytes");
        }

        tmp.resize(tmp.size() - padLen);
        return tmp;
    }

}


namespace SHA256 {

    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    inline uint32_t big_sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    inline uint32_t big_sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    inline uint32_t small_sigma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    inline uint32_t small_sigma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    struct Context {
        uint64_t bitlen = 0;
        uint32_t state[8] = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
        };
        uint8_t buffer[64];
        size_t buffer_len = 0;
    };

    void transform(Context& ctx, const uint8_t* chunk) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(chunk[4 * i]) << 24) |
                (uint32_t(chunk[4 * i + 1]) << 16) |
                (uint32_t(chunk[4 * i + 2]) << 8) |
                (uint32_t(chunk[4 * i + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = ctx.state[0];
        uint32_t b = ctx.state[1];
        uint32_t c = ctx.state[2];
        uint32_t d = ctx.state[3];
        uint32_t e = ctx.state[4];
        uint32_t f = ctx.state[5];
        uint32_t g = ctx.state[6];
        uint32_t h = ctx.state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + big_sigma1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = big_sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        ctx.state[0] += a;
        ctx.state[1] += b;
        ctx.state[2] += c;
        ctx.state[3] += d;
        ctx.state[4] += e;
        ctx.state[5] += f;
        ctx.state[6] += g;
        ctx.state[7] += h;
    }

    void update(Context& ctx, const uint8_t* data, size_t len) {
        ctx.bitlen += len * 8;
        while (len > 0) {
            size_t to_copy = std::min(len, 64 - ctx.buffer_len);
            std::memcpy(ctx.buffer + ctx.buffer_len, data, to_copy);
            ctx.buffer_len += to_copy;
            data += to_copy;
            len -= to_copy;
            if (ctx.buffer_len == 64) {
                transform(ctx, ctx.buffer);
                ctx.buffer_len = 0;
            }
        }
    }

    void finalize(Context& ctx, uint8_t* hash) {
        // padding
        ctx.buffer[ctx.buffer_len++] = 0x80;
        if (ctx.buffer_len > 56) {
            while (ctx.buffer_len < 64)
                ctx.buffer[ctx.buffer_len++] = 0x00;
            transform(ctx, ctx.buffer);
            ctx.buffer_len = 0;
        }
        while (ctx.buffer_len < 56)
            ctx.buffer[ctx.buffer_len++] = 0x00;

        // append length (big endian)
        for (int i = 7; i >= 0; --i) {
            ctx.buffer[ctx.buffer_len++] =
                static_cast<uint8_t>((ctx.bitlen >> (8 * i)) & 0xFF);
        }
        transform(ctx, ctx.buffer);

        for (int i = 0; i < 8; ++i) {
            hash[4 * i] = static_cast<uint8_t>((ctx.state[i] >> 24) & 0xFF);
            hash[4 * i + 1] = static_cast<uint8_t>((ctx.state[i] >> 16) & 0xFF);
            hash[4 * i + 2] = static_cast<uint8_t>((ctx.state[i] >> 8) & 0xFF);
            hash[4 * i + 3] = static_cast<uint8_t>(ctx.state[i] & 0xFF);
        }
    }

    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        Context ctx;
        update(ctx, data.data(), data.size());
        std::vector<uint8_t> out(32);
        finalize(ctx, out.data());
        return out;
    }

}

namespace MD5 {

    inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (~x & z);
    }
    inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
        return (x & z) | (y & ~z);
    }
    inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }
    inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
        return y ^ (x | ~z);
    }

    inline uint32_t leftrotate(uint32_t x, uint32_t c) {
        return (x << c) | (x >> (32 - c));
    }

    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };

    static const uint32_t s[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };

    struct Context {
        uint32_t a = 0x67452301;
        uint32_t b = 0xefcdab89;
        uint32_t c = 0x98badcfe;
        uint32_t d = 0x10325476;
        uint64_t bitlen = 0;
        uint8_t buffer[64];
        size_t buffer_len = 0;
    };

    void transform(Context& ctx, const uint8_t block[64]) {
        uint32_t M[16];
        for (int i = 0; i < 16; ++i) {
            M[i] = (uint32_t(block[4 * i])) |
                (uint32_t(block[4 * i + 1]) << 8) |
                (uint32_t(block[4 * i + 2]) << 16) |
                (uint32_t(block[4 * i + 3]) << 24);
        }

        uint32_t a = ctx.a;
        uint32_t b = ctx.b;
        uint32_t c = ctx.c;
        uint32_t d = ctx.d;

        for (int i = 0; i < 64; ++i) {
            uint32_t Fval, g;
            if (i < 16) {
                Fval = F(b, c, d);
                g = i;
            }
            else if (i < 32) {
                Fval = G(b, c, d);
                g = (5 * i + 1) % 16;
            }
            else if (i < 48) {
                Fval = H(b, c, d);
                g = (3 * i + 5) % 16;
            }
            else {
                Fval = I(b, c, d);
                g = (7 * i) % 16;
            }
            uint32_t temp = d;
            d = c;
            c = b;
            uint32_t to_rotate = a + Fval + K[i] + M[g];
            b = b + leftrotate(to_rotate, s[i]);
            a = temp;
        }

        ctx.a += a;
        ctx.b += b;
        ctx.c += c;
        ctx.d += d;
    }

    void update(Context& ctx, const uint8_t* data, size_t len) {
        ctx.bitlen += len * 8;
        while (len > 0) {
            size_t to_copy = std::min(len, 64 - ctx.buffer_len);
            std::memcpy(ctx.buffer + ctx.buffer_len, data, to_copy);
            ctx.buffer_len += to_copy;
            data += to_copy;
            len -= to_copy;
            if (ctx.buffer_len == 64) {
                transform(ctx, ctx.buffer);
                ctx.buffer_len = 0;
            }
        }
    }

    void finalize(Context& ctx, uint8_t digest[16]) {
        ctx.buffer[ctx.buffer_len++] = 0x80;
        if (ctx.buffer_len > 56) {
            while (ctx.buffer_len < 64)
                ctx.buffer[ctx.buffer_len++] = 0x00;
            transform(ctx, ctx.buffer);
            ctx.buffer_len = 0;
        }
        while (ctx.buffer_len < 56)
            ctx.buffer[ctx.buffer_len++] = 0x00;

        // append length (little endian)
        for (int i = 0; i < 8; ++i) {
            ctx.buffer[ctx.buffer_len++] = static_cast<uint8_t>((ctx.bitlen >> (8 * i)) & 0xFF);
        }

        transform(ctx, ctx.buffer);

        uint32_t words[4] = { ctx.a, ctx.b, ctx.c, ctx.d };
        for (int i = 0; i < 4; ++i) {
            digest[4 * i] = static_cast<uint8_t>(words[i] & 0xFF);
            digest[4 * i + 1] = static_cast<uint8_t>((words[i] >> 8) & 0xFF);
            digest[4 * i + 2] = static_cast<uint8_t>((words[i] >> 16) & 0xFF);
            digest[4 * i + 3] = static_cast<uint8_t>((words[i] >> 24) & 0xFF);
        }
    }

    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        Context ctx;
        update(ctx, data.data(), data.size());
        std::vector<uint8_t> out(16);
        finalize(ctx, out.data());
        return out;
    }

}

namespace RC4 {

    struct State {
        uint8_t S[256];
        uint8_t i = 0;
        uint8_t j = 0;
    };

    // key-scheduling
    void ksa(State& st, const uint8_t* key, size_t keylen) {
        for (int i = 0; i < 256; ++i)
            st.S[i] = static_cast<uint8_t>(i);
        st.i = st.j = 0;

        uint8_t j = 0;
        for (int i = 0; i < 256; ++i) {
            j = static_cast<uint8_t>(j + st.S[i] + key[i % keylen]);
            std::swap(st.S[i], st.S[j]);
        }
    }

    uint8_t prga_byte(State& st) {
        st.i = static_cast<uint8_t>(st.i + 1);
        st.j = static_cast<uint8_t>(st.j + st.S[st.i]);
        std::swap(st.S[st.i], st.S[st.j]);
        uint8_t K = st.S[(uint8_t)(st.S[st.i] + st.S[st.j])];
        return K;
    }

    std::vector<uint8_t> crypt(const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key) {
        State st;
        ksa(st, key.data(), key.size());
        std::vector<uint8_t> out(data.size());
        for (size_t n = 0; n < data.size(); ++n) {
            out[n] = data[n] ^ prga_byte(st);
        }
        return out;
    }

}

namespace ChaCha20 {

    // 32-bit little-endian helpers
    inline uint32_t load32(const uint8_t* p) {
        return uint32_t(p[0]) |
            (uint32_t(p[1]) << 8) |
            (uint32_t(p[2]) << 16) |
            (uint32_t(p[3]) << 24);
    }

    inline void store32(uint8_t* p, uint32_t v) {
        p[0] = uint8_t(v & 0xFF);
        p[1] = uint8_t((v >> 8) & 0xFF);
        p[2] = uint8_t((v >> 16) & 0xFF);
        p[3] = uint8_t((v >> 24) & 0xFF);
    }

    inline uint32_t rotl(uint32_t v, int c) {
        return (v << c) | (v >> (32 - c));
    }

    inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }

    void chacha20_block(const uint8_t key[32],
        const uint8_t nonce[12],
        uint32_t counter,
        uint8_t out[64]) {
        static const char* constants = "expand 32-byte k";
        uint32_t state[16];

        state[0] = 0x61707865; // "expa"
        state[1] = 0x3320646e; // "nd 3"
        state[2] = 0x79622d32; // "2-by"
        state[3] = 0x6b206574; // "te k"

        for (int i = 0; i < 8; ++i)
            state[4 + i] = load32(key + 4 * i);

        state[12] = counter;
        state[13] = load32(nonce + 0);
        state[14] = load32(nonce + 4);
        state[15] = load32(nonce + 8);

        uint32_t working[16];
        for (int i = 0; i < 16; ++i)
            working[i] = state[i];

        for (int i = 0; i < 10; ++i) {
            // odd round
            quarter_round(working[0], working[4], working[8], working[12]);
            quarter_round(working[1], working[5], working[9], working[13]);
            quarter_round(working[2], working[6], working[10], working[14]);
            quarter_round(working[3], working[7], working[11], working[15]);
            // even round
            quarter_round(working[0], working[5], working[10], working[15]);
            quarter_round(working[1], working[6], working[11], working[12]);
            quarter_round(working[2], working[7], working[8], working[13]);
            quarter_round(working[3], working[4], working[9], working[14]);
        }

        for (int i = 0; i < 16; ++i) {
            uint32_t res = working[i] + state[i];
            store32(out + 4 * i, res);
        }
    }

    std::vector<uint8_t> crypt(const std::vector<uint8_t>& plaintext,
        const std::array<uint8_t, 32>& key,
        const std::array<uint8_t, 12>& nonce,
        uint32_t counter = 0) {
        std::vector<uint8_t> out(plaintext.size());
        uint32_t block_counter = counter;
        uint8_t block[64];

        size_t offset = 0;
        while (offset < plaintext.size()) {
            chacha20_block(key.data(), nonce.data(), block_counter++, block);
            size_t block_size = std::min<size_t>(64, plaintext.size() - offset);
            for (size_t i = 0; i < block_size; ++i) {
                out[offset + i] = plaintext[offset + i] ^ block[i];
            }
            offset += block_size;
        }
        return out;
    }

}


int main() {
    std::string message = "Hello, cryptos!"; // 16 bytes for ecb length
    std::vector<uint8_t> msg_bytes(message.begin(), message.end());

    std::cout << "Message: " << message << std::endl << std::endl;
    std::array<uint8_t, 16> aes_key = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };
    std::vector<uint8_t> aes_plain(16, 0);
    for (size_t i = 0; i < std::min<size_t>(16, msg_bytes.size()); ++i)
        aes_plain[i] = msg_bytes[i];

    auto aes_ct = AES128::encrypt_ecb(aes_plain, aes_key);
    auto aes_pt = AES128::decrypt_ecb(aes_ct, aes_key);
    print_hex("AES-128 ECB ciphertext: ", aes_ct);
    print_hex("AES-128 ECB decrypted : ", aes_pt);
    std::cout << std::endl;

    std::array<uint8_t, 16> aes_iv = { 0 };
    auto aes_cbc_ct = AES128::encrypt_cbc(msg_bytes, aes_key, aes_iv);
    auto aes_cbc_pt = AES128::decrypt_cbc(aes_cbc_ct, aes_key, aes_iv);

    print_hex("AES-128 CBC ciphertext: ", aes_cbc_ct);
    std::cout << "AES-128 CBC decrypted : "
        << std::string(aes_cbc_pt.begin(), aes_cbc_pt.end()) << std::endl << std::endl;

    auto sha256 = SHA256::hash(msg_bytes);
    print_hex("SHA-256: ", sha256);
    std::cout << std::endl;

    auto md5 = MD5::hash(msg_bytes);
    print_hex("MD5: ", md5);
    std::cout << std::endl;

    std::vector<uint8_t> rc4_key = { 'k','e','y' };
    auto rc4_ct = RC4::crypt(msg_bytes, rc4_key);
    auto rc4_pt = RC4::crypt(rc4_ct, rc4_key); // same function for decrypt
    print_hex("RC4 ciphertext: ", rc4_ct);
    std::cout << "RC4 decrypted: " << std::string(rc4_pt.begin(), rc4_pt.end()) << std::endl << std::endl;

    std::array<uint8_t, 32> chacha_key = {};
    for (int i = 0; i < 32; ++i) chacha_key[i] = static_cast<uint8_t>(i);
    std::array<uint8_t, 12> chacha_nonce = { 0 };

    auto chacha_ct = ChaCha20::crypt(msg_bytes, chacha_key, chacha_nonce, 0);
    auto chacha_pt = ChaCha20::crypt(chacha_ct, chacha_key, chacha_nonce, 0);

    print_hex("ChaCha20 ciphertext: ", chacha_ct);
    std::cout << "ChaCha20 decrypted: "
        << std::string(chacha_pt.begin(), chacha_pt.end()) << std::endl << std::endl;

    return 0;
}
