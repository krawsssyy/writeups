# Building

Just compile the binary with MSVC.

# Source code

```C++
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <cstdint>
#include <iomanip>
#include <stdexcept>

std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("Could not open file: " + path);
    }
    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(f),
        std::istreambuf_iterator<char>()
    );
}

std::vector<unsigned char> read_self_binary() {
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        throw std::runtime_error("GetModuleFileNameA failed");
    }
    return read_file(path);
}

int main() {
    try {
        std::vector<unsigned char> flag = read_file("flag.txt");
        size_t flag_len = flag.size();
        if (flag_len == 0) {
            std::cerr << "Flag is empty" << std::endl;
            return 1;
        }

        std::vector<unsigned char> self_bin = read_self_binary();
        size_t bin_len = self_bin.size();

        if (bin_len <= flag_len) {
            return 1;
        }

        std::random_device rd;
        std::mt19937 mt(rd());

        for (int i = 0; i < 700; ++i) {
            uint32_t r = mt(); 
            std::cout << r << std::endl;
        }

        // 701st output decides offset
        uint32_t rnd = mt();

        size_t max_offset = bin_len - flag_len;
        size_t offset = rnd % max_offset;

        // XOR flag with bytes from our own binary at that offset
        std::vector<unsigned char> cipher(flag_len);
        for (size_t i = 0; i < flag_len; ++i) {
            cipher[i] = flag[i] ^ self_bin[offset + i];
        }
        std::cout << std::hex << std::setfill('0');
        for (unsigned char c : cipher) {
            std::cout << std::setw(2) << static_cast<int>(c);
        }
        std::cout << std::endl;

    }
    catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

```


Players will be asked to crack the MT19937 algorithm, given 700 outputs. They will be given the outputs from the original run and the compiled binary.


# Solver

```Python
import sys
from mt19937predictor import MT19937Predictor


def parse_output(path):
    with open(path, "rt", encoding="utf16") as f: # windows output weirdness
        lines = [line.strip() for line in f if line.strip()]

    if len(lines) < 701:
        raise ValueError(f"Expected at least 701 lines, got {len(lines)}")

    ciphertext_hex = lines[-1]
    ciphertext = bytes.fromhex(ciphertext_hex)
    outputs = []
    for line in lines[:-1]:
        try:
            outputs.append(int(line))
        except ValueError:
            continue

    if len(outputs) < 700:
        raise ValueError(f"Expected at least 700 MT outputs, got {len(outputs)}")

    return outputs[:700], ciphertext


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} output.txt challenge2.exe")
        sys.exit(1)

    output_path = sys.argv[1]
    binary_path = sys.argv[2]

    outputs, ciphertext = parse_output(output_path)
    flag_len = len(ciphertext)

    pred = MT19937Predictor()
    for i in range(624):
        pred.setrandbits(outputs[i], 32)
    for _ in range(624, 700):
        assert outputs[_] == pred.getrandbits(32), "Error predicting"

    rnd_701 = pred.getrandbits(32)

    with open(binary_path, "rb") as f:
        bin_data = f.read()

    bin_len = len(bin_data)
    if bin_len <= flag_len:
        raise ValueError("Binary is too small compared to ciphertext length")

    max_offset = bin_len - flag_len
    offset = rnd_701 % max_offset
    key = bin_data[offset:offset + flag_len]
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, key))

    print(f"Binary size: {bin_len} bytes")
    print(f"max_offset:  {max_offset}")
    print(f"offset used: {offset}")
    print("Recovered flag:", plaintext.decode(errors="replace"))


if __name__ == "__main__":
    main()

```

# Challenge description

Name: `Twist of Fate`

Description:
```
The university’s experimental randomness beacon has started behaving strangely. Its stream of “entropy reports” looks ordinary enough at first—just a long series of numbers—but the device suddenly locks itself down after the final value and hides the system’s master flag behind a veil of shifting noise.

Rumor has it that the beacon’s sense of unpredictability is… optimistic.
If you can uncover the pattern behind its output, you might just be able to unwind the fate it’s woven around the flag.
```


Flag: `ISMCTF{m3rs3nn3_tw1zzt3rs_are_so_s00_FUN}`
Difficulty: `Easy`
Category: `Cryptography`
Points: `15`
Hint 1 - 5 points: `Disassemble the binary in IDA/Ghidra. Check out the algorithm used for generation of the random numbers and search why would it give you that many outputs. Then see what that last line is, and how it is generated from the binary itself.`
Hint 2 - 9 points: `The algorithm used is a Mersenne Twister. You require 624 outputs to break the initial state and be able to generate the same numbers. Then, it computes an offset from the binary from the 701st output of the Mersenne Twister and encrypts the flag. Revert the decryption and get the flag.`