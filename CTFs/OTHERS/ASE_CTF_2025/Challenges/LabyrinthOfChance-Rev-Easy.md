# Building

Just compile using MSVC

# Source code

```C++
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstdint>
#include <conio.h> 

// lcg params
static const uint32_t LCG_A = 1664525u;
static const uint32_t LCG_C = 1013904223u;
uint32_t lcg_next(uint32_t& state) {
    state = state * LCG_A + LCG_C; // uint32_t overflow wraps automatically
    return state;
}
// hardcoded maze params
static const int WIDTH = 10;
static const int HEIGHT = 10;
static const uint32_t MAZE_SEED = 0x12345678u;

struct Pos {
    int x;
    int y;
};

uint32_t generate_maze(std::vector<char>& maze, uint32_t seed) {
    maze.assign(WIDTH * HEIGHT, '.');

    uint32_t state = seed;

    for (int y = 0; y < HEIGHT; ++y) {
        for (int x = 0; x < WIDTH; ++x) {
            // keep start and end always free
            if ((x == 0 && y == 0) || (x == WIDTH - 1 && y == HEIGHT - 1))
                continue;

            state = lcg_next(state);
            // 1/4 chance of being a wall - just some random stuff
            if ((state & 0x3u) == 0u) {
                maze[y * WIDTH + x] = '#';
            }
        }
    }
    return state;
}

void print_maze(const std::vector<char>& maze, const Pos& player) {
    system("cls"); // clear console for Windows
    for (int y = 0; y < HEIGHT; ++y) {
        for (int x = 0; x < WIDTH; ++x) {
            if (x == player.x && y == player.y) {
                std::cout << '@'; // player
            }
            else if (x == 0 && y == 0) {
                std::cout << 'S'; // start
            }
            else if (x == WIDTH - 1 && y == HEIGHT - 1) {
                std::cout << 'E'; // end
            }
            else {
                std::cout << maze[y * WIDTH + x];
            }
        }
        std::cout << std::endl;
    }
}

bool is_wall(const std::vector<char>& maze, int x, int y) {
    return maze[y * WIDTH + x] == '#';
}

std::string read_flag(const std::string& path) {
    std::ifstream fin(path, std::ios::binary);
    if (!fin) {
        throw std::runtime_error("Could not open flag file: " + path);
    }
    std::string flag((std::istreambuf_iterator<char>(fin)),
        std::istreambuf_iterator<char>());

    // strip trailing characters
    while (!flag.empty() && (flag.back() == '\n' || flag.back() == '\r')) {
        flag.pop_back();
    }
    return flag;
}

void xor_encrypt_flag(std::string& flag, uint32_t seed) {
    uint32_t state = seed;
    for (int i = 0; i < 11; ++i) {
        uint32_t r = lcg_next(state);
        uint8_t key_byte = static_cast<uint8_t>(r & 0xFFu);
        for (auto& ch : flag) {
            ch ^= key_byte;
        }
    }
}

std::string to_hex(const std::string& data) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char c : data) {
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0F]);
    }
    return out;
}

int main() {
    try {
        std::vector<char> maze;
        uint32_t new_seed = generate_maze(maze, MAZE_SEED);
        std::cout << "Press any key to start the game..." << std::endl;
        _getch();

        Pos player{ 0, 0 };
        std::string flag = read_flag("flag.txt");
        std::string encrypted_flag = flag;
        xor_encrypt_flag(encrypted_flag, new_seed);
        std::string encrypted_hex = to_hex(encrypted_flag);

        bool running = true;
        while (running) {
            print_maze(maze, player);
            std::cout << std::endl << "Use WASD to move. Reach 'G' to win" << std::endl;

            int ch = _getch();
            int nx = player.x;
            int ny = player.y;

            if (ch == 'w' || ch == 'W') ny--;
            else if (ch == 's' || ch == 'S') ny++;
            else if (ch == 'a' || ch == 'A') nx--;
            else if (ch == 'd' || ch == 'D') nx++;
            else if (ch == 'q' || ch == 'Q') {
                std::cout << "Quitting" << std::endl;
                break;
            }

            if (nx >= 0 && nx < WIDTH && ny >= 0 && ny < HEIGHT &&
                !is_wall(maze, nx, ny)) {
                player.x = nx;
                player.y = ny;
            }

            if (player.x == WIDTH - 1 && player.y == HEIGHT - 1) {
                print_maze(maze, player);
                std::cout << std::endl << "You reached the goal!" << std::endl;
                std::cout << "Encrypted flag (hex): " << encrypted_hex << std::endl;
                running = false;
            }
        }

    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
```

Players will be given the compiled binary (release configuration) and the encrypted flag.


# Solution script

```Python
LCG_A = 1664525
LCG_C = 1013904223
MOD_MASK = 0xFFFFFFFF
ENC_SEED = 0x12345678

def lcg_next(state):
    return (state * LCG_A + LCG_C) & MOD_MASK

def xor_encrypt(data: bytes, seed: int) -> bytes:
    state = seed
    out = bytearray(data)
    for _ in range(10 * 10 - 2):
        state = lcg_next(state) # advance lcg from maze generation
    for _ in range(11): # do xor rounds
        state = lcg_next(state)
        key_byte = state & 0xFF
        for i in range(len(out)):
            out[i] ^= key_byte
    return bytes(out)

def main():
    enc_flag = "d7cdd3ddcad8e5c2c2d2ddd9abc1aaaaadc1f0aea9c1ead6dfa9c1fcdfdffab1b1e3"
    try:
        data = bytes.fromhex(enc_flag)
    except ValueError:
        exit(1)

    result = xor_encrypt(data, ENC_SEED)
    print("Flag:", result.decode(errors="replace"))

if __name__ == "__main__":
    main()

```

# Challenge description:

Name: `Labyrinth of Chance`

Description:
```
The academy’s old maze-simulator has been revived for a special exercise—but something is off. The labyrinth shifts according to a mysterious sequence of numbers, and your path through it is only half the puzzle. At the end of the maze lies a message, but it has been wrapped in layers of misdirection born from the very same sequence that shaped the walls around you.

Those who understand the patterns of chance may find more than just the exit.
Reach the goal, study what the maze reveals, and unravel what was hidden behind its carefully engineered randomness.
```

Provided encrypted flag: `d7cdd3ddcad8e5c2c2d2ddd9abc1aaaaadc1f0aea9c1ead6dfa9c1fcdfdffab1b1e3`

Flag: `ISMCTF{\\LCG5_443_n07_tHA7_bAAd//}`
Points: `15`
Difficulty: `Easy`
Category: `Reverse Engineering`
Hint 1 - 3 points: `Disassemble the binary in IDA/Ghidra. See how it encrypts the flag and from where the key is derived.`
Hint 2 - 5 points: `The program uses an LCG to XOR encrypt the flag. Advance the LCG to the required number, then use it generate the XOR key and decrypt the flag.`