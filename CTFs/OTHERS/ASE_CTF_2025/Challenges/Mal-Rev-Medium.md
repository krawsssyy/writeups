# Building


```Python
import os
import string
import random
import hashlib

INPUT_DIR = r"C:\Users\alex\Desktop\New folder\files"
ALPHABET = string.ascii_letters + string.digits + "_-"
BLOCK_SIZE = 8
random.seed(0x1337deadbeef1337)
def generate_ascii_key(length: int = 200) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(length))

def derive_3des_key(session_key_bytes: bytes) -> bytes:
    digest = hashlib.sha256(session_key_bytes).digest()
    return digest[:24] # 24 bytes = 3 DES keys

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOXES = [
    # S1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ],
    # S2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    ],
    # S3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    ],
    # S4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    ],
    # S5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    ],
    # S6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    ],
    # S7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    ],
    # S8
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ],
]

def permute(block_bits, table):
    return [block_bits[i - 1] for i in table]

def bytes_to_bits(b: bytes):
    return [(byte >> (7 - i)) & 1 for byte in b for i in range(8)]

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for j in range(8):
            val = (val << 1) | bits[i + j]
        out.append(val)
    return bytes(out)

def xor_bits(a, b):
    return [x ^ y for x, y in zip(a, b)]

def left_rotate(lst, n):
    return lst[n:] + lst[:n]

def generate_round_keys(key64_bits):
    key56 = permute(key64_bits, PC1)
    C = key56[:28]
    D = key56[28:]

    round_keys = []
    for shift in SHIFTS:
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        CD = C + D
        subkey = permute(CD, PC2)  # 48-bit round key
        round_keys.append(subkey)
    return round_keys


def sbox_substitution(bits48):
    out = []
    for i in range(8):
        chunk = bits48[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = SBOXES[i][row][col]
        # convert 0..15 into 4 bits
        for shift in (3, 2, 1, 0):
            out.append((val >> shift) & 1)
    return out

def feistel(R, subkey):
    expanded = permute(R, E)
    xored = xor_bits(expanded, subkey)
    s_out = sbox_substitution(xored)
    return permute(s_out, P)

def des_block_encrypt(block8: bytes, key8: bytes) -> bytes:
    block_bits = bytes_to_bits(block8)
    key_bits = bytes_to_bits(key8)

    perm = permute(block_bits, IP)
    L = perm[:32]
    R = perm[32:]

    round_keys = generate_round_keys(key_bits)

    # 16 Feistel rounds
    for i in range(16):
        f_out = feistel(R, round_keys[i])
        newL = R
        newR = xor_bits(L, f_out)
        L, R = newL, newR

    # Swap L/R and apply Final Permutation
    preoutput = R + L
    out_bits = permute(preoutput, FP)
    return bits_to_bytes(out_bits)

def des_block_decrypt(block8: bytes, key8: bytes) -> bytes:
    block_bits = bytes_to_bits(block8)
    key_bits = bytes_to_bits(key8)

    perm = permute(block_bits, IP)
    L = perm[:32]
    R = perm[32:]

    round_keys = generate_round_keys(key_bits)

    for i in range(16):
        # reverse key order for decryption
        f_out = feistel(R, round_keys[15 - i])
        newL = R
        newR = xor_bits(L, f_out)
        L, R = newL, newR

    preoutput = R + L
    out_bits = permute(preoutput, FP)
    return bits_to_bytes(out_bits)

def triple_des_encrypt_block(block8: bytes, key24: bytes) -> bytes:
    """
    3DES EDE mode: E_k1( D_k2( E_k3(block) ) )
    key24 = k1 || k2 || k3, each 8 bytes.
    """
    assert len(key24) == 24
    k1 = key24[0:8]
    k2 = key24[8:16]
    k3 = key24[16:24]

    b1 = des_block_encrypt(block8, k1)
    b2 = des_block_decrypt(b1, k2)
    b3 = des_block_encrypt(b2, k3)
    return b3

def triple_des_decrypt_block(block8: bytes, key24: bytes) -> bytes:
    """
    Inverse of the EDE construction:
      D_k3( E_k2( D_k1(block) ) )
    """
    assert len(key24) == 24
    k1 = key24[0:8]
    k2 = key24[8:16]
    k3 = key24[16:24]

    b1 = des_block_decrypt(block8, k3)
    b2 = des_block_encrypt(b1, k2)
    b3 = des_block_decrypt(b2, k1)
    return b3

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def triple_des_ecb_encrypt(data: bytes, key24: bytes) -> bytes:
    data = pkcs7_pad(data, BLOCK_SIZE)
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        out.extend(triple_des_encrypt_block(block, key24))
    return bytes(out)

def triple_des_ecb_decrypt(data: bytes, key24: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        out.extend(triple_des_decrypt_block(block, key24))
    return pkcs7_unpad(bytes(out), BLOCK_SIZE)

def encrypt_file_with_3des(path_in: str, key24: bytes) -> None:
    with open(path_in, "rb") as f:
        plaintext = f.read()
    ciphertext = triple_des_ecb_encrypt(plaintext, key24)
    with open(path_in, "wb") as f:
        f.write(ciphertext)

def process_ctf_folder(input_dir: str, key24: bytes) -> None:
    for name in os.listdir(input_dir):
        in_path = os.path.join(input_dir, name)
        if not os.path.isfile(in_path):
            continue
        encrypt_file_with_3des(in_path, key24)


def main():
    session_key_str = generate_ascii_key()
    session_key_bytes = session_key_str.encode("ascii")
    key24 = derive_3des_key(session_key_bytes)
    process_ctf_folder(INPUT_DIR, key24)

if __name__ == "__main__":
    main()
```

Script was then obfuscated using Carbon and then ObfuXtreme. From there, it was compiled to a PyInstaller.

# Solver

```Python
import hashlib
from Crypto.Cipher import DES3
import argparse
import random
import string
BLOCK_SIZE = 8

def derive_3des_key() -> bytes:
    ALPHABET = string.ascii_letters + string.digits + "_-"
    random.seed(0x1337deadbeef1337)
    key = "".join(random.choice(ALPHABET) for _ in range(200))
    h = hashlib.sha256(key.encode("ascii")).digest()
    return h[:24]  # 24 bytes = k1||k2||k3

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding content")
    return data[:-pad_len]

def decrypt_file_3des_ecb(infile: str, outfile: str, key24: bytes):
    cipher = DES3.new(key24, DES3.MODE_ECB)

    with open(infile, "rb") as f:
        ciphertext = f.read()

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length is not a multiple of 8")

    plaintext = cipher.decrypt(ciphertext)
    plaintext = pkcs7_unpad(plaintext)

    with open(outfile, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted OK -> {outfile}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="3DES solver")
    parser.add_argument("input_file", help="Encrypted file")
    parser.add_argument("output_file", help="Output file")
    args = parser.parse_args()

    key24 = derive_3des_key()
    print("3DES key (hex):", key24.hex())

    decrypt_file_3des_ecb(args.input_file, args.output_file, key24)

```

# Challenge description

Name: `Mal`

Description:
```
Soo yeah, that same intern now ran a ransomware :(. Please help us recover our most important treasure.
```

Flag: `ISMCTF{n1c3_j0B_bUSt1ng_th1s_r4ns0MMM3W4rEE_d0w7--s33DED_r4nds_4r3_s0_bad_pls_dont_use_them}`
Points: `30`
Category: `Reverse Engineering`
Difficulty: `Medium`
Hint 1 - 8 points: `Its a PyInstaller EXE. Unpack it and analyze the entry module via uncompyle6 or pylingual.`
Hint 2 - 12 points: `Use dis module to analyze the decompressed byte code.`
Hint 3 - 4 points: `Search for the magic values there in order to identify the algorithm.`