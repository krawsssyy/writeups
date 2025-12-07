# Building

```Python
from Crypto.Random import get_random_bytes
import random

def crypt(pt):
    n = len(pt)
    r = random.sample(range(n), k=1)[0]
    rb1 = get_random_bytes(n)
    rb2 = get_random_bytes(n)
    rb3 = get_random_bytes(n)
    val = ((pt[r] | rb1[r]) ^ (pt[r] & rb2[r])) | (rb3[r] & pt[r])
    res = bytearray(get_random_bytes(n))
    res[r] = val
    return res.hex()

FLAG = "ISMCTF{f4k3_flag_for_testing_obv_lol}"
with open("output.txt", "w") as f:
    for _ in range(1500000):
        f.write(crypt(FLAG.encode()) + '\n')
```

# Solution

```Python
def bit_profile(ciphertext, length):
    profile = [0] * (length * 8)
    byte_array = bytearray.fromhex(ciphertext)
    for byte_index, byte in enumerate(byte_array):
        for bit_index in range(8):
            if byte & (1 << (7 - bit_index)):
                profile[byte_index * 8 + bit_index] += 1
    return profile

def aggregate_profiles(ciphertexts):
    length = len(bytearray.fromhex(ciphertexts[0]))
    aggregated = [0] * (length * 8)
    for ciphertext in ciphertexts:
        profile = bit_profile(ciphertext, length)
        for i in range(len(profile)):
            aggregated[i] += profile[i]
    return aggregated, length


def reconstruct_flag(aggregated, length, threshold):
    flag_bits = ['0'] * (length * 8)
    for i in range(length * 8):
        flag_bits[i] = '1' if aggregated[i] > threshold else '0'
    flag_bytes = []
    for i in range(0, len(flag_bits), 8):
        flag_bytes.append(int(''.join(flag_bits[i:i+8]), 2))
    return bytes(flag_bytes)

with open("output.txt", "r") as f:
    ciphertexts = f.readlines()
ciphertexts = [c.strip() for c in ciphertexts]

aggregated, length = aggregate_profiles(ciphertexts)
for i in range(748000, 752000, 50):
    f = reconstruct_flag(aggregated, length, i)
    if b"ISMCTF{" == f[0:7] and f[-1] == "}":
        print(i)
        print(f)
        break
```

# Challenge description

Name: `No more Mr. Nice Guy`

Description:
```
- I'm a changed man, he said..
- Don't worry hun, they all say that, but we know its not true
```

Flag: `ISMCTF{!same_s0lver_7s_LAst_yEar_d4m7_so0o_original_Brou}`
Points: `40`
Difficulty: `Hard`
Category: `Cryptography`