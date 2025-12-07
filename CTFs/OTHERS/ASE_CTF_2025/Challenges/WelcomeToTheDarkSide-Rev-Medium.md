# Building

```Python
from pwn import *

context.arch = 'amd64'

FLAG_PATH = "/home/kali/Desktop/flag.txt"
BUF_SIZE  = 0x100

sc = ""
# open(path, O_RDONLY, 0)
sc += shellcraft.open(FLAG_PATH, 'O_RDONLY', 0)

# read(fd = rax, buf = rsp, count = BUF_SIZE)
# On return:
# rax = number of bytes read
# rsp = buffer start
sc += shellcraft.read('rax', 'rsp', BUF_SIZE)


# inline asm
# 1. chacha-inspired quarter round and streamed key from key "gr00t_groot"
# 2. hex-encode the ciphertext for useful prints
# 3. result: rdi = ptr to hex string, rdx = hex length
sc += r"""
    /* rax = length, rsp = buffer */
    mov rdi, rsp
    mov rsi, rax
    mov rdx, rax

    /* chacha-ish state derived from "gr00t_groot" ("expand 32-byte k" ^ ZEXT("gr00t_groot")) */
    mov r12d, 0x51400a02
    mov r13d, 0x41473b1a
    mov r14d, 0x7916425d
    mov r15d, 0x6b206574

encrypt_loop:
    cmp rsi, 0
    je encrypt_done

    /* quarter-round */
    add r12d, r13d
    xor r15d, r12d
    rol r15d, 16

    add r14d, r15d
    xor r13d, r14d
    rol r13d, 12

    add r12d, r13d
    xor r15d, r12d
    rol r15d, 8

    add r14d, r15d
    xor r13d, r14d
    rol r13d, 7

    /* encrypt byte */
    mov al, [rdi]
    mov bl, r12b
    xor al, bl
    mov [rdi], al

    inc rdi
    dec rsi
    jmp encrypt_loop

encrypt_done:

    /* hex-encode ciphertext */
    mov rcx, rdx
    test rcx, rcx
    jz hex_done

    lea rsi, [rsp]
    lea rdi, [rsp + rdx*2]

hex_loop:
    dec rcx
    mov al, [rsi + rcx]
    mov bl, al
    and bl, 0x0f
    mov dl, bl
    add dl, '0'
    cmp dl, '9'
    jle .low_ok
    add dl, 39
.low_ok:
    dec rdi
    mov [rdi], dl

    mov al, [rsi + rcx]
    shr al, 4
    add al, '0'
    cmp al, '9'
    jle .high_ok
    add al, 39
.high_ok:
    dec rdi
    mov [rdi], al

    test rcx, rcx
    jnz hex_loop

hex_done:
    shl rdx, 1
"""


# write(1, rdi, rdx)  ; stdout <- hex(ciphertext)
sc += shellcraft.write(1, 'rdi', 'rdx')

# exit(0)
sc += shellcraft.exit(0)

shellcode = asm(sc)

print(f"Shellcode length: {len(shellcode)} bytes")
print("Shellcode (hex):")
print(enhex(shellcode))

```

Loader for testing:
```C
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

unsigned char shellcode[] = "\x68\x75\x79\x75\x01\x81\x34\x24\x01\x01\x01\x01\x48\xb8\x6f\x70\x2f\x66\x6c\x61\x67\x2e\x50\x48\xb8\x6c\x69\x2f\x44\x65\x73\x6b\x74\x50\x48\xb8\x2f\x68\x6f\x6d\x65\x2f\x6b\x61\x50\x48\x89\xe7\x31\xd2\x31\xf6\x6a\x02\x58\x0f\x05\x48\x89\xc7\x31\xc0\x31\xd2\xb6\x01\x48\x89\xe6\x0f\x05\x48\x89\xe7\x48\x89\xc6\x48\x89\xc2\x41\xbc\x02\x0a\x40\x51\x41\xbd\x1a\x3b\x47\x41\x41\xbe\x5d\x42\x16\x79\x41\xbf\x74\x65\x20\x6b\x48\x83\xfe\x00\x74\x39\x45\x01\xec\x45\x31\xe7\x41\xc1\xc7\x10\x45\x01\xfe\x45\x31\xf5\x41\xc1\xc5\x0c\x45\x01\xec\x45\x31\xe7\x41\xc1\xc7\x08\x45\x01\xfe\x45\x31\xf5\x41\xc1\xc5\x07\x8a\x07\x44\x88\xe3\x30\xd8\x88\x07\x48\xff\xc7\x48\xff\xce\xeb\xc1\x48\x89\xd1\x48\x85\xc9\x74\x3d\x48\x8d\x34\x24\x48\x8d\x3c\x54\x48\xff\xc9\x8a\x04\x0e\x88\xc3\x80\xe3\x0f\x88\xda\x80\xc2\x30\x80\xfa\x39\x7e\x03\x80\xc2\x27\x48\xff\xcf\x88\x17\x8a\x04\x0e\xc0\xe8\x04\x04\x30\x3c\x39\x7e\x02\x04\x27\x48\xff\xcf\x88\x07\x48\x85\xc9\x75\xcb\x48\xd1\xe2\x48\x89\xfe\x6a\x01\x5f\x6a\x01\x58\x0f\x05\x31\xff\x6a\x3c\x58\x0f\x05";

int main(void) {
    size_t len = sizeof(shellcode) - 1;

    void *buf = mmap(NULL, len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    memcpy(buf, shellcode, len);
    ((void(*)())buf)();

    return 0;
}
```

# Solution

```Python
#!/usr/bin/env python3
from typing import List

KEY = b"gr00t_groot"

CHACHA_CONSTS = [
    0x61707865, # "expa"
    0x3320646e, # "nd 3"
    0x79622d32, # "2-by"
    0x6b206574, # "te k"
]

def init_state() -> List[int]:
    k16 = KEY.ljust(16, b"\x00")
    k_words = [int.from_bytes(k16[i:i+4], "little") for i in range(0, 16, 4)]
    state = [(c ^ k) & 0xffffffff for c, k in zip(CHACHA_CONSTS, k_words)]
    return state

def rotl32(x: int, n: int) -> int:
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def quarter_round(state: List[int]) -> None:
    # same quarter round as in shellcode - (a, b, c, d) = (s0, s1, s2, s3)

    # a += b; d ^= a; d <<<= 16;
    # c += d; b ^= c; b <<<= 12;
    # a += b; d ^= a; d <<<= 8;
    # c += d; b ^= c; b <<<= 7;
    
    a, b, c, d = state

    a = (a + b) & 0xffffffff
    d ^= a
    d = rotl32(d, 16)

    c = (c + d) & 0xffffffff
    b ^= c
    b = rotl32(b, 12)

    a = (a + b) & 0xffffffff
    d ^= a
    d = rotl32(d, 8)

    c = (c + d) & 0xffffffff
    b ^= c
    b = rotl32(b, 7)

    state[0], state[1], state[2], state[3] = a, b, c, d

def stream_cipher_keystream(len_bytes: int) -> bytes:
	# produce len_bytes keystream using the same logic as the shellcode
	# each byte uses state[0] after a quarter_round
    state = init_state()
    ks = bytearray()
    for _ in range(len_bytes):
        quarter_round(state)
        ks.append(state[0] & 0xff)
    return bytes(ks)

def encrypt(plaintext: bytes) -> bytes:
    ks = stream_cipher_keystream(len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, ks))

def decrypt(ciphertext: bytes) -> bytes:
    # stream cipher => encryption == decryption
    return encrypt(ciphertext)

def main():
    import sys

    data = sys.stdin.read().strip()
    if not data:
        print("Usage: echo <hex_ciphertext> | python3 solve.py")
        sys.exit(1)

    ciphertext = bytes.fromhex(data)
    plaintext = decrypt(ciphertext)
    sys.stdout.buffer.write(plaintext + b"\n")

if __name__ == "__main__":
    main()

```

# Challenge description

Name: `Welcome to the dark side`

Description:
```
If you've reached this far, you deserve a medal, congrats! Inspect the following piece we extracted from an in-memory execution of a ransomware and get the flag.
```

Provided encrypted flag: `d61a1551ec147674b6f9ec7692203107f69baf1c9230203a5d7a245fd2e5a148c263ef626e57a964b4fae6e6f00c72e324361247`

Flag: `ISMCTF{sh3l1c0d3_anal1SYS_l34d5_THE_wayyyy_brothaa}`
Points: `30`
Difficulty: `Medium`
Category: `Reverse Engineering`
Hint 1 - 10 points: `Write a small C loader for the shellcode and debug it.`
Hint 2 - 18 points: `Its a stream cipher (its just a simpler version of ChaCha20), so its symmetrical. Just redo the encryption.`