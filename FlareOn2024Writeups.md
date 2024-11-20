# 1 - Frog

Simple PyGame app where we are given the .py source. We are asked to play the game and reach some statue for the flag to reveal itself.

We see this is the generating function for the flag:

```Python
def GenerateFlagText(x, y):
    key = x + y*20
    encoded = "\xa5\xb7\xbe\xb1\xbd\xbf\xb7\x8d\xa6\xbd\x8d\xe3\xe3\x92\xb4\xbe\xb3\xa0\xb7\xff\xbd\xbc\xfc\xb1\xbd\xbf"
    return ''.join([chr(ord(c) ^ key) for c in encoded])
```

We see that it depends on the `(x, y)` coordinates, and those are in the range `0-800` and `0-600`. Hence, a simple brute force checking for the flag would work.

```Python
def GenerateFlagText(x, y):
    key = x + y*20
    encoded = "\xa5\xb7\xbe\xb1\xbd\xbf\xb7\x8d\xa6\xbd\x8d\xe3\xe3\x92\xb4\xbe\xb3\xa0\xb7\xff\xbd\xbc\xfc\xb1\xbd\xbf"
    return ''.join([chr(ord(c) ^ key) for c in encoded])

if __name__ == "__main__":
	for x in range(800):
		for y in range(600):
			r = GenerateFlagText(x, y)
			if "@flare" in r:
				print(r)
				break
```

FLAG: `welcome_to_11@flare-on.com`

# 2 - Checksum

Insanely shitty challenge :D

We're provided a golang PE. Upon running it, it seems to be asking us to perform some additions, and after that it asks us for a checksum without any prompts.
Opening the binary in IDA, we can see that after the round of math testing, it requires us to input a hex string of length 32. It will go on and use that hex string to derive the XChaCha20Poly1305 key and nonce from our input, and it will attempt to decrypt the encrypted flag with it, so, unless we give the correct sha256, it won't decrypt correctly.

Further fiddling with the code, we see a final function before the flag.jpg is written onto disk.

```C++
__int64 __fastcall main_a(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  unsigned __int8 *v6; // rax
  __int64 v7; // rbx
  __int64 v8; // r14
  __int64 v9; // rax
  unsigned __int8 *v10; // r8
  int v11; // r9d
  __int64 v12; // rcx
  unsigned __int8 *v13; // rdx
  __int64 i; // rbx
  unsigned __int8 *v15; // rdi
  unsigned __int64 v16; // rax
  __int64 v17; // rdx
  __int64 v18; // rbx
  __int64 v19; // rdi
  __int64 v20; // rdx
  __int64 v22; // [rsp-20h] [rbp-28h]
  __int64 v23; // [rsp-18h] [rbp-20h]
  __int64 v24; // [rsp-10h] [rbp-18h]
  unsigned __int8 *v25; // [rsp+0h] [rbp-8h]
  void *retaddr; // [rsp+10h] [rbp+8h] BYREF

  if ( (unsigned __int64)&retaddr <= *(_QWORD *)(v8 + 16) )
    ((void (__fastcall __noreturn *)(__int64, __int64, __int64, __int64, __int64, __int64))runtime_morestack_noctxt_abi0)(
      a1,
      a2,
      a3,
      a4,
      a5,
      a6);
  if ( !v6 )
    v6 = (unsigned __int8 *)&runtime_noptrbss;
  v25 = v6;
  v9 = runtime_makeslice(a1, a2, a3, v7, a5, a6);
  v12 = v7;
  v13 = v25;
  for ( i = 0LL; v12 > i; ++i )
  {
    a2 = v9;
    v15 = v13;
    v16 = i - 11 * ((__int64)((unsigned __int128)(i * (__int128)0x5D1745D1745D1746LL) >> 64) >> 2); // fancy mod 11
    v17 = v13[i];
    if ( v16 >= 0xB )
      runtime_panicIndex(v15, a2, v17, 11LL);
    v10 = byte_7F8035;
    v11 = byte_7F8035[v16];
    *(_BYTE *)(a2 + i) = v11 ^ v17;
    v9 = a2;
    v13 = v15;
  }
  v18 = v9;
  v19 = v12;
  encoding_base64___Encoding__EncodeToString(v12, a2, runtime_bss, v12, (_DWORD)v10, v11, v22, v23, v24);
  if ( v18 == 88 )
    return ((__int64 (__fastcall *)(__int64, __int64, __int64, __int64))runtime_memequal)(v19, a2, v20, 88LL);
  else
    return 0LL;
}
```

It applies XOR on the bytes of our checksum input with the key "FlareOn2024", then encodes the result with base64 and checks it against a predefined value. I got stuck here for quite a while, because while debugging I was looking directly at source code and upon reaching the check, both buffers seemed equal all the type. Luck struck, and I went to look at the assembly of that call, as it was getting quite annoying.

```asm
.text:00000000007D785A loc_7D785A:                             ; CODE XREF: main_a+B4↑j
.text:00000000007D785A                 lea     rbx, unk_800A10
.text:00000000007D7861                 mov     ecx, 58h ; 'X'
.text:00000000007D7866                 call    runtime_memequal
```

We see a `lea` being performed, and upon inspecting that, we see a base64 encoded string. If we decode it, and then apply XOR with the same key, we get a hash. Inputting that hash as the checksum yields the flag (dropped in AppData as JPG \./).

FLAG: `Th3_M4tH_Do_b3_mAth1ng@flare-on.com`

# 3 - aray

We are presented with a big Yara rule with a lot of byte conditions, and we need to obtain the file that would match that rule. Seems like an ideal job of `z3`.

Looking through the conditions, we can see that some are redundant (`byte % value < value` - this is always true), knowing that the result is text (specifically rules that state that some `byte < 128` and the ones where `byte & 128 == 0`, which translates to `byte < 128`). Then, we can infer some values already, by having the conditions that the byte equals some calculation. I saved those separately and then removed all other conditions that were using that offset.

From there, we have quite a few of conditions that impose certain 2 bytes have a specific `MD5`/`SHA256` hash or `CRC32` checksum. I cracked these and obtained their values and again put those separately, together with removing all references of those offsets from the rest of the conditions. 

Putting all the aforementioned conditions together, I noticed that we have somewhere `fl`, and pretty close a `n.`, which seems oddly close to the flag format (email address `@flare-on.com`), so I guessed (lucky guess) that all bytes in between are that, and marked them accordingly, removing further references of these offsets.

In the end, I converted all other rules in `z3` format and added the rest of the rules, together with the ones focusing on double-words (`uint32`). However, last `uint32` rule seems to break `z3` such that it wouldn't find any solutions, so I had to brute-force 4 bytes that would get us the target `MD5` hash for the entire file.

```Python
from z3 import *

s = Solver()
flag = [BitVec(f'b{i}', 8) for i in range(85)]
for x in flag:
    s.add(Or(x >= 32, x <= 127))

s.add(Sum(flag) == 85) # filesize

s.add(flag[0] == ord('r'))
s.add(flag[1] == ord('u'))
s.add(flag[32] == ord('u'))
s.add(flag[33] == ord('l'))
s.add(flag[50] == ord('3'))
s.add(flag[51] == ord('A'))
s.add(flag[76] == ord('i'))
s.add(flag[77] == ord('o'))
s.add(flag[14] == ord(' '))
s.add(flag[15] == ord('s'))
s.add(flag[55] == ord('@'))
s.add(flag[56] == ord('f'))
s.add(flag[57] == ord('l'))
s.add(flag[58] == ord('a'))
s.add(flag[59] == ord('r'))
s.add(flag[60] == ord('e'))
s.add(flag[61] == ord('-'))
s.add(flag[62] == ord('o'))
s.add(flag[63] == ord('n'))
s.add(flag[64] == ord('.'))
s.add(flag[65] == ord('c'))
s.add(flag[66] == ord('o'))
s.add(flag[67] == ord('m'))
s.add(flag[63] == ord('n'))
s.add(flag[64] == ord('.'))
s.add(flag[8] == ord('r'))
s.add(flag[9] == ord('e'))
s.add(flag[34] == ord('e'))
s.add(flag[35] == ord('A'))
s.add(flag[78] == ord('n'))
s.add(flag[79] == ord(':'))
s.add(flag[36] + 4 == 72)
s.add(flag[27] ^ 21 == 40)
s.add(flag[45] ^ 9 == 104)
s.add(flag[74] + 11 == 116)
s.add(flag[75] - 30 == 86)
s.add(flag[2] + 11 == 119)
s.add(flag[7] - 15 == 82)
s.add(flag[21] - 21 == 94)
s.add(flag[16] ^ 7 == 115)
s.add(flag[26] - 7 == 25)
s.add(flag[84] + 3 == 128)

s.add(85 ^ flag[11] != 107)
s.add(flag[17] > 31)
s.add(flag[68] > 10)
s.add(85 ^ flag[28] != 12)
s.add(flag[4] > 30)
s.add(85 ^ flag[73] != 17)
s.add(85 ^ flag[31] != 5)
s.add(flag[3] > 21)
s.add(85 ^ flag[82] != 228)
s.add(85 ^ flag[13] != 42)
s.add(85 ^ flag[6] != 39)
s.add(85 ^ flag[3] != 43)
s.add(85 ^ flag[54] != 39)
s.add(flag[73] > 26)
s.add(flag[70] > 6)
s.add(85 ^ flag[40] != 230)
s.add(85 ^ flag[11] != 33)
s.add(flag[54] > 15)
s.add(85 ^ flag[20] != 83)
s.add(flag[43] > 24)
s.add(85 ^ flag[83] != 197)
s.add(85 ^ flag[43] != 33)
s.add(flag[72] > 10)
s.add(85 ^ flag[47] != 11)
s.add(85 ^ flag[71] != 3)
s.add(85 ^ flag[37] != 37)
s.add(85 ^ flag[70] != 209)
s.add(85 ^ flag[20] != 17)
s.add(85 ^ flag[10] != 44)
s.add(flag[71] > 19)
s.add(85 ^ flag[49] != 156)
s.add(flag[47] > 13)
s.add(flag[29] > 22)
s.add(85 ^ flag[17] != 16)
s.add(85 ^ flag[12] != 226)
s.add(85 ^ flag[6] != 129)
s.add(85 ^ flag[83] != 31)
s.add(flag[11] > 18)
s.add(85 ^ flag[44] != 17)
s.add(85 ^ flag[71] != 128)
s.add(85 ^ flag[43] != 251)
s.add(85 ^ flag[28] != 238)
s.add(85 ^ flag[13] != 219)
s.add(85 ^ flag[53] != 243)
s.add(flag[20] > 1)
s.add(85 ^ flag[39] != 49)
s.add(85 ^ flag[69] != 30)
s.add(flag[30] > 6)
s.add(85 ^ flag[29] != 37)
s.add(85 ^ flag[25] != 47)
s.add(85 ^ flag[24] != 94)
s.add(85 ^ flag[30] != 18)
s.add(85 ^ flag[38] != 84)
s.add(85 ^ flag[42] != 91)
s.add(flag[40] > 15)
s.add(85 ^ flag[18] != 234)
s.add(85 ^ flag[68] != 8)
s.add(85 ^ flag[81] != 7)
s.add(85 ^ flag[23] != 18)
s.add(85 ^ flag[19] != 31)
s.add(flag[82] > 3)
s.add(85 ^ flag[46] != 186)
s.add(flag[6] > 6)
s.add(85 ^ flag[82] != 32)
s.add(85 ^ flag[48] != 29)
s.add(85 ^ flag[39] != 18)
s.add(85 ^ flag[47] != 119)
s.add(85 ^ flag[24] != 217)
s.add(flag[12] > 19)
s.add(85 ^ flag[37] != 141)
s.add(85 ^ flag[53] != 19)
s.add(flag[41] > 5)
s.add(85 ^ flag[12] != 116)
s.add(flag[39] > 7)
s.add(flag[69] > 25)
s.add(85 ^ flag[69] != 241)
s.add(85 ^ flag[17] != 208)
s.add(85 ^ flag[4] != 23)
s.add(85 ^ flag[18] != 33)
s.add(85 ^ flag[68] != 135)
s.add(85 ^ flag[23] != 242)
s.add(flag[18] > 13)
s.add(85 ^ flag[42] != 1)
s.add(85 ^ flag[19] != 222)
s.add(flag[28] > 27)
s.add(flag[19] > 4)
s.add(flag[80] > 2)
s.add(85 ^ flag[22] != 31)
s.add(flag[10] > 9)
s.add(flag[22] > 20)
s.add(85 ^ flag[10] != 205)
s.add(85 ^ flag[48] != 99)
s.add(85 ^ flag[52] != 22)
s.add(85 ^ flag[25] != 224)
s.add(flag[23] > 2)
s.add(85 ^ flag[31] != 32)
s.add(85 ^ flag[81] != 242)
s.add(85 ^ flag[54] != 141)
s.add(flag[24] > 22)
s.add(flag[48] > 15)
s.add(flag[37] > 16)
s.add(flag[13] > 21)
s.add(85 ^ flag[80] != 56)
s.add(85 ^ flag[52] != 238)
s.add(flag[46] > 22)
s.add(85 ^ flag[3] != 147)
s.add(85 ^ flag[30] != 249)
s.add(85 ^ flag[5] != 243)
s.add(85 ^ flag[5] != 43)
s.add(85 ^ flag[72] != 219)
s.add(flag[52] > 25)
s.add(flag[83] > 16)
s.add(flag[31] > 7)
s.add(85 ^ flag[46] != 18)
s.add(flag[53] > 24)
s.add(85 ^ flag[80] != 236)
s.add(85 ^ flag[49] != 10)
s.add(flag[5] > 14)
s.add(85 ^ flag[38] != 8)
s.add(85 ^ flag[72] != 37)
s.add(85 ^ flag[70] != 41)
s.add(flag[38] > 18)
s.add(85 ^ flag[41] != 233)
s.add(85 ^ flag[4] != 253)
s.add(flag[81] > 11)
s.add(85 ^ flag[22] != 191)
s.add(flag[44] > 5)
s.add(85 ^ flag[73] != 61)
s.add(85 ^ flag[29] != 158)
s.add(flag[25] > 27)
s.add(flag[49] > 27)
s.add(85 ^ flag[40] != 49)
s.add(flag[42] > 3)
s.add(85 ^ flag[41] != 74)
s.add(85 ^ flag[44] != 96)

s.add(BitVecVal(425706662, 32) ^ Concat(flag[55], flag[54], flag[53], flag[52]) == 1495724241)
s.add(Concat(flag[20], flag[19], flag[18], flag[17]) - 323157430 == 1412131772)
s.add(BitVecVal(512952669, 32) ^ Concat(flag[62], flag[61], flag[60], flag[59]) == 1908304943)
s.add(Concat(flag[31], flag[30], flag[29], flag[28]) - 419186860 == 959764852)
s.add(BitVecVal(310886682, 32) ^ Concat(flag[69], flag[68], flag[67], flag[66]) == 849718389)
s.add(Concat(flag[13], flag[12], flag[11], flag[10]) + 383041523 == 2448764514)
s.add(Concat(flag[40], flag[39], flag[38], flag[37]) + 367943707 == 1228527996)
s.add(BitVecVal(372102464, 32) ^ Concat(flag[25], flag[24], flag[23], flag[22]) == 1879700858)
s.add(Concat(flag[49], flag[48], flag[47], flag[46]) - 412326611 == 1503714457)
s.add(Concat(flag[73], flag[72], flag[71], flag[70]) + 349203301 == 2034162376)
s.add(Concat(flag[83], flag[82], flag[81], flag[80]) - 473886976 == 69677856)
s.add(BitVecVal(298697263, 32) ^ Concat(flag[6], flag[5], flag[4], flag[3]) == 2108416586)
#s.add(Concat(flag[44], flag[43], flag[42], flag[41]) + 404880684 == 1699114335) - breaks for whatever reason
if s.check() == sat:
    m = s.model()
    solution = [m[b].as_long() for b in flag]
    print(solution)
else:
    print("No solution")
    print(s.unsat_core())
```

```Python
target = "b7dc94ca98aa58dabb5404541c812db2"
from hashlib import md5
res = [114, 117, 108, 101, 32, 102, 108, 97, 114, 101, 111, 110, 32, 123, 32, 115, 116, 114, 105, 110, 103, 115, 58, 32, 36, 102, 32, 61, 32, 34, 49, 82, 117, 108, 101, 65, 68, 97, 121, 75, 51, 71, 29, 34, 85, 97, 108, 119, 52, 114, 51, 65, 119, 52, 121, 64, 102, 108, 97, 114, 101, 45, 111, 110, 46, 99, 111, 109, 34, 32, 99, 111, 110, 100, 105, 116, 105, 111, 110, 58, 32, 36, 102, 32, 125]

a = list(range(32, 127, 1))
for x in a:
	for y in a:
		for w in a:
			for z in a:
				res[41] = x
				res[42] = y
				res[43] = w
				res[44] = z
				s = [chr(x) for x in res]
				s = ''.join(s)
				if md5(s.encode()).hexdigest() == target:
					print(s)
					break
```

FLAG: `1RuleADayK33p$Malw4r3Aw4y@flare-on.com`

# 4 - Meme Maker 3000

We are provided a HTML file with a big JS inside. Opening the file in the browser, we can look through the JS inside (a good idea would be to also have the JS run through a deobfuscator first and look through it there, then go analyze it in the page).

Once analyzing everything, we notice an abnormality in the `a0e` variable which holds the image data for the memes, we see there an image whose data starts with `TVqQA`, which is indicative of a PE file. Getting that base64 decoded and analyzing the PE, it seems to have been just a red herring to distract us.

Going back to the JS code, I started deobfuscating everything to get a better understanding of what's happening. When deobfuscating, we stumble upon an `alert(atob(obfuscated) + var)` call, which strikes some interest. By decoding the base64 inside, we see the text `Congratulations! Here you go: `, so I think we're on the right path (unlike the PE which was a tiny bit mocking as you derypted its strings). Further looking into the function which we got that from, we can see it builds a string from the contents of the text boxes for the memes.

```JavaScript
function a0k() {
  const t = a0p, a = a0g["alt"].split("/")["pop"]();

  if (a !== Object["keys"](a0e)[5]) return;

  const b = a0l.textContent, c = a0m["textContent"], d = a0n.textContent;

  if (a0c["indexOf"](b) == 14 && a0c["indexOf"](c) == a0c["length"] - 1 && a0c["indexOf"](d) == 22) {
    var e = (new Date)["getTime"]();
    while ((new Date)["getTime"]() < e + 3e3) {}
    var f = d[3] + "h" + a[10] + b[2] + a[3] + c[5] + c[c["length"] - 1] + "5" + a[3] + "4" + a[3] + c[2] + c[4] + c[3] + "3" + d[2] + a[3] + "j4" + a0c[1][2] + d[4] + "5" + c[2] + d[5] + "1" + c[11] + "7" + a0c[21][1] + b["replace"](" ", "-") + a[11] + a0c[4]["substring"](12, 15);
    f = f["toLowerCase"](), alert("Congratulations! Here you go: " + f);
  }
}
```

We see that in order to reach that code, we need to have as the first text box the element in the content list from index 14, in the second one index 25, and the third one index 22. Simply doing `const b = aoc[14], c = a0c[25], d = a0c[22];` in the console works just fine. Further more, in order to have 3 text boxes, we need to be on the image who's alt is at index 5 in the list of images, namely `boy_friend0.jpg`. Simply going to that image and doing `const a = = a0g["alt"].split("/")["pop"]();` is fine. Then, we set `const t = a0p;` so we can deobfuscate stuff, and then just copy the definition of `f` and print it out.

FLAG: `wh0a_it5_4_cru3l_j4va5cr1p7@flare-on.com`

# 5 - sshd

Looking through the archive, and seeing that the challenge is named `sshd`, I decided to search for files related, and found an interesting core dump file.

Loading it in gdb (`gdb <path_to_sshd_binary> <path_to_core_dump_file>`) and fixing all shared libraries to be loaded from the correct directories (`set sysroot <path_to_/_in_archive>`). 

After that, I did `bt` to see the stack trace, and saw that the last frame executed code at `0x0` from somewhere in `liblzma`. Doing `disass <addr_from_stack_frame_of_liblzma>, +16`, we see some instructions. 
Opening up in the `liblzma` shared object and searching for the instructions there, we get that its the function at offset `9B20`. Analzying the function, we see that it does some stuff (uninteresting), and then calls `dlsym(0, "RSA_public_decrypt")`, which resolves the address of `RSA_public_decrypt` from openssl.

Opening up `openssl` documentation for that function, we see that its signature is `int RSA_public_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);`, and given that the binaries are 64 bit, by the x64 calling convention, we have that arg1 is in `RDI`, arg2 in `RSI`, arg3 in `RDX`, arg4 in `RCX` and arg5 in `R8`. `flen` is the length of the message digest, `*from` is the memory space where it is held, `*to` is the memory space where the decrypted version will be, `*rsa` is a pointer to an RSA structure holding the public key required and `padding` is an int for whether there is `PKCS1` padding used or no padding.
By inspecting the values in those register, we get that the buffer is `512` bytes, and we also get its location and bytes. Unfortunately, `RCX` is empty and doesn't have our RSA structure.

Checking the other "uninteresting" stuff in the crashing function, we can see a rather interesting string in the first function call: `expand 32-byte k`. Googling this, we see that it's a magic constant used in `ChaCha20` encryption. By analyzing the other function, that one seems to be actually doing the `ChaCha20` encryption/decryption, so guessing the structure is `chacha20_prepArgs();mmap();memcpy(mmap_res, enc_buf, len);chacha20_encrypt_decrypt();run_shellcode();chacha20_prepArgs();chacha20_encrypt_decrypt();`.

By reversing the argument prepping function, we may be able to get the key and nonce.
It looks like it creates the `ChaCha20` context in the first argument, which is in `RDI`. Before it is called, we have `LEA R15, [RSP+0x20];MOV RDI, R15` which is equivalent to `RDI = RSP + 0x20`. We can see that the structure starts holding data at itself + 0x48, which means that important data will start at `RSP + 0x68` in our dump.

Seeing that there's stuff that repeats with sizes matching the key (0x20 bytes) and nonce (0xc bytes or 0x8 bytes), we make an educated guess and test these with the encrypted buffer(`DAT_00123960`) we see (key=`943df638a81813e2de6318a507f9a0ba2dbb8a7ba63666d08d11a65ec914d66f`, nonce=`f236839f4dcd711a52862955`).

By using that key and nonce with the encrypted buffer in cyberchef, we see that it produces valid shellcode `55488BECE8....` => `push rbp; mov rbp, rsp; call...`. So now we got the shellcode, let's debug it. I wrote a simple C program to load it and run it.


```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int main(int argc, char **argv) {
    FILE *f;
    size_t shellcode_size;
    unsigned char *shellcode;
    void (*func)();

    f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror("Failed to open file");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    shellcode_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    shellcode = mmap(NULL, shellcode_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shellcode == MAP_FAILED) {
        perror("mmap failed");
        fclose(f);
        return 1;
    }

    if (fread(shellcode, 1, shellcode_size, f) != shellcode_size) {
        perror("fread failed");
        munmap(shellcode, shellcode_size);
        fclose(f);
        return 1;
    }
    fclose(f);

    printf("Executing\n");
    func = (void (*)())shellcode;
    func();
    munmap(shellcode, shellcode_size);
    return 0;
}
```

By debugging that shellcode, we can see that it does some interesting syscalls.
`sys_socket(AF_INET, SOCK_STREAM, TCP);
sys_connect(fd, 0x0f02000a39050002, 0x10);
recvfrom(fd, buf, 0x20);
recvfrom(fd, buf, 0xc);
recvfrom(fd, buf, 0x4);
recvfrom(fd, buf, 0); // close connection
sys_open(file);
sys_read(fd_file, buf, 0x80);`

And then it proceeds to do some operations, which also include our interesting `expand 32-byte k` string, so this all hints at it using `ChaCha20` again to decrypt the data read from the file.

By seeing what it received, we can only guess (since there's no data as the connection fails), that the 0x20 bytes one is the key, the 0xc bytes one is the nonce, and the 0x4 bytes is some sort of a size (since `sizeof(int)=4`).

Since this shellcode was executed in the context of our `liblzma` binary, this means that the values received are probably on the stack somewhere.

Given that at the start of the functions where it communicates with that `IP` we have `LEA RSP, [RSP-0x1688]` => `RSP=RSP-0x1688`, we can start searching the stack for our pattern (most likely 32 byte key, 12 byte nonce, 4 byte size and then a file name).

By searching the stack around that area, we see that at `RSP-0x1280` we have printable hex codes, which translate to `/root/certificate_authority_signing_key.txt`, and above that, we seem to have that exact pattern.

Thus, we can infer that for this new round, we have the `key=8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7; nonce=111111111111111111111111; size = 0x20`. 

At this point, I wrote a small Python script that'd just decrypt all 0x20 buffers from the core dump, as that read buffer could've been anywhere (it should be rather close but still), but it fails to provide anything of use. (`read` reads 0x80 bytes, but the data from `recvfrom` says 0x20, so we'll go with that for now and see later if we need to adjust)

So, we go on further analyzing the shellcode and seeing whether the decryption algorithm there is custom or we missed something else.
By analzying the shellcode, we can see that the key is located at `rbp-0x1278`, nonce at `rbp-0x1258`, the chacha struct will be at `rbp-0xc8`, and that the buffer read from the file is at `rbp-0x1148`. Seeing as how we found the key and nonce, we can just go `0x110` bytes more from the nonce, and we should have the buffer there.

By using `unicorn` to emulate the encryption code (as it uses a different magic constant and various changed constants), we can try to decrypt our flag.

```Python
import binascii
import unicorn
import unicorn.x86_const as consts

key = binascii.unhexlify("8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7") # key
nonce = binascii.unhexlify("111111111111111111111111") # nonce
blob = b'\xa9\xf6\x34\x08\x42\x2a\x9e\x1c\x0c\x03\xa8\x08\x94\x70\xbb\x8d\xaa\xdc\x6d\x7b\x24\xff\x7f\x24\x7c\xda\x83\x9e\x92\xf7\x07\x1d' # encrypted blob
with open("C:\\malware\\sc.dat", "rb") as f:
    code = f.read()

code_addr = 0x1000000 # address for the code
stack_addr = 0x2000000 # address for the stack
mem_addr = 0x3000000 # address for the memory items
key_addr = mem_addr
iv_addr = mem_addr + 32
chacha_addr = mem_addr + 0x100
crypted_addr = mem_addr + 0x1000

uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64) # initialize the unicorn engine
# map the memory addresses
uc.mem_map(code_addr, 0x10000)
uc.mem_map(stack_addr, 0x10000)
uc.mem_map(mem_addr, 0x10000)
# write our data and set RSP
uc.mem_write(code_addr, code)
uc.mem_write(key_addr, key)
uc.mem_write(iv_addr, nonce)
uc.reg_write(consts.UC_X86_REG_RSP, stack_addr + 0x10000)

init_pos = code.find(binascii.unhexlify("535657415455488BEC488BD84C8BC9498BF032C0488BFBB9C0000000F3AA")) # for finding the address of the init function
init_addr = code_addr + init_pos
# prepare args as they appear in IDA
uc.reg_write(consts.UC_X86_REG_RAX, chacha_addr)
uc.reg_write(consts.UC_X86_REG_RDX, key_addr)
uc.reg_write(consts.UC_X86_REG_RCX, iv_addr)
uc.reg_write(consts.UC_X86_REG_R8, 0)
# emulate code
uc.emu_start(init_addr, init_addr + 118)

crypt_pos = code.find(binascii.unhexlify("5356574154415555488BEC488BF0488BFA4C8BE1488BDE")) # for finding the address of the encryption/decryption functon
uc.mem_write(crypted_addr, blob)
# prepare args as they appear in IDA
uc.reg_write(consts.UC_X86_REG_RDX, crypted_addr)
uc.reg_write(consts.UC_X86_REG_RCX, len(blob))
uc.reg_write(consts.UC_X86_REG_RAX, chacha_addr)
# emulate code
uc.emu_start(code_addr + crypt_pos, code_addr + crypt_pos + 58)
# read the flag
flag = uc.mem_read(crypted_addr, len(blob))
flag = flag.split(b"\n")[0].decode()
print(flag)
```

FLAG: `supp1y_cha1n_sund4y@flare-on.com`

# 6 - Bloke2

Analyzing the files, we see a custom implementation of the Blake2 hashing algorithm in SystemVerilog.

Looking through the files, we see some interesting stuff in the `data_mgr.v` file, namely a register called `tst` and a 512 bits hash value named `TEST_VAL`. Also, in that same file, we see that the what we can only assume is the hash being `XORed` with the TEST_VAL & tst.

```SystemVerilog
always @(posedge clk) begin
    if (rst) begin 
      out_cnt <= 0;
    end else begin
      //$display("%t dmgr dout oc %h", $time, out_cnt);
      if (h_rdy) begin
        //$display("%t dmgr dout h %h t %b", $time, h_in, tst);
        out_cnt <= W;
        h <= h_in ^ (TEST_VAL & {(W*16){tst}});
      end else if(out_cnt != 0) begin
        //$display("%t dmgr dout d %h dv %b de %b oc %h", $time, data_out, dv_out, data_end, out_cnt);
        out_cnt <= out_cnt - 1;
        h <= {8'b0, h[W*8-1:8]};
      end
    end
  end
```

Using some of the debug prints available, we see that the `tst` value is 0. In that same file, we see that `tst` is assigned the value `finish`, which is an input parameter for the `data_mgr` module.

Keeping that in mind, we now search to see where that module is instantiated and see where it gets the value of `finish` from. In the `bloke2.v` file we see the `data_mgr.v` module being created with `finish` also as a parameter for that module. Moving further, in the `bloke2b.v` and `bloke2s.v` files we see them creating a `bloke2` module, having yet again `finish` as an input parameter. Moving on, we have the test benches for each of these files (`bloke2b_tb.v` and `bloke2s_tb.v`), we see them instantiate the `bloke2b`, respectively `bloke2s` modules, and also assigning values to the `finish` variable in the `initial` stage, and also the `hash_message` task.

Setting `finish` to 1 in both files (works for only doing that in `hash_message`, is not necessary to put it in both places) and then running the app with the provided details (`make tests`) yields the flag.

FLAG: `please_send_help_i_am_trapped_in_a_ctf_flag_factory@flare-on.com`
