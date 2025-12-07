# Building

Obfuscated this Python script heavily (its just an affine cipher with a modified alphabet)

```Python
_I = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_" 
__II = len(_I)
def _II_(_, __, ___):
    I = []
    for II in _:
        if II in _I:
            III = _I.index(II)
            I.append(_I[(__ * III + ___) % __II])
    return "".join(I)
__III = 7
__IIII = 3
_ = open("flag.txt","r").read().strip()
__ = _II_(_, __III, __IIII)
print(__)
```

# Solver

```Python
import base64
import zlib
from Crypto.Cipher import AES
import re
unpad = lambda s : s[:-ord(s[len(s)-1:])]
data = open("Stages.ps1_", "r").read().strip()

# deobf first ps - just b6
base64_blob = data.split("'")[1].strip()
base64_dec = base64.b64decode(base64_blob).decode()

# deobf next blob - aes enc
k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
aes_b64_blob = base64.b64decode(base64_dec.split("'")[1].strip())
aes = AES.new(k, AES.MODE_CBC, k)
dec = unpad(aes.decrypt(aes_b64_blob))

# deobf js
stage_js = dec
for i in range(5): # obf count - obtained from trial and error
	key = int(stage_js.decode().split("]")[1].split("=")[1].split(";")[0].strip())
	new = b''.join([((int(x) ^ key) & 0xFF).to_bytes(1, "big") for x in stage_js.decode().split("[")[1].split("]")[0].strip().split(",")])
	stage_js = new

# deobf vbs
stage_vbs = stage_js

for i in range(1):
	tmp = stage_vbs.split(b"=chr(102)&chr(111)&chr(114)&chr(32)&chr(")[0]
	tmp = b''.join(tmp.split(b":")[:-2])[:-1]
	idx = tmp.find(b"=\"")
	tmp = tmp[idx + 2:]
	s = b""
	for x in tmp:
		s += ((x + 1) % 256).to_bytes(1, "big")
	stage_vbs = s

# deobf py
stage_py = zlib.decompress(base64.b64decode(stage_vbs.split(b"'")[-2].decode())).decode()
for i in range(36):
	if "b64decode" in stage_py and "::-1" in stage_py:
		blob = stage_py.split("'")[-2].strip()
		stage_py = zlib.decompress(base64.b64decode(blob[::-1])).decode()
	elif "b64decode" in stage_py and "::-1" not in stage_py:
		blob = stage_py.split("'")[-2].strip()
		stage_py = zlib.decompress(base64.b64decode(blob)).decode()

print(stage_py)

# analyze decoded output, see that it is an affine cipher and revert it

_I = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_"

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for a={a} mod {m} (gcd={g})")
    return x % m

def affine_decrypt(text, a, b):
    a_inv = modinv(a, 65) # alphabet length
    res = []
    for ch in text:
        if ch in _I:
            y = _I.index(ch)
            x = (a_inv * (y - b)) % 65
            res.append(_I[x])
        else:
            res.append(ch)
    return "".join(res)

print(affine_decrypt("7_WRGmvnAQGudgg9JFCOF}s}9Cx8}96nSs}z9QX96qWX55Xb9{XXc32", 7, 3))
```

# Challenge description

Name: `Stages`

Description:
```
Our intern got tricked with a FakeCaptcha prompt and ran this powershell code. Please analyze it and uncover its secrets, as it bested our most senior analysts, you're our only chance now, good luck!

We managed to extract this artifact, but we can't make sense of it: `7_WRGmvnAQGudgg9JFCOF}s}9Cx8}96nSs}z9QX96qWX55Xb9{XXc32`

NOTE: This is not a real malware. The obfuscation is malware-like, but end stage is just a regular challenge.
```

Flag: `ISMCTF{hunTiNgg_m4lw43r3_l1k3_ther3s_no_t0MoRRoW_booya}`
Points: `40`
Difficulty: `Hard`
Category: `Forensics`
Hint 1 - 0 points: `That initial string is a base64 string. Decode it and get to work analyzing.`
Hint 2 - 1 point: `Reproduce the decryption of the second base64 string (you have the key and IV) and then analyze next stages.`
Hint 3 - 2 points: `The stages will eventually stop. You better write some code for deobfuscating that. Use CyberChef if you're stubborn, it has a lot of power. Otherwise, Python is your friend since it can easily manipulate everything you need it to in order to reach the end one. It only has 40 stages, nothing too much. You're on your own from now, just do what the file does to decrypt stuff and you'll be just fine. GL!`