# Building

```Python
phrase = "ISMCTF{F0r3nsics_m4d3_ezz_with_1s_and_0z!!}"

bits = "".join(format(ord(c), "08b") for c in phrase)
mapping = {"0": "\t", "1": "\n"}
encoded = "".join(mapping[b] for b in bits)

open("SoundOfSilence.bin", "wb").write(encoded.encode())

```

# Solver script

```Python
data = open("SoundOfSilence.bin","rb").read().decode()

candidates = [
    {"\t":"0", "\n":"1"},
    {"\t":"1", "\n":"0"}
]

for rev in candidates:
    try:
        bits = "".join(rev[c] for c in data)
        out = "".join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8))
        if "ISMCTF{" in out:
            print(out)
            break
    except:
        pass

```

# Challenge description

Name: `Sound of silence`

Description:
```
Shhh....
```

Flag: `ISMCTF{F0r3nsics_m4d3_ezz_with_1s_and_0z!!}`
Points: `5`
Difficulty: `Easy`
Category: `Forensics`
Hint 1 - 4 points: `Hmm, I wonder what counting system uses only 2 digits...`