# Building

```Python
import random
import string
import re
from itertools import permutations

ALPHABET = string.ascii_uppercase

def char_to_idx(c): 
    return ord(c) - 65
def idx_to_char(i): 
    return chr(i + 65)

# number expansion
def expand_numbers(text):
    mapping = {
        1: "eins",
        2: "zwei",
        3: "drei",
        4: "vier",
        5: "fuenf",
        7: "sieben",
        18: "achtzehn",
        19: "neunzehn",
        24: "vierundzwanzig",
        45: "fuenfundvierzig",
    }

    def repl(m):
        n = int(m.group(0))
        return mapping.get(n, m.group(0))

    return re.sub(r"\d+", repl, text)

def normalize_text(text):
    text = expand_numbers(text)
    text = (
        text.replace('ä','ae').replace('ö','oe').replace('ü','ue')
            .replace('Ä','AE').replace('Ö','OE').replace('Ü','UE')
            .replace('ß','ss').replace('ẞ','SS')
    )
    text = text.upper()
    return ''.join(ch for ch in text if 'A' <= ch <= 'Z')

# engima classes
class Rotor:
    def __init__(self, wiring, notch, ring=0, position=0):
        self.fwd = [char_to_idx(c) for c in wiring]
        self.inv = [0] * 26
        for i,t in enumerate(self.fwd): 
            self.inv[t] = i
        self.notch = char_to_idx(notch)
        self.ring = ring
        self.position = position

    def step(self):
        self.position = (self.position + 1) % 26

    def at_notch(self):
        return self.position == self.notch

    def forward(self, i):
        s = (i + self.position - self.ring) % 26
        m = self.fwd[s]
        return (m - self.position + self.ring) % 26

    def backward(self, i):
        s = (i + self.position - self.ring) % 26
        m = self.inv[s]
        return (m - self.position + self.ring) % 26

class Reflector:
    def __init__(self, wiring):
        self.map = [char_to_idx(c) for c in wiring]

    def reflect(self, i):
        return self.map[i]

class EnigmaMachine:
    def __init__(self, rotors, ref):
        self.L, self.M, self.R = rotors
        self.ref = ref

    def set_positions(self, key):
        self.L.position = char_to_idx(key[0])
        self.M.position = char_to_idx(key[1])
        self.R.position = char_to_idx(key[2])

    def step_rotors(self):
        if self.M.at_notch():
            self.M.step()
            self.L.step()
        elif self.R.at_notch():
            self.M.step()
        self.R.step()

    def enc_char(self, c):
        if c not in ALPHABET: 
            return ""
        self.step_rotors()
        i = char_to_idx(c)
        i = self.R.forward(i)
        i = self.M.forward(i)
        i = self.L.forward(i)
        i = self.ref.reflect(i)
        i = self.L.backward(i)
        i = self.M.backward(i)
        i = self.R.backward(i)
        return idx_to_char(i)

    def enc_text(self, text):
        return ''.join(self.enc_char(c) for c in text if c in ALPHABET)

# known rotor data
def build_rotors(): # enigma 1 with 5 rotors
    return {
        "I":("EKMFLGDQVZNTOWYHXUSPAIBRCJ","Q"),
        "II":("AJDKSIRUXBLHWTMCQGZNPYFVOE","E"),
        "III":("BDFHJLCPRTXVZNYEIWGAKMUSQO","V"),
        "IV":("ESOVPZJAYQUIRHXLNFTGKDCMWB","J"),
        "V":("VZBRGITYUPSDNHLXAWMJQOFECK","Z"),
    }

def build_reflector():
    return Reflector("YRUHQSLDPXNGOKMIEBFZCWVJAT") # B

def plaintext_msg(): # https://enigma.hoerenberg.com/index.php?cat=The%20U534%20messages&page=P1030669
    return (
        "SEHR SEHR DRINGEND [An] Chef 5. U-Flott:\n"
        "1) Torpedofangboot 18 mit 2 Stellkarten Ausrüstung Skagerrak und Norwegen "
        "mit Hafenplänen und 1 Exemplar laufende Befehl B.d.U. Op. Nr. 7 vom 24.4.45. "
        "sofort Neustadt in Marsch setzen.\n"
        "2) Torpedofangboot 19 vorläufig Kiel bleiben.\n"
        "3) Bestätigung erbeten."
    )

def main():
    raw = plaintext_msg()
    pt = normalize_text(raw)

    rotor_defs = build_rotors()
    ref = build_reflector()

    names = list(rotor_defs.keys())

    # rotor order unknown (60), rings = A (0)
    order = random.choice(list(permutations(names, 3)))
    rings = [0, 0, 0]  # Ringstellung = AAA

    # build machine
    Rs = [Rotor(*rotor_defs[o], ring=rings[i]) for i, o in enumerate(order)]
    m = EnigmaMachine(Rs, ref)

    # random starting key
    key = ''.join(random.choice(ALPHABET) for _ in range(3))
    m.set_positions(key)

    ct = m.enc_text(pt)
    with open("cipher.txt","w") as f:
        f.write(ct+"\n")

    print("[DEBUG] Rotor order:", "-".join(order))
    print("[DEBUG] Ring settings: AAA")
    print("[DEBUG] Starting key:", key)
    print("[DEBUG] Normalized plaintext (start):", pt[:200] + "...")
    print("Wrote cipher.txt")

if __name__ == "__main__":
    main()

```

Generate enigma encrypted text using the given source code. Offer players the cipher and some enigma settings.

# Solver

```Python
import string
from itertools import permutations

ALPHABET = string.ascii_uppercase

def char_to_idx(c): 
    return ord(c) - 65
def idx_to_char(i): 
    return chr(i + 65)

def normalize_text(t):
    t = (
        t.replace('ä','ae').replace('ö','oe').replace('ü','ue')
         .replace('Ä','AE').replace('Ö','OE').replace('Ü','UE')
         .replace('ß','ss').replace('ẞ','SS')
    )
    t = t.upper()
    return ''.join(c for c in t if 'A' <= c <= 'Z')

class Rotor:
    def __init__(self, wiring, notch, ring=0, position=0):
        self.fwd = [char_to_idx(c) for c in wiring]
        self.inv = [0] * 26
        for i,t in enumerate(self.fwd): 
            self.inv[t] = i
        self.notch = char_to_idx(notch)
        self.ring = ring
        self.position = position

    def step(self): 
        self.position = (self.position + 1) % 26
    def at_notch(self): 
        return self.position == self.notch

    def forward(self, i):
        s = (i + self.position - self.ring) % 26
        m = self.fwd[s]
        return (m - self.position + self.ring) % 26

    def backward(self, i):
        s = (i + self.position - self.ring) % 26
        m = self.inv[s]
        return (m - self.position + self.ring) % 26

class Reflector:
    def __init__(self, w): 
        self.map = [char_to_idx(c) for c in w]
    def reflect(self, i): 
        return self.map[i]

class EnigmaMachine:
    def __init__(self, rotors, ref):
        self.L, self.M, self.R=rotors
        self.ref=ref

    def set_positions(self, key):
        self.L.position = char_to_idx(key[0])
        self.M.position = char_to_idx(key[1])
        self.R.position = char_to_idx(key[2])

    def step(self):
        if self.M.at_notch():
            self.M.step()
            self.L.step()
        elif self.R.at_notch():
            self.M.step()
        self.R.step()

    def enc_char(self, c):
        if c not in ALPHABET: 
            return ""
        self.step()
        i = char_to_idx(c)
        i = self.R.forward(i)
        i = self.M.forward(i)
        i = self.L.forward(i)
        i = self.ref.reflect(i)
        i = self.L.backward(i)
        i = self.M.backward(i)
        i = self.R.backward(i)
        return idx_to_char(i)

    def enc_text(self, text):
        return ''.join(self.enc_char(c) for c in text)

def build_rotors():
    return {
        "I":("EKMFLGDQVZNTOWYHXUSPAIBRCJ","Q"),
        "II":("AJDKSIRUXBLHWTMCQGZNPYFVOE","E"),
        "III":("BDFHJLCPRTXVZNYEIWGAKMUSQO","V"),
        "IV":("ESOVPZJAYQUIRHXLNFTGKDCMWB","J"),
        "V":("VZBRGITYUPSDNHLXAWMJQOFECK","Z"),
    }

def build_reflector(): 
    return Reflector("YRUHQSLDPXNGOKMIEBFZCWVJAT")

def main():
    cipher = open("cipher.txt").read().strip()
    crib = normalize_text("Torpedofangboot")

    rotor_defs = build_rotors()
    names = list(rotor_defs.keys())
    ref = build_reflector()

    total = 0

    for order in permutations(names, 3):
        print(f"Trying rotor order: {'-'.join(order)}")

        L_def = rotor_defs[order[0]]
        M_def = rotor_defs[order[1]]
        R_def = rotor_defs[order[2]]

        # RINGSTELLUNG = AAA
        ringL, ringM, ringR = 0, 0, 0

        for a in ALPHABET:
            for b in ALPHABET:
                for c in ALPHABET:
                    key = a + b + c

                    L = Rotor(*L_def, ring=ringL)
                    M = Rotor(*M_def, ring=ringM)
                    R = Rotor(*R_def, ring=ringR)

                    mach = EnigmaMachine([L, M, R], ref)
                    mach.set_positions(key)

                    pt = mach.enc_text(cipher)
                    total += 1

                    if crib in pt:
                        print("\nSOLVED!")
                        print("Rotor order:", "-".join(order))
                        print("Ringstellung: AAA")
                        print("Starting key:", key)
                        print("\nPlaintext:\n", pt)
                        print("\nTotal tested:", total)
                        return

    print("Not found. Tested", total, "configurations.")

if __name__ == "__main__":
    main()
```

# Challenge description

Name: `Germany's Downfall`

Description:
```
During the final months of WWII, German naval units continued to use the Kriegsmarine Enigma I for administrative communications. Messages often included routine instructions, logistics, and vessel movements. Because the Enigma could only encipher the letters A–Z, German messages were first normalized: numbers were written out as German words (e.g., 18 → “achtzehn”), umlauts were spelled phonetically (“ü” → “ue”), and all punctuation and spaces were removed before transmission.

You have intercepted one such encrypted naval message. The original plaintext is unknown, but intelligence confirms that it contains the word “Torpedofangboot”, which appears frequently in naval logistics.

You may assume:

- The machine is a Kriegsmarine Enigma I.
- Rotor inventory available: I, II, III, IV, V.
- Exactly three distinct rotors were used, but the order is unknown.
- The ring settings (Ringstellung) are known to be A-A-A.
- The starting rotor positions (Grundstellung) are unknown (AAA–ZZZ).
- Reflector is B.
- No plugboard connections were used.

Provide the flag by creating a SHA256 hash of the date in the decrypted ciphertext (`ISMCTF{sha256(date_in_format-dd/mm/yyyy)}`).
```

Given ciphertext: `KPCVGWTYJFFPHBXOVVZVRYUEAKLABDSHUPXVIIXAEMFEUVKWLDFIHNLIHKEQQKWPHYVKKPOBJIHRRWOGMVMSJHLWTUWHVYMJZXFMMWQDIKJLUPMWDFONCCFDRLIZQTEDLDUKQFPOFDVQVIAHMGSGIAJUVLFYNSOVUYIKNBXHZGNOJJCHQVXWVJTFJRVXOJQAHVMHHAXREHMPQJKOAYJLURWCDLSHCPOGINUMUHNGAVZUCLAHAQNUNYBLEQOCGJOQDMWHYWYJOFSSZJDRWYYEXFNNXOLJXDMLSXQVSLNNRNGHL`

Flag: `ISMCTF{4489ffc43d0e598f9a54c11d05ebc3c1257d43b772aa6e448be756073cbb6112}`
Points: `25`
Difficulty: `Medium`
Category: `Cryptography`
Hint 1 - 20 points: `Simply bruteforce the starting rotor positions. It should take a few minutes. Then pop the resulting text in a german lexer (or send it to AI) and get the date.`.
