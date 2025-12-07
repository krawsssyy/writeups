# Building

```Python
import string
alphabet = string.ascii_uppercase

def vigenere_encrypt(plaintext, key):
    plaintext = ''.join(c for c in plaintext.upper() if c in alphabet)  # strip non-letters
    key = key.upper()
    out = []
    klen = len(key)
    for i, ch in enumerate(plaintext):
        pi = alphabet.index(ch)
        ki = alphabet.index(key[i % klen])
        out.append(alphabet[(pi + ki) % 26])
    return ''.join(out)

pt = "THE FLAG IS ISMCTF{VIGENERE_IS_A_REALLY_OLD_CIPHER_BUT_STILL_QUITE_TRICKY_TO_SOLVE_INNIT} LOREM IPSUM DOLOR SIT AMET CONSECTETUR ADIPISCING ELIT ETIAM VITAE LECTUS LOBORTIS DICTUM URNA NON IACULIS ARCU LOREM IPSUM DOLOR SIT AMET CONSECTETUR ADIPISCING ELIT DONEC A TRISTIQUE LIBERO ORNARE PHARETRA AUGUE SUSPENDISSE TURPIS LEO INTERDUM NON PURUS EU RUTRUM DAPIBUS IPSUM NULLAM VEL ELIT SEMPER FEUGIAT DUI A ELEIFEND SAPIEN SED ID PORTA ERAT NON VEHICULA DOLOR PELLENTESQUE SOLLICITUDIN MI JUSTO ID FACILISIS LIGULA CONSEQUAT ET SUSPENDISSE ELIT NULLA MOLESTIE EGET ALIQUET EU VIVERRA EGET NUNC PELLENTESQUE MOLESTIE AUGUE IN QUAM VESTIBULUM RHONCUS SUSPENDISSE EGET ENIM ENIM AENEAN LIGULA NISL FINIBUS VEL ODIO AT POSUERE CONDIMENTUM AUGUE CURABITUR LAOREET UT NEQUE SED VARIUS IN HAC HABITASSE PLATEA DICTUMST CURABITUR POSUERE RISUS ET FINIBUS IMPERDIET LEO ELIT MALESUADA VELIT NEC LACINIA LIBERO AUGUE VITAE RISUS"
ct = vigenere_encrypt(pt, "DUPERKEZ")

with open("cipher.txt", "w") as f:
    f.write(ct)

```

Generate a cipher.txt with the wanted parameters. Players will be given only the ciphertext value and the knowledge that text was encrypted using Vigenere + the flag format (ISMCTF{...} and words are split by `_`)

# Solution

Use Friedman/Kaiski analysis to guess key length, then do simple frequency analysis for solving to find the best matches given english alphabet.

```Python
import sys
import re
import string
from collections import Counter
from math import gcd

alphabet = string.ascii_uppercase
A2I = {c: i for i, c in enumerate(alphabet)}
I2A = {i: c for i, c in enumerate(alphabet)}

# expected English letter frequencies (normalized)
ENG_FREQ = {
    'A': .08167, 'B': .01492, 'C': .02782, 'D': .04253, 'E': .12702,
    'F': .02228, 'G': .02015, 'H': .06094, 'I': .06966, 'J': .00153,
    'K': .00772, 'L': .04025, 'M': .02406, 'N': .06749, 'O': .07507,
    'P': .01929, 'Q': .00095, 'R': .05987, 'S': .06327, 'T': .09056,
    'U': .02758, 'V': .00978, 'W': .02360, 'X': .00150, 'Y': .01974,
    'Z': .00074
}

def index_of_coincidence(text):
    N = len(text)
    freqs = Counter(text)
    return sum(v*(v-1) for v in freqs.values()) / (N*(N-1)) if N > 1 else 0

def friedman(cipher):
    # estimate key length statistically
    IC = index_of_coincidence(cipher)
    if IC == 0:
        return 1
    K = (0.027 * len(cipher)) / ((len(cipher)-1)*IC - 0.038*(len(cipher)-1) + 0.065)
    return max(1, round(K))

def kasiski(cipher):
    # find repeated trigrams and take gcd of distances.
    distances = []
    for N in range(3, 6):  # check 3-5 letter repeats
        seen = {}
        for i in range(len(cipher)-N):
            trigram = cipher[i:i+N]
            if trigram in seen:
                distances.append(i - seen[trigram])
            seen[trigram] = i
    if not distances:
        return None
    g = distances[0]
    for d in distances[1:]:
        g = gcd(g, d)
    return g if g >= 2 else None

def solve_caesar_column(col):
    # find shift that best matches English frequency
    best_shift = 0
    best_score = float('inf')

    for shift in range(26):
        decrypted = ''.join(I2A[(A2I[c] - shift) % 26] for c in col)
        counts = Counter(decrypted)
        N = len(decrypted)

        # chi-squared statistic
        chi2 = 0
        for letter, expected_freq in ENG_FREQ.items():
            observed = counts[letter]
            expected = expected_freq * N
            chi2 += (observed - expected)**2 / (expected + 1e-9)

        if chi2 < best_score:
            best_score = chi2
            best_shift = shift

    return best_shift

def vigenere_decrypt(cipher, key):
    out = []
    for i, c in enumerate(cipher):
        shift = A2I[key[i % len(key)]]
        out.append(I2A[(A2I[c] - shift) % 26])
    return ''.join(out)

def auto_solve(cipher):
    cipher = ''.join(c for c in cipher.upper() if c in alphabet)

    friedman_guess = friedman(cipher)
    kasiski_guess = kasiski(cipher)

    print(f"Friedman key length estimate: {friedman_guess}")
    print(f"Kasiski key length guess: {kasiski_guess}")

    # try several candidate lengths
    candidates = []
    if kasiski_guess:
        candidates.append(kasiski_guess)
    candidates += [friedman_guess - 2, friedman_guess - 1, friedman_guess, friedman_guess + 1, friedman_guess + 2]
    candidates = [k for k in candidates if k >= 1]

    tried = set()
    for key_len in candidates:
        if key_len in tried:
            continue
        tried.add(key_len)

        print(f"\nTrying key length = {key_len}")

        key_shifts = []
        for i in range(key_len):
            col = cipher[i::key_len]
            shift = solve_caesar_column(col)
            key_shifts.append(shift)

        key = ''.join(I2A[s] for s in key_shifts)
        print(f"    Key guess: {key}")

        pt = vigenere_decrypt(cipher, key)
        print("    Preview:")
        print("    " + pt[:200])
        print()
    print("Choose the correct key from above.")

def main():
    with open("cipher.txt") as f:
        cipher = f.read()

    auto_solve(cipher)

if __name__ == "__main__":
    main()

```

# Challenge description

Name: `War Chronicles`

Description:
```
An old battlefield journal has resurfaced. Its pages filled not with stories, but with a cryptic script the generals once used to relay secret orders across the front. Every line of the Chronicle seems ordinary at first glance, yet the patterns beneath the surface whisper of a hidden strategy encoded long ago, Vigenere.

Historians claim the key to unlocking the journal was lost in the chaos of war, leaving only the ciphered text behind. But careful eyes know that even the most disciplined code can betray subtle rhythms and repeated truths.

Study the Chronicle, follow its patterns, and uncover the message buried behind its shifting letters.
The war may be over, but its secrets are not.

Flag format: ISMCTF{uppercased_words_inside_split_by_underline}
```

Provided ciphertext: `WBTJCKKHVCHQTDJULATRVBIHVUGIRVPXRFSGZZLDUVJXJDMKOKJMKOXQLWZCKYWNOPTMEXMSOIGIDSTRXGSSCYVRLNPQVDGNQMTGKOXTUUSMGSWBLHVICSXDWCPQMSXZHFTGKEWKRVDVKSWCLWIYDEVMDHDRZKGTOCHEIMYKRLTQZZWTPXDPFBWHWUBIKMSMVYRXVDYQDXXTZCGHQATPZDHNQYREKBMRWCFYVVMAHLDSIXEQHJWEIOXQDUJKLOWTVJTRUSWRHNJVGSWKHIXRKOVCXGCSEZYQXMTYIEXQXGSEGSFTVCEWLWRTOFPQMOPDOCIWVWTDUZTYXSESGOXEVVIHIYCHJKTHHHHIUSHORLIEVBESQICZVRMBXFPHFVSQSYAPVXXDVKJIJYPKLWXXLNMMPCYYJDSHGZPGZVMRLMAMXEPZFICWVAYZWYIWLCTDQXXWJOIKLNCYCVELRFTWKSIDJYIECSUTHNTYMSZDULPIXOXMXHRTVVPDQNTWHEILRFTWKSIZXAJIZXUTDGKIJDMAXFJQIRSMFOHWLCTDQXXWJOIFHNTRZWIMLGPIEOEMOCVYCKRHVFUMESFTVPTPFNMNDNESJEIQHWDRUSQDQNJQREKTHWJVRLMSXLAEFBIDWOIRVAYDVYSZRBMTVCCLRMLZECIEJCIOOUIIRNMBWOBWKMYQDVXXLBTNVOTVVBMRXMTXWSRHEOHMDZIQGCTXCOSDOCIQRVIRXUSEMOPHWHTGCKGHQCPPZLIQRUJKLOZHWUTVZCYR`

Flag: `ISMCTF{VIGENERE_IS_A_REALLY_OLD_CIPHER_BUT_STILL_QUITE_TRICKY_TO_SOLVE_INNIT}`
Points: `25`
Difficulty: `Medium`
Category: `Cryptography`
Hint 1 - 7 points: `Given a Vigenere cipher, search for methods for decrypting it when the key and its length are unknown. There are various cryptanalysis and statistical methods for breaking it quite easily.`
Hint 2 - 13 points: `Do Friedman/Kaiski analysis for the key length, and then use frequency analysis for determining the key. The decoded output contains no spaces, so reconstruct it based on the words there and then join them by _, wrapping everything in ISMCTF{...}.`