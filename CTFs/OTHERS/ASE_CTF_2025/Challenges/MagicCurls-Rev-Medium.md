# Building

```
git clone https://github.com/curl/curl.git
... modify source file
autoreconf -fi
./configure
make install
```
Then get libcurl from /usr/local/lib/libcurl.so.*
Additionally, you can link /usr/local/bin/curl for testing via `echo "/usr/local/lib" > /etc/ld.so.conf.d/localcurl.conf` and then `ldconfig` for refreshing.

# Source

Modified `lib/http.c` function `http_add_hd` such that when a specific user agent is passed, we print the flag. The flag is saved encrypted inside the binary with RC4. Replaced the case for `H1_HD_USER_AGENT` with the following code:

```C++
case H1_HD_USER_AGENT:
    if(data->set.str[STRING_USERAGENT] && // regular code
       *data->set.str[STRING_USERAGENT] &&
       data->state.aptr.uagent)
      result = curlx_dyn_add(req, data->state.aptr.uagent);

    // trigger for "magic" user agent
    if(data->set.str[STRING_USERAGENT] &&
       strcmp(data->set.str[STRING_USERAGENT], "magic") == 0) {

        unsigned char S[256];
        int i, j = 0;
		const unsigned char callout[] = "psst...come closer"; // small hint
		fprintf(stderr, "%.*s\n", sizeof(callout), callout);
        const unsigned char key[] = "curl_magic_flag";
        const int keylen = sizeof(key) - 1;

        const unsigned char encrypted_flag[] = {
0xb0, 0x84, 0x63, 0x3e, 0x5c, 0x38, 0xe1, 0xce, 0x0d, 0xe5, 0x8e, 0xa7, 0x73, 0x1d, 0xf8, 0xed, 0x10, 0x3a, 0x2d, 0xa6, 0x51, 0x48, 0x39, 0x80, 0x44, 0xe7, 0x96, 0x31, 0x46, 0x90, 0xdb, 0x35, 0xd8, 0xeb, 0xe8, 0xb8, 0x09, 0x7b, 0xf1, 0x5b, 0x7e, 0xe1, 0xda, 0xf4, 0x21, 0xa6
};
        const int flaglen = sizeof(encrypted_flag);

        // rc4 ksa
        for(i = 0; i < 256; i++) 
        	S[i] = i;
        for(i = 0; i < 256; i++) {
            j = (j + S[i] + key[i % keylen]) & 255;
            unsigned char tmp = S[i];
            S[i] = S[j];
            S[j] = tmp;
        }

        // rc4 crypt
        i = j = 0;
        unsigned char decrypted[256];
        for(int n = 0; n < flaglen; n++) {
            i = (i + 1) & 255;
            j = (j + S[i]) & 255;
            unsigned char tmp = S[i];
            S[i] = S[j];
            S[j] = tmp;
            unsigned char K = S[(S[i] + S[j]) & 255];
            decrypted[n] = encrypted_flag[n] ^ K;
        }
        fprintf(stderr, "%.*s\n", flaglen, decrypted);
    }

    break;
```

Flag generation script:
```Python
def rc4(key, data):
    # ksa
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # crypt
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(byte ^ K)
    return bytes(out)


key = b"curl_magic_flag"
flag = b"ISMCTF{s1d3l0adinG_1s_b4d_but_a7s0_k1NDa_n1CE}"

encrypted = rc4(key, flag)

print("unsigned char encrypted_flag[] = {")
print(", ".join(f"0x{b:02x}" for b in encrypted))
print("};")
print(f"unsigned int encrypted_flag_len = {len(encrypted)};")
```

# Solver

Locate hint in binary's strings. Trace it back to its usage inside the binary. See the requirement and run an example command with the specified user-agent (such as `curl -A "magic" google.com`), that will print the flag (requires linking against the actual `curl` binary on the player's system).

Apart from that, identify RC4 algorithm and decrypt the flag.
```Python
def rc4(key, data):
    # ksa
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # crypt
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(byte ^ K)
    return bytes(out)


key = b"curl_magic_flag"
enc_flag = [0xb0, 0x84, 0x63, 0x3e, 0x5c, 0x38, 0xe1, 0xce, 0x0d, 0xe5, 0x8e, 0xa7, 0x73, 0x1d, 0xf8, 0xed, 0x10, 0x3a, 0x2d, 0xa6, 0x51, 0x48, 0x39, 0x80, 0x44, 0xe7, 0x96, 0x31, 0x46, 0x90, 0xdb, 0x35, 0xd8, 0xeb, 0xe8, 0xb8, 0x09, 0x7b, 0xf1, 0x5b, 0x7e, 0xe1, 0xda, 0xf4, 0x21, 0xa6]
dec = rc4(key, enc_flag)

print(dec.decode())
```

# Challenge description

Name: `Magic curls`

Description:
```
Our monitoring system flagged something strange: a routine HTTP request made by one of our servers triggered an unexpected outbound connection. After some digging, we discovered the culprit wasn’t malware, but a tampered curl binary quietly swapped into place.

Whoever modified it left no obvious artifacts — no suspicious strings, no debug paths, no plaintext secrets. Everything looks almost normal… almost.

Internal logs suggest the binary may be waiting for a specific phrase or special invocation before revealing anything meaningful. We don’t know what the trigger is, or what happens when it’s used, but we do know this:

If someone compromised our curl, they must have left a mechanism for controlling it.
Your task is to reverse the binary and figure out what they built into it.

Find out what this “magic curl” is hiding.
```

Flag: `ISMCTF{s1d3l0adinG_1s_b4d_but_a7s0_k1NDa_n1CE}`
Points: `25`
Difficulty: `Medium`
Category: `Reverse Engineering`
Hint 1 - 15 points: `There's something interesting in the strings, a small breadcrumb, saying "psst". Trace that back to its usage in the binary and see where that leads you, it might have the flag.`
Hint 2 - 9 points: `That piece of code is related to checks against the user-agent. You can either see what it asks, link the libcurl against your actual curl and provide the required value, or you can decrypt the flag yourself after identifying the used algorithm.`