# OpTinselTrace 1

## Task 1

Q: What is the name of the email client that Elfin is using?

`eM client` - obtained from liveresponse/pwsh-get-processlist.csv

## Task 2

Q: What is the email the threat is using?

`definitelynotthegrinch@gmail.com` - look into TriageData\C\users\Elfin\Appdata\Roaming\eM Client\Local Folders\mail-data.dat-wal, susp email

## Task 3

Q: When does the threat actor reach out to Elfin?

`2023-11-27 17:27:26` - look into TriageData\C\users\Elfin\Appdata\Roaming\eM Client\Local Folders\conversations.dat-wal, search by email, get date of first

## Task 4

Q: What is the name of Elfins boss?

`elfuttin bigelf` - look into TriageData\C\users\Elfin\Appdata\Roaming\eM Client\Local Folders\conversations.dat-wal

## Task 5

Q: What is the title of the email in which Elfin first mentions his access to Santas special files?

`re: work` - look into TriageData\C\users\Elfin\Appdata\Roaming\eM Client\Local Folders\conversations.dat-wal, look into the chain of emails from the threat actor

## Task 6

Q: The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?

`wendy elflower, 2023-11-28 10:00:21` - look into TriageData\C\users\Elfin\Appdata\Roaming\eM Client\Local Folders\conversations.dat-wal, look into the chain of emails from the threat actor

## Task 7

Q: What is the name of the bar that Elfin offers to meet the threat actor at?

`SnowGlobe` - look into TriageData\C\users\Elfin\Appdata\Roaming\eM Client\Local Folders\conversations.dat-wal, look into the chain of emails from the threat actor

## Task 8

Q: When does Elfin offer to send the secret files to the actor?

`2023-11-28 16:56:13` - look into TriageData\C\users\Elfin\Appdata\Roaming\eM Client\Local Folders\conversations.dat-wal, look into the chain of emails from the threat actor

## Task 9

Q: What is the search string for the first suspicious google search from Elfin? (Format: string)

`how to get around work security` - load TriageData\C\users\Elfin\Appdata\Local\Google\Chrome\User Data\Default\History into a sqllite db viewer and look at cluster_keywords table data

## Task 10

Q: What is the name of the author who wrote the article from the CIA field manual?

`Joost Minnaar` - load TriageData\C\users\Elfin\Appdata\Local\Google\Chrome\User Data\Default\History into a sqllite db viewer and look at urls table data

## Task 11

Q: What is the name of Santas secret file that Elfin sent to the actor?

`santa_deliveries.zip` - look into TriageData\C\users\Elfin\Appdata\Roaming\eM Client\Local Folders\conversations.dat-wal, look into the chain of emails from the threat actor

## Task 12

Q: According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?

`2023-11-28 17:01:29` - load TriageData\C\$MFT (master file table) into MFT Explorer from Zimmermans tools and look for the secret file, get creation date of zip

## Task 13

Q: What is the full directory name that Elfin stored the file in?

`C:\users\Elfin\Appdata\Roaming\top-secret` - search in the root folder for santa_deliveries and you'll get the location, transpose it to elfin's machine

## Task 14

Q: Which country is Elfin trying to flee to after he exfiltrates the file?

`Greece` - also obtained from chrome's cluster_keywords table data, think it can be obtained from the emails but didn't look

## Task 15

Q: What is the email address of the apology letter the user (elfin) wrote out but didn’t send?

`Santa.claus@gmail.com` - in the same %APPDATA% folder for eM client, go to the weird guid-looking like folder (32969170-c98d-4a48-b444-526374e467e4), load up mail-data.dat-wml and look for sorry

## Task 16

Q: The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?

`Santaknowskungfu` - use mimikatz with the sam and security hives from TriageData\C\Windows\system32\config, get ntlm hash and use it on crackstation to get the password


# OpTinselTrace 2

## Task 1

Q: What is the MD5 sum of the binary the Threat Actor found the S3 bucket location in?

`62d5c1f1f9020c98f97d8085b9456b05` - hash the santa_deliveries binary from the previous challenge

## Task 2

Q: What time did the Threat Actor begin their automated retrieval of the contents of our exposed S3 bucket?

`2023-11-29 08:24:07` - given task 4 and that I created a script to gather all the data from all the jsons provided, simply search for python as a user agent, iterating over first jsons yields nothing, going from the end we see python-requests, which is pretty shady, and we also see that it uses GetObject as an event, hence we try the first date when we see that

## Task 3

Q: What time did the Threat Actor complete their automated retrieval of the contents of our exposed S3 bucket?

`2023-11-29 08:24:16` - get date of last exfil from previous step

## Task 4

Q: Based on the Threat Actor's user agent - what scripting language did the TA likely utilise to retrieve the files?

`python` - this is done second, as the hint has *****n, and that it is a scripting language, hence it is pretty easy to guess

## Task 5

Q: Which file did the Threat Actor locate some hard coded credentials within?

`claus.py` - from the files with extension exfiltrated at the previous 2 tasks, check everything with an extension, as the hint provided was "file.ext"

## Task 6

Q: Please detail all confirmed malicious IP addresses. (Ascending Order)

`45.133.193.41, 191.101.31.57` - first ip is obtained from the python-requests exfil (191....), and second ip is obtained from vpn exfil (45...), just place them in order

## Task 7

Q: We are extremely concerned the TA managed to compromise our private S3 bucket, which contains an important VPN file. Please confirm the name of this VPN file and the time it was retrieved by the TA.

`bytesparkle.ovpn, 2023-11-29 10:16:53` - search in the file with all jsons for `*.ovpn` and the event should ideally be GetObject, and we get the exfil filename and date for that

## Task 8

Q: Please confirm the username of the compromised AWS account?

`elfadmin` - aws account present in the santa_deliveries binary, also aws account used for exfil

## Task 9

Q: Based on the analysis completed Santa Claus has asked for some advice. What is the ARN of the S3 Bucket that requires locking down?

`arn:aws:s3:::papa-noel` - aws bucket present in the santa_deliveries binary, also aws account used for automated exfil


# OpTinselTrace 3

## Task 1

Q: What is the name of the file that is likely copied from the shared folder (including the file extension)?

`present_for_santa.zip` - look through volatility3 windows.filescan.FileScan

## Task 2

Q: What is the file name used to trigger the attack (including the file extension)?

`click_for_present.lnk` - obtained from task 3, guess

## Task 3

Q: What is the name of the file executed by click_for_present.lnk (including the file extension)?

`present.vbs` - use bulk_extractor and look at the lnk, it spawns a powershell running this vbs

## Task 4

Q: What is the name of the program used by the vbs script to execute the next stage?

`powershell.exe` - reconstruct the vbs partially and see what it builds, it builds some PS code and then runs it / use memprocfs with -forensic 1 and look at the vbs script, it runs powershell with some code

## Task 5

Q: What is the name of the function used for the powershell script obfuscation?

`WrapPresent` - use bulk_extractor to get the present_for_santa.vbs, then search the provided memory dump for crumbs from the script provided the output and try to reconstruct it, then the WrapPresent will appear in plaintext somewhere (eventually we're lead to the script building something via searching 'A4 =') / use memprocfs(had to build it manually, mount it to /mnt/<dir>) with -forensic 1 to load all the files, then we have the zip with the entire vbs code, deobfuscate it a little and see what function is used

## Task 6

Q: What is the URL that the next stage was downloaded from?

`http://77.74.198.52/destroy_christmas/evil_present.jpg` - did it a bit late, checked vt for name:present.vbs and looked at bhv tab :D - found out later that we can use memprocfs(had to build it manually, mount it to /mnt/<dir>) with -forensic 1 to load all the files, then we have the zip with the entire vbs code, we can run that decode function and see what it outputs => we get url

## Task 7

Q: What is the IP and port that the executable downloaded the shellcode from (IP:Port)?

`77.74.198.52:445` - dump the files using volatility and load the present.exe file into ghidra, reverse the address

## Task 8

Q: What is the process ID of the remote process that the shellcode was injected into?

`724` - run volatility3 with windows.malfind.Malfind and try PIDs from there / use memprocfs with -forensic 1 and look at the output of findevil - it says that there was something injected into svchost

## Task 9

Q: After the attacker established a Command & Control connection, what command did they use to clear all event logs?

`Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }` - search the powershell.evtx from windows.dumpfiles.DumpFiles in vol3

## Task 10

Q: What is the full path of the folder that was excluded from defender?

`c:\users\public` - search the powershell.evtx from windows.dumpfiles.DumpFiles in vol3

## Task 11

Q: What is the original name of the file that was ingressed to the victim?

`procdump.exe ` - from the previous powershell.evtx we get that they used some process PresentForNaughtyChild.exe; look it up in memprocfs output( forensic/files; requires -forensic 1) and open it in detect it easy - in versioninfo we see that it's actually process dump from sysinternals with the original filename as procdump - add the exe extension and voila

## Task 12

Q: What is the name of the process targeted by procdump.exe?

`lsass.exe` - from the previous powershell.evtx we see that it used procdump on lsass.exe

```
https://github.com/dbissell6/DFIR/blob/main/Blue_Book/Blue_Book.md#volatility
```


# OpTinselTrace 4

## Task 1

Q: The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?

`172.17.79.133` - filter for the printer ip = 192.168.68.128 and you'll see a lot of requests coming from that one

## Task 2

Q: Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?

`9100` - look at the ports used after the portscan

## Task 3

Q: What is the full name of printer running on the server?

`Northpole HP LaserJet 4200n` - look through the requests after the initial compromise and reconstruct the name from one of the replies

## Task 4

Q: Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?

`Douglas Price` - look through the commands issued and see where the printer returns the nice kids list, commands are after the compromise

## Task 5

Q: The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?

`The addressed employee is confirmed to be working with grinch and team. According to Clause 69 , This calls for an immediate expulsion.` - look through the commands issued and see where the printer wanted to print the layoff notice, commands are after the nice/naughty lists

## Task 6

Q: What was the name of the scheduled print job?

`MerryChristmas+BonusAnnouncment` - look through the commands issued and see where the printer mentions some scheduled jobs and get their name, commands are after elfin's layoff

## Task 7

Q: Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?

`/Administration/securitykeys/ssh_systems/id_rsa` - look throught the commands issued after the scheduled job and you'll see some security stuff pop up, and later the id_rsa for ssh appears

## Task 8

Q: What is size of this file in bytes?

`1914` - obtained from the same pcl packet as the id_rsa before

## Task 9

Q: What was the hostname of the other compromised critical server?

`christmas.gifts` - obtained from the same pcl packet as the id_rsa from task7

## Task 10

Q: When did the Grinch attempt to delete a file from the printer? (UTC)

`2023-12-08 12:18:14` - look through the commands issued (up until around the end) until you see a delete command via pcl issued for id_rsa, get its utc arrival time


# OpTinselTrace 5

## Task 1

Q: Which CVE did the Threat Actor (TA) initially exploit to gain access to DC01?

`CVE-2020-1472` - Netlogon CVE; look trough system evtx(use evtxecmd) and see unusual services, try different cves until something sticks - found easier if searching for logons, it pops out there as it has a known privesc cve - also, there is a service started after exploitation named "vulnerable_to_zerologon"

## Task 2

Q: What time did the TA initially exploit the CVE? (UTC)

`2023-12-13 09:24:23` - get time of last request sent via netlogon

## Task 3

Q: What is the name of the executable related to the unusual service installed on the system around the time of the CVE exploitation?

`hAvbdksT.exe` - filter in system evtx by the vulnerable_to_zerologon name and see when it is installed, and get the binary name

## Task 4

Q: What date & time was the unusual service start?

`2023-12-13 09:24:24` - same as for task 3, just that you look at when it starts

## Task 5

Q: What was the TA's IP address within our internal network?

`192.168.68.200` - obtained from security.evtx - noticed some ip used for bytesparkle, since it was used for initial access; then same ip used for admin logon

## Task 6

Q: Please list all user accounts the TA utilised during their access. (Ascending order)

`Administrator, bytesparkle` - bytesparkle used for access via ssh (prev chall), administrator obtained after lpe

## Task 7

Q: What was the name of the scheduled task created by the TA?

`svc_vnc` - obtained from kape uploads log file, seeing the tasks created and tried it

## Task 8

Q: Santa's memory is a little bad recently! He tends to write a lot of stuff down, but all our critical files have been encrypted! Which creature is Santa's new sleigh design planning to use?

`Unicorn` - iles are encrypted via XOR using the key EncryptingC4Fun! - decrypt the OperationStartLightJourney.pdf.xmax file using that and get the answer

## Task 9

Q: Please confirm the process ID of the process that encrypted our files.

`5828` - get date of accessing the splunk_svc from $MFT via MFTExplorer, then look through all the events logs and try PIDs (select event, go to details tab then xml view) based on the event's relevance and its date - eventually we'll end up in the UAC-FileVirtualization%254Operational, where we see some UAC events for deleting some png files and creating their variant .xmax (encrypted) - get the PID of that and voila