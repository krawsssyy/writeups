# How to generate

SHA256 length extension attack challenge

Save all files in a directory, and then run:
`generate_challenge.py --phrase "<PHRASE>"`

## Generation script (generate_challenge.py)

```Python
from __future__ import annotations

import argparse
import json
import os
import secrets
import string
from pathlib import Path
from typing import Any, Dict

from sha256le import sha256_hexdigest, length_extension_sha256
import hashlib


def main() -> None:
	parser = argparse.ArgumentParser(description="SHA-256 length-extension generator")
	parser.add_argument("--phrase", required=True, help="Phrase to append")
	args = parser.parse_args()

	secret_len = secrets.randbelow(49) + 16
	alphabet = string.ascii_letters + string.digits
	secret_str = "".join(secrets.choice(alphabet) for _ in range(secret_len))
	secret = secret_str.encode("utf-8")
	digest = sha256_hexdigest(secret)
	append_bytes = args.phrase.encode("utf-8")

	ext_digest, glue = length_extension_sha256(digest, secret_len, append_bytes)
	# cross-check using hashlib on the true constructed message
	real = hashlib.sha256(secret + glue + append_bytes).hexdigest()
	assert real == ext_digest, "Internal sanity check failed (length extension mismatch)"

	print(f"Digest: {digest}")
	print(f"Original secret length: {secret_len} bytes")
	print(f"Append phrase: {args.phrase!r}")
	print("Glue padding (hex):", glue.hex())
	print(f"Expected flag (extended digest): {ext_digest}")
	print(f"Secret for verification: {secret_str}")


if __name__ == "__main__":
	main()

```

Generated params are:
```
Digest: 8341c545f269a4a751ff31bf5ecc5cd633c1438413577c97dc7b7b718fd735a1
Original secret length: 54 bytes
Append phrase: 'gimme_flag_p13ase'
Glue padding (hex): 800000000000000001b0
Expected flag (extended digest): 8ae1b9c32bb63f9350efd9f2d5820adf901b0a9defd489826813bba69c66cb5d
Secret for verification: cFm4jXVGL4aUashky9cgdML98MXzfKgYg80MAfu3ggmAxbq4eNZEDQ
```

Players will be given the digest and the length, and will be asked to provide the flag, by appending the phrase `gimme_flag_p13ase` to the original secret. Then, the flag will be constructed as `ISMCTF{NEW_HASH}`.

## Solution scripts

- sha256le.py
```Python
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

_K: Tuple[int, ...] = (
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)

_H0: Tuple[int, ...] = (
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
)


def _right_rotate(value: int, amount: int) -> int:
	return ((value >> amount) | ((value & 0xFFFFFFFF) << (32 - amount))) & 0xFFFFFFFF


def _ch(x: int, y: int, z: int) -> int:
	return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int) -> int:
	return (x & y) ^ (x & z) ^ (y & z)


def _big_sigma0(x: int) -> int:
	return _right_rotate(x, 2) ^ _right_rotate(x, 13) ^ _right_rotate(x, 22)


def _big_sigma1(x: int) -> int:
	return _right_rotate(x, 6) ^ _right_rotate(x, 11) ^ _right_rotate(x, 25)


def _small_sigma0(x: int) -> int:
	return _right_rotate(x, 7) ^ _right_rotate(x, 18) ^ ((x >> 3) & 0x1FFFFFFF)


def _small_sigma1(x: int) -> int:
	return _right_rotate(x, 17) ^ _right_rotate(x, 19) ^ ((x >> 10) & 0x003FFFFF)


def _to_uint32(x: int) -> int:
	return x & 0xFFFFFFFF


def _pack32_be(words: Iterable[int]) -> bytes:
	out = bytearray()
	for w in words:
		out.extend(w.to_bytes(4, "big"))
	return bytes(out)


def _unpack32_be(block: bytes) -> List[int]:
	return [int.from_bytes(block[i:i+4], "big") for i in range(0, 64, 4)]


def _compress(block: bytes, state: List[int]) -> None:
	w = _unpack32_be(block)
	for i in range(16, 64):
		w.append((_small_sigma1(w[i - 2]) + w[i - 7] + _small_sigma0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF)

	a, b, c, d, e, f, g, h = state

	for i in range(64):
		t1 = (h + _big_sigma1(e) + _ch(e, f, g) + _K[i] + w[i]) & 0xFFFFFFFF
		t2 = (_big_sigma0(a) + _maj(a, b, c)) & 0xFFFFFFFF
		h = g
		g = f
		f = e
		e = (d + t1) & 0xFFFFFFFF
		d = c
		c = b
		b = a
		a = (t1 + t2) & 0xFFFFFFFF

	state[0] = (state[0] + a) & 0xFFFFFFFF
	state[1] = (state[1] + b) & 0xFFFFFFFF
	state[2] = (state[2] + c) & 0xFFFFFFFF
	state[3] = (state[3] + d) & 0xFFFFFFFF
	state[4] = (state[4] + e) & 0xFFFFFFFF
	state[5] = (state[5] + f) & 0xFFFFFFFF
	state[6] = (state[6] + g) & 0xFFFFFFFF
	state[7] = (state[7] + h) & 0xFFFFFFFF


def sha256_padding(current_len_bytes: int) -> bytes:
	pad = bytearray()
	pad.append(0x80)
	# zeros until length ≡ 56 (mod 64)
	while ((current_len_bytes + len(pad)) % 64) != 56:
		pad.append(0x00)
	pad.extend((current_len_bytes * 8).to_bytes(8, "big"))
	return bytes(pad)


@dataclass
class SHA256:
	initial_state: Optional[Tuple[int, ...]] = None
	initial_len_bytes: int = 0

	def __post_init__(self) -> None:
		if self.initial_state is None:
			self._h = list(_H0)
		else:
			if len(self.initial_state) != 8:
				raise ValueError("initial_state must have 8 elements")
			self._h = [int(x) & 0xFFFFFFFF for x in self.initial_state]
		if self.initial_len_bytes < 0:
			raise ValueError("initial_len_bytes must be >= 0")
		self._buffer = bytearray()
		self._total_len = int(self.initial_len_bytes)

	def update(self, data: bytes) -> "SHA256":
		if not data:
			return self
		self._buffer.extend(data)
		# process full 64-byte blocks from buffer
		while len(self._buffer) >= 64:
			block = bytes(self._buffer[:64])
			del self._buffer[:64]
			_compress(block, self._h)
			self._total_len += 64
		return self

	def _finalize(self) -> Tuple[List[int], bytes]:
		# work on a copy so instance can be reused after digest()
		h = self._h.copy()
		buf = bytes(self._buffer)
		total_len = self._total_len + len(buf)
		# apply padding for the current total message length
		pad = sha256_padding(total_len)
		m = buf + pad
		for i in range(0, len(m), 64):
			_compress(m[i:i+64], h)
		return h, m # h is final state; m is only the padded tail that was processed now

	def digest(self) -> bytes:
		h, _ = self._finalize()
		return _pack32_be(h)

	def hexdigest(self) -> str:
		return self.digest().hex()


def parse_sha256_hexdigest_to_state(hex_digest: str) -> Tuple[int, ...]:
	if len(hex_digest) != 64:
		raise ValueError("SHA-256 hex digest must be 64 hex chars")
	b = bytes.fromhex(hex_digest)
	if len(b) != 32:
		raise ValueError("Digest must be 32 bytes")
	return tuple(int.from_bytes(b[i:i+4], "big") for i in range(0, 32, 4))


def sha256(data: bytes) -> bytes:
	h = SHA256()
	h.update(data)
	return h.digest()


def sha256_hexdigest(data: bytes) -> str:
	return sha256(data).hex()


def length_extension_sha256(
	orig_digest_hex: str,
	orig_len_bytes: int,
	suffix: bytes,
) -> Tuple[str, bytes]:
	initial_state = parse_sha256_hexdigest_to_state(orig_digest_hex)
	glue_padding = sha256_padding(orig_len_bytes)
	initial_len = orig_len_bytes + len(glue_padding)
	ext = SHA256(initial_state=initial_state, initial_len_bytes=initial_len)
	ext.update(suffix)
	return ext.hexdigest(), glue_padding
```

- solve_length_extension.py
```Python
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Optional, Tuple

from sha256le import (
	length_extension_sha256,
	sha256_hexdigest,
	sha256_padding,
)


def perform_length_extension(
	orig_digest_hex: str,
	orig_len: int,
	append_bytes: bytes,
) -> Tuple[str, bytes, bytes]:
	new_digest_hex, glue_padding = length_extension_sha256(
		orig_digest_hex=orig_digest_hex,
		orig_len_bytes=orig_len,
		suffix=append_bytes,
	)
	return new_digest_hex, glue_padding, glue_padding + append_bytes


def main() -> None:
	parser = argparse.ArgumentParser(description="Solve SHA-256 length extension")
	parser.add_argument("--digest", required=True, help="Original SHA-256 hex digest of the secret")
	parser.add_argument("--orig-len", required=True, type=int, help="Original secret length (bytes)")
	parser.add_argument("--append", required=True, help="The phrase to append")
	args = parser.parse_args()

	if not args.digest or args.orig_len is None:
		raise SystemExit("--digest and --orig-len are required")
	orig_digest_hex = args.digest.strip()
	orig_len = int(args.orig_len)
	append_phrase = args.append if args.append is not None else ""
	append_bytes = (append_phrase or "").encode("utf-8")

	new_digest_hex, glue_padding, forged_tail = perform_length_extension(
		orig_digest_hex=orig_digest_hex, orig_len=orig_len, append_bytes=append_bytes
	)

	print("New digest (flag):", new_digest_hex)
	print("Glue padding (hex):", glue_padding.hex())
	print("Forged tail = glue_padding || append (hex):", forged_tail.hex())
	print(f"Forged message shape: secret({orig_len} bytes) || glue_padding({len(glue_padding)} bytes) || append({len(append_bytes)} bytes)")


if __name__ == "__main__":
	main()
```

# Challenge's description

Name: `Astra-5’s Lengthy Transmission`

Description:
```
The university’s research satellite Astra-5 has gone silent, but before losing contact it transmitted one final telemetry packet — a SHA2-256 digest supposedly authenticating an internal command (`8341c545f269a4a751ff31bf5ecc5cd633c1438413577c97dc7b7b718fd735a1`). Engineers believe the packet was meant to authorize a critical system routine, but without the original command string they can’t validate or extend it.

Your mission is to pick up where the ground team left off. The digest you’ve recovered was generated from a secret message known only to the satellite’s onboard computer (the sattelite only sends messages that are 54 bytes long). However, analysts suspect that it’s possible to craft a new valid digest for a modified command that appends the phrase `gimme_flag_p13ase`. If you can produce such a digest, ground control can reconstruct the missing message and recover access to the satellite.

Recover the modified digest and submit it as the flag (Flag format: `ISMCTF{new_SHA256_digest}`). The stars are waiting.
```

Flag: `ISMCTF{8ae1b9c32bb63f9350efd9f2d5820adf901b0a9defd489826813bba69c66cb5d}`
Difficulty: `Medium`
Category: `Cryptography`
Points: `20`
Hint 1 - 6 points: `Since the digest is a SHA2, check out possible attacks for it that suit your situation.`
Hint 2 - 12 points: `The title is a hint. SHA2 is vulnerable to an attack called length-extension.`