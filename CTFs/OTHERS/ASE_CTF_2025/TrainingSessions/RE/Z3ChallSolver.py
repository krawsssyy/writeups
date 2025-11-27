from z3 import *

# model solution
p = [BitVec(f'p{i}', 8) for i in range(8)]

s = Solver()

# constraints from binary
s.add(p[0] + p[1] + p[2] == 285)
s.add(p[3] * 2 + p[4] == 231)
s.add(p[5] ^ p[6] == 40)
s.add(p[6] + p[7] == 115)
s.add(((p[0] - p[7]) ^ p[2]) == 68)
s.add(p[1] + p[5] + p[7] == 271)
s.add((p[2] + p[3]) * 3 - p[4] == 525)
s.add(Sum([ZeroExt(24, x) for x in p]) == 663)

# enforce ascii
for x in p:
    s.add(x >= 32, x <= 126)

if s.check() == sat:
    m = s.model()
    pwd_bytes = [m[x].as_long() for x in p]
    pwd = ''.join(chr(b) for b in pwd_bytes)
    print("Password:", pwd)
else:
    print("No solution :(")
