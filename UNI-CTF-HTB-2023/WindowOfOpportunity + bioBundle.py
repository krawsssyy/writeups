arr = [0x9c, 0x96, 0xbd, 0xaf, 0x93, 0xc3, 0x94, 0x60, 0xa2, 0xd1, 0xc2, 0xcf, 0x9c, 0xa3, 0xa6, 0x68, 0x94, 0xc1, 0xd7, 0xac, 0x96, 0x93, 0x93, 0xd6, 0xa8, 0x9f, 0xd2, 0x94, 0xa7, 0xd6, 0x8f, 0xa0, 0xa3, 0xa1, 0xa3, 0x56, 0x9e]

def check_password(password):
    for i in range(len(password) - 1):
        char_sum = ord(password[i]) + ord(password[i + 1])
        if char_sum != arr[i]:
            return False
    return True

def bruteforce_password(start):
    password = start
    for _ in range(36):
        for i in range(32, 127):  
            aux_pwd = password + chr(i)
            if len(aux_pwd) < 39:
                if check_password(aux_pwd):
                    password += chr(i)
    return password

for i in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    # start is H
    password = bruteforce_password(i)
    print(password)
    print(len(password))

# construct passwd that respects their conditions


# biobundle
    # check with ltrace what it opens, then go to /proc/pid/fd/ and get the file from there, reverse it w ghidra and boom flag, then it needs strrev