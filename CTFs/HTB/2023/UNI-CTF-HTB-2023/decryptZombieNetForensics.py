def init_crypto_lib(param_1, param_2,param_3):
    auStack_110 = [0x0 for _ in range(260)]
    auStack_110 = key_rounds_init(param_1, auStack_110)
    perform_rounds(auStack_110, param_2, param_3)
    return 0

def key_rounds_init(param_1,param_2):
    sVar2 = len(param_1)
    iVar3 = 0
    while iVar3 != 0x100:
        param_2[iVar3] = iVar3
        iVar3 = iVar3 + 1
    iVar3 = 0
    iVar5 = 0
    while iVar3 != 0x100:
        iVar7 = iVar3 % sVar2
        iVar3 = iVar3 + 1
        iVar5 = (param_1[iVar7] + param_2[iVar3 - 1] + iVar5) % 0x100
        param_2[iVar3 - 1], param_2[iVar5] = param_2[iVar5], param_2[iVar3 - 1]
    return param_2


def perform_rounds(param_1,param_2,param_3):
    sVar2 = len(param_2)
    uVar6 = 0
    uVar5 = 0
    sVar4 = 0
    while sVar4 != sVar2:
        uVar5 = uVar5 + 1
        pbVar3 = param_1[uVar5:]
        bVar1 = pbVar3[0]
        uVar6 = param_1[uVar5] + uVar6 & 0xff;
        param_1[uVar5], param_1[uVar6] = param_1[uVar6], param_1[uVar5]
        param_3[sVar4] = param_1[param_1[uVar5] + param_1[uVar6] & 0xff] ^ param_2[sVar4];
        sVar4 += 1
    return 0

auStack_3c = [0xc5,0x7c,0x2b,0x05,0x48,0x90,0xf3,0xb7,0x3f,0x76,0x0f,0x5b,0x68,0x7b,0x62,0x72,0xbd,0xf8,0x01,0x9b,0x57,0x47,0x1e,0x6f,0xdf,0x8c,0x55]
auStack_68 = [ord(_) for _ in "d2c0ba035fe58753c648066d76fa793bea92ef29"]
#auStack_68.append(0x0)
print(auStack_68)
sVar1 = len(auStack_3c);
pvVar2 = [0x00 for _ in range(sVar1 << 2)]
init_crypto_lib(auStack_68, auStack_3c, pvVar2);
res = ""
for _ in pvVar2:
    res += chr(_)
print(f"%s\n%s\n" % (res, res))