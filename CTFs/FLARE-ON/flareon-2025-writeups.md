# 1. Drill Baby Drill!

We are given a PyGame executable, together with all the assets and the actual Python source. Inspecting it, we see the following code for generating the flag:

```Python
def GenerateFlagText(sum):
    key = sum >> 8
    encoded = "\xd0\xc7\xdf\xdb\xd4\xd0\xd4\xdc\xe3\xdb\xd1\xcd\x9f\xb5\xa7\xa7\xa0\xac\xa3\xb4\x88\xaf\xa6\xaa\xbe\xa8\xe3\xa0\xbe\xff\xb1\xbc\xb9"
    plaintext = []
    for i in range(0, len(encoded)):
        plaintext.append(chr(ord(encoded[i]) ^ (key+i)))
    return ''.join(plaintext)
```

Looking at its usage, we see:
```Python
screen_width = 800
screen_height = 600
...
...
LevelNames = [
    'California',
    'Ohio',
    'Death Valley',
    'Mexico',
    'The Grand Canyon'
]
...
...
...
	bear_sum = 1
	...
	...
            if player.hitBear():
                player.drill.retract()
                bear_sum *= player.x
                bear_mode = True

            if bear_mode:
                screen.blit(bearimage, (player.rect.x, screen_height - tile_size))
                if current_level == len(LevelNames) - 1 and not victory_mode:
                    victory_mode = True
                    flag_text = GenerateFlagText(bear_sum)
                    print("Your Flag: " + flag_text)
```

Therefore, by gradually trying to increase the sum search space in a brute force approach, we get the flag:
```Python
def GenerateFlagText(sum):
    key = sum >> 8
    encoded = "\xd0\xc7\xdf\xdb\xd4\xd0\xd4\xdc\xe3\xdb\xd1\xcd\x9f\xb5\xa7\xa7\xa0\xac\xa3\xb4\x88\xaf\xa6\xaa\xbe\xa8\xe3\xa0\xbe\xff\xb1\xbc\xb9"
    plaintext = []
    for i in range(0, len(encoded)):
        plaintext.append(chr(ord(encoded[i]) ^ (key+i)))
    return ''.join(plaintext)


for sum in range(800**2):
    try:
        flag = GenerateFlagText(sum)
        if "@flare-on.com" in flag:
            print(flag)
            exit(0)
    except Exception:
        continue

```

FLAG: `drilling_for_teddies@flare-on.com`

# 2. project_chimera

We are given a Python file, which uses encoded bytecode for next stage execution. Writing the bytecode to a .pyc (with Python 3.12, since I tried `dis.dis` on 3.11 and failed, so I upped the version and it was fine) to decompile it with `pylingual` works, and we get the next stage.

```Python
import zlib, marshal, importlib.util, struct, time

# These are my encrypted instructions for the Sequencer.
encrypted_sequencer_data = b'x\x9cm\x96K\xcf\xe2\xe6\x15\xc7\xfd\xcedf\x92\xe6\xd2J\x93\xceTI\x9b\x8c\x05&\x18\xe4\t\x06\x03/\xc2\xdc1w\xcc\x1dl/\x00_\x01\xe3\x1b6\xc6\xe6\xfa\x15\x9a\xae\xd2\xae\xba\xae\xd2/Q\xf5\x0b\xbc\xd1\xa4JJVUV\xdd\xa5\xca\xae\xab\xf2\xceM\x89\x9ag\xe1\xf3\x9cs~\xe7\xfc\x8f\x1f\xc9\xd6\xf3\x1d\xf0\xa3u\xef\xa5\xfd\xe1\xce\x15\x00|\x0e\x08\x80p\xa5\x00\xcc\x0b{\xc5\\=\xb7w\x98;\xcf\xed]\xe6\xaep\x87y\xe3\x0e \xde\x13\xee~q\xf5\xa2\xf0\nx\xee\xbf\xf1\x13\x1f\x90\xdf\x01\xfeo\x89\xaf\x19\xe6\xc1\x85\xb9\x92\x7f\xf53\xcc\x83\xd7\xcc[\x17\xe6\x8e\xfc\xfe\xcf0o\xbdf\xde~\xae}\xef\'\xdaw\xe5\xdf\xfcL\xcd-\xf9\xee\x17/\xbd/\xee\xbc\xac\x7f\xef\x12}\xefU\xf4\n\xd8^\xc1\xf7\xff}\xbb%\xad\xbf\xbe\t\x00\xbc\xf7 \x06[\xe9\xb8\x0f\x89MU\xb0\xbbc\x97\'E!\x0ea<\t\xfa\xc7\x81aG\xf3\xac\x88\xca\xe1\xe0\x12a\xce\x1b\x18\xa5v\xce59:\x85\xd5Y\xb5)G\xac\x92\xbc\xdbB8Y\xeb\\cc\xeff%\xf6\xcb>\xb5\x10\xdc\xce\x15"\x16\x8f\xcb\xc85\\\xc2\xb4b\xfa\x94\xc1\xcb\xabF\x0c\xd3\x95M\xde\xf2r\x0c\xb6_\x11\xc9\xfd!ed\x9bX\x8e\x13\xb9q ]\xd8U\r\xb361\x0bT\x83B\xb3K8\x8ay+\x95AC\xab\x8a\xd16\xa2\xc0\xb9\xb9\x0c\x06b\xce\xbexR \xaa\xe9\x14\xdb\xb6G.\xd2sj\\$\xf7\xabh\xe7\x10EF+\x08\xcd*y\xf7x<lH\xd48\r\xaa\xd7s84\xf0i=4R\x9c\x1d\xdd\xeb\xfa\x98@\xfc+\xaf\x11:b\xa0\xb2E u\x1f\xaa\x08\xe9q0\x12\xc0[\xfb\x80\x15\xaa#\xca\xf2p\xcc7*\xa3z\xcd\x11;&\xb9\x8b\xee\xa1\x12\x92\xcc\x12\x93\xbd\x10\xac\xaa}%\x8e\xe8q\xdf\xb1\xb5\x87l\x8e\x85\x1d\xb4\xdb\x08\x0cr]*\x10O\xac\x83!|\x9c\xcf\xecT\xa5U\xa4\x12\x870\xb73&\xbb\xb5#o\'}\xa1\xce\xc1($\xb61\x01\xa1\xd6\x8b\x10=\x93\x97\x13\xc8\x01\xc7\x10\xea\xdaMr\x831\xd7>\x7f` \xc6\'\xe3\x12\xb7E\xb5H2X\xc6\x87\xc5\x9c\xb4Z\x8c\xe7h:\x94M\x11\xcbE\x14l\x9eL\xd5\x82X\xc9\x9d\x06m\x97\r\x05\x92\xa5\x9d-\x18+R\xd1\xa2M<\x0b\xb6V\x9a\xc0\xc0]|3\xc7l\xdf\xccPU\x8dm\x8a\x0e\xd7\x0fuk\xdc6\xe3\x97\xd885\xf2\x98i\xa6\x83\r\x08\x9f}8)\x8cE\xd0\'D1\xa4QS\nM\x82\xc6\x10\xa9L\xdbTU3\x1cu\xab\x9fTf\xba\x96\x06\xf5\x8c\xdf[\xaf\xb0\x90\xba!\x15}\xc3$i\xb8\x18\x14c\xb6\x13T\xe9X\x83\xcc\x87\xe9\x84\x8f]r#\x83\xc9*\xf3To\x81\x83\xb5\xec\xfaP(_\xc7\x88),\x1b\xa0\x82\xb9\x04\xed\x9f\xc7\xb3^E\xc9a\xc7|B0\x1a\x01\x19\x16\x1b\xfb\xcd\x90\xe7\xb6M7:\xd9sh\x04&\xb3\x0e{\x12\x8d\xde5#\xe9\xbe\xe1\x84\xf6H\xcd\xc0,\x91\xcc\xc6 9\x05-\xa0Q>\x94\xea\xf4"\xa2#gC\xa7<\xb8Xp6\xde\\\x99f\xadZ\xd9\xab\xbe\x92\x9e+\xe7#\x9e\x10)%]\xf0$l:\x87\x84\'\xc2\x1f\xe1j#\xb6$6\xf3\xfc\xb6\xb6\xc9\xed\xf3\th\xb0\xa2B\xfdY\x00\t\xe6\x96\'r\xe4\xbb\x1cK>\xc3\xc6\x1c\x91\xb88\xe6\xae\xbb\x083y0\x86\xc5+#%76\xcb\xd8l#G\xe8\xb5\xa8GB\xbe\xc01\x19M$\xe3Z\xad\x14\x17\xe7\xf1\x8dLP\x8e\xe3\xb6G\xa3]1\x10\xc1\xab\x1b\xa6\xe7Q\xaa\r\xbf\x12\xc8\xd8\xde$Q^Hu\xa9Q4\x86\\\xc0\xa4\x1a[\x07\xcc\xb5OL\x7f\x8c\xf4R\x18\xb5\x8f\xa0\xeb\x95\x88\xb7\xd0\xa5S\xf6\xce\xf2\x8cf_\x8b\x1b6r\x8a%\xb1\x82k\xf2\x15t\xdf\x99\xed\x9b\xc9r?\x9a\xcd\x0b\xab5d\xed\xdde?Y\xdc\xb2\xf9%\xbcI\xf3}\xd3\x93\xa2\x9aY\xbe\x83\x0c\x19\xa6\x86\xb2\xbb\xf9\x1e-J\'\xc9\x91\xfc\xaa@/\'<Q\x98N=;S\xdc\x0cl\tE\xaa\xf1b\xa5\xber\x13|\xbc)f\x02\x0b\xd26\x13\x17-\x1d\xce\xa19\xb5\xc2\xd5\xc1\x98g\x89\x0b\xc1\x8eJ\xc9\xfa@1s|\xaa\x8b\\\x13\x12\xb1\xd1\xbc\xfd6\x94a\xb804E\x92N)\xcc\xc4\xf9Sg\x0ev\x06\x06\x94-\xc5\x05\x7f\'Y]g5%\x82.\x1c~L\x16\xfa}S\x0e\xb4F0GT\xd2yZ\xe9xiu1\xef\r\xc3\x9d\xa2k\x16\xac:\xd9\xd7\t\xd5"\x17\xd2)\x89T\x1b\xe5\xa0\xe2\xcd\x9e\xacf\x91\xd7\x88\n]\xe5d.\xd3@,G\x87\xd2$I\xc7B\x9dZt\x1anP~\x9f\xb7P\x92\x02#?\xaf\xc4\xd7\xd7\xa1D$\x91\xedT\x82\xe9$\xb8\xaccr\xb3\xbfhur\xc7]3+\xf4\x82\x8e\xba\xc42\xdd\xb5\xb5\xaaZ~rm3\xa6\x9fpd|\xe7R\xecP_[`\x0c?\x0e\xda\xd1\xb4F\x1a\xe8LZ\x8a\x16\xd6\x0f\xec\x84=\x1c\x9b#\xe5\x12\x96&{\x9d\xd6\xb1\x1bH\xa0{~\xba\x04SE\xa4x\xe4X\xd2\x8bJ\xf6\x904\x07\xc5MyA\x0f\xa9\x11\x9d\xafb\xd1\xd8^-\x94\xa7\xf6\xd2f$\x83\x84s\xb8\xbb\xe5R\xd6\x91\xdb\x12\xfe\xe2\x86\x91T\xa3\xbb\xdc\xe8X\xa19\x0b\x96\x02\x91\x02$\xc5<\x19u?\xcb\xf61\x1b)\xe3\'5\x7fr\xca\xd4,I\x0e\x9b\xa5\xa2\xec\x93\xa28\xbc*\xa3\x9e\xb8\xab\xd0B\x89\xe8L\xe4J\xd7\x0e\x88\xbe\xd2@\xed\xa05\xbcl\x1c1\xaf\xbb\xcanY\xa5\xe0w\xe1\x1eR\xaa\x12\xb3\x8e\x18\xac\xba\xb9n\xa3\xd6\xee\xaa\xd9"\xe5\xfa\xd6A|\x1em\x84Z\xdd\x1aN\xe0\xbcs\x8c)Z,#\xba\x8d\xca\xf6\x98\x98\x08\x04f\xec\xd0\xb8\xde\xf0\x9f\x88\xe9\x9e\x9d\x12\x88\xa6\xc73\xd3(l\x14\t\x83\xa4\xfdHl\xc8\xd62\x851^K\xf8\xcb$\x98Kj\xd3v\xbf]d\xf2DrD\xa6\xa3\xcb\x14\xabZS{\xbb\xc5]\x95\xa1\x85lkv\x08a{t\xe0\x0f\xa0\xedr\xa3\x9b\x9eGFT\x86eF\x1d\xe9\x14Kdd\xa4d\xa9\x8dqyS\xd5\xcc\xd9B\xd0\x9b\xe1\xa3\x89\xda\xbe#\x95\x0f\xae\x8ezy\x86\x90]\x8f6\xa6\x02\x98\xbd\xcao3\xe8\x8a\xf6b\xb8\xbck\xe6\xe7T\x0eN\xee\xda\x92\x1b\t\xb8\x03p8\xf2z\xa4\x12\xebk\x16ZR\xb72\xd4BPly\xcd\xb2]\'!\xd0\x198\x0e\xdamP+W\x08\xce\xb3\x0c\xd6\\\xfa\x10\x9e\xa7\x97\xd4\x9e\xdcC\xe0\xb4*m\xda\xd4\xa1\x97\x15A-\x17\xa9nO\x1e\xbe>4a\x88/\xb9{\x95\xee\x95\xe5\xc4\x1c\xadL:1QX\xce\xed\xf2\x12\x8e0\x89\xd9\xc8\x98\x9e\xd4\xda\xae\x1c\xc7\xd4\xb8\x1f\xac\x8du?\x18\x16\xc4\xa9\xda\xcaD\xaa\xc5\x1d?Lz\xbb\x9diV\xd2\x17tE\x91\xa1\xfd\xe5\x87\x9c\xf6,\xfa\x87zz\x83L\xe9\n\xdc\xee\xbb\x1e\xa9k\xfb\x0f\xd9\x9cU\xef{\xdac\x98\xd7X\xf0\x90\xb0\x06\xdb\x01\xd2\\\xe7\xdc\xf6\xb1\x99v\x0e\x05\x1e\xb5\xb0I\xbd\x9a\x98+Fx{\x18\xe4\x88\x9a\xb7\x10\xf6b\xady\xec\x94\xb5e\x04\xa4\x91\xe8\x9a\xd8V\xbd4T\'\n$f\xc7\x14<\x90\x91x\xa7;\x91\x8a\xe3CP\x90\x8b\xd5Z\xd4\x06\xd39\x1fJ&\x16ku\x8fGt\xc4\xd6\x92\x08|\x9d\x18{\x8cj[\xd8\x0f\x9d\xed\xae2AG\xad\xed\x8a\xf1V\xe0\xa5\x97\xa2\x8a\x88\xcb\x0fXi&s)\xd2\xb3\x00\x83-MC\xfa2\xc2\x13:\x17\xf4\x83\xfe|k\xc4\xa6K\xebB2\x8c\x16+{h\\\xad\xe8)\x1eJ\x9aI\xd9Z\x93ht\xd5\x9b\x0c\xc6\xa5T\x8e\xf3\xf2\xd1\xd6<:\xcaH4\x08\x8d7\x02%\x11\xe9(-\x81f\xa54\xc6\xd9\xd24\x1f\xe0\xc4@#\xe5/\x94\xfc\x10B\xe0\x19\x18\xe2B\xde|\r>HaF.C\xd5\x9e\x13d\xae)\xbe0\x95\x830g,\xf1x\x82\xa6F\xc4R`\x87q\xd5)O\x96\x8b\xd6\xe5S\xa3\xb7\xaa\xaf\xe0[\xb8~\xc2\xc8\xc5IO\xe6x`\xbbn\xce\xea\xaaI0,B"\xccb\xb9\r\xa3U\x06\xed\x8dS`3\x9c\xaf\xb5\xa8\xe8\xfa\x0eB\x10\xe4I\x81U\x16\x9c\xc9\xae\x17\xda\xecIY\xd4\xc4\xf5\x82\x7f\xd2\x13W\xb6\xa8\xf1\xa2\xf9\xe4B\xec>.\x8a\xbc.\xdc\xe6yv\xcd*[k\xfd\xa4H\xe6\x9eXk\x93\xd5\x84\xa7O\x9f\xee>\xeam\xb5\xf5\\\xb4\x16\xbb[\xa8\xf0\n\xea\x89\xa6\xad^\xf2\xf0/\xcf\xf79\xd6\x12c\xd8\xf9\x8d\xddE\xec\xfc@eMk\xce*\xe7{\xeb\xad!Z\xe7\xc7\x17-]\x10\x85\xc9\xab\xfe\x93\x17\xbd\xcf\xf7\x0cs\xa1\xad\xcfoq\xd7Q\xe1v\x06\xf1\xfc\x90\xd7U\xc3\x14-\xebG\xf4\xf9\x17\xb7\xc9\x17\xe1\xf3\xe3\x97\xbd\x95\x0b0{\xf1:\x93\xe7\x95\xf7\x14\x9d\x15\xac\xf3\xfb\xaf5n\xa3\x13\x9d\x93E~}~\xa7dk\xfcz\xa1k\xfd\xcb@\xe7\x073E\xe7X\xc5:\x7f\xf8\x1a^h\xb7\xdc\x05\x98H/\xc9\xbf\x00?\xdc^\xfb\xfe\xfb\x10\x7f%c\xbd:\xb5\xf4\xf9M\\\xd5\x05[\x11\xd3\xe6\xaf\x9f\xdf\x12\x01\xc0\xfa\xfd\xe5\xf1\xfd\xdd\xab\xab\xab\xef\x80w\xbf\x05\xde\xfe\x16x\xef[\xe0\x9d\xef\xef\x03\x1f\xd6<7\xc0\xe3\x7f\x01\xf7n\xee#_\x01O\xffy\xbb\xf9\xe4+\xc0\xff\xcd#\xdfg\xd2\xd7\x8f|_>\xf2\xdd|\x92~\xf6(s\x03<\xfc\xe6\x03\xf8\x8f\xde?\x7f\xfa\xa7Oo\x02\xa9g\x1f\xa4/u\xdf<\xf6~\xe6|~\xfc\xc3\xf1\x06\xc2\x9f=N\xdd\x00\xef?\xef\xe4\xfb\n\xf8\xe4\xd2\xfbc\xf4\x8f\xe2\xd7\x1f\x85\xbe\xfc(t\x83\x12\x7fs\xfe\xbe}\xf6Q\xe7\x06\xf8\xf0?\xf7\x81\xab\xdf\xfe\x03\xf8\x9d\xf9\xf02\xd3\xff\x00hw\x9dH'

bc = zlib.decompress(encrypted_sequencer_data)
code = marshal.loads(bc)

magic = importlib.util.MAGIC_NUMBER
bitfield = 0
timestamp = int(time.time())
source_size = 0

header = magic + struct.pack("<III", bitfield, timestamp, source_size)

with open("payload.pyc", "wb") as f:
    f.write(header)
    f.write(marshal.dumps(code))

print("Wrote payload.pyc")
```
->
```Python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: <genetic_sequencer>
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 2025-09-27 09:27:06 UTC (1758965226)

import base64
import zlib
import marshal
import types
encoded_catalyst_strand = b'c$|e+O>7&-6`m!Rzak~llE|2<;!(^*VQn#qEH||xE2b$*W=zw8NW~2mgIMj3sFjzy%<NJQ84^$vqeTG&mC+yhlE677j-8)F4nD>~?<GqL64olvBs$bZ4{qE;{|=p@M4Abeb^*>CzIprJ_rCXLX1@k)54$HHULnIe5P-l)Ahj!*6w{D~l%XMwDPu#jDYhX^DN{q5Q|5-Wq%1@lBx}}|vN1p~UI8h)0U&nS13Dg}x8K^E-(q$p0}4!ly-%m{0Hd>^+3*<O{*s0K-lk|}BLHWKJweQrNz5{%F-;@E_{d+ImTl7-o7&}O{%uba)w1RL*UARX*79t+0<^B?zmlODX9|2bzp_ztwjy_TdKb)1%eP4d-Xti0Ygjk_%w!^%1xuMNv4Z8&(*Ue7_^Fby1n3;+G<VDAfqi^h1>0@=Eki5!M~rms%afx`+uxa0*;FzudpqNln5M<@!OqndZ)R<vh4u&gpmmnaMewbT0RJby?(fa7XW#r>ZQ4UE&u|~lZsEY~-lpfWMf0_+pV-H`PXInpwmyo~mZ`tfUK?($KHa%mvNlovZ;Y)D+e6uw+mY6LNB2Y9&akbWpZ@lh=Si<!J@t|CG86E`)jp!l4xEY(h7@$llA4}B9dpL*j)eL{vVcbyMx5_{b13)N@wa~epS8Zfo&V_Y#fM*g9;@6%j=%i%WB0=QS3ewj@0~B!iibu<MqrrJIH{m&FoAGB3#0Nf;x!~dvQ|9#3c})IL6kEvhByJvA{B9%UqX0Tg*-+Ak~NW&RJbB?a6weENW&rzRi2ZB!647HWlA^rG4gvj3Yteo30&*};59;7nJF7eh7vjEXwwxPWWzD*3<IvZS#lIL(l*?u$;EGifKfLDpVb*rXLyw!AP~ZT^-S=4X{31tqe<O1kwG$gBZnu8eva3~6;4CxrcH1{Qg{M;GT5@Bdqt%s{xkT;DyaBk)v>cTr#=XM@cQ-VZZJ1azh{1Df~fwf(mdYk_cEC``#zrevUuf1-I7DHKqx9c7Me?*iNur9a3~o)A1AmHbK!6#k<d+QmXjoUlrAc=R-8EfEvn$TP%?Zb2%`-;wF2Z7c~Qh!QUp%@F7d(Q;It@nl31iwc^NCTTrj*OW)bEH>BYlQ$YmihSV2QDxrCsKNToEmsNif~;-ILG+l$@~sMDcnEHYIbjb?L-swo%>NNY60QJ5`2LX(&$CFf*W(cl7t80939@QH+>;!kK4jMTiOQA}zM@dS+wmk4?RtsqIs(NtuZr(Ewj<zxXaVots!6<}UP5>nNp1gfkes4T*zd{)6h-GF4>NSQO}R*91{c`k!=D-D}baN$1fuVNrUDvGiYVXWYBI456{mCG`ukuZfpN)A<xyb=s}byE(DvZfmpRkvo4CMg+F*3C%f6#?m{g@T4u-G<~mB~wGXg;NVMFDj&f5<)qG1#7xlYdFEQ_jHRu*e&FUmQ1J<Gp}4$xq@yalC(x)S-FIEgQe+IxARLJPRm@DXx&t+<h5L0ORJ<E<cw}6ln6?exLHy}9_dE4pz17oL(~E`{a`E-no7?`5)pDEpNY(-6VaJ?C^<J9(GN!A;n`PTPDZBE;WN>5k=ams`uyy<xmZYd@Og|04{1U(*1PGLR>h3WX?aZWQf~69?j-FsmL^GvInrgidoM2}r1u&}XB+q}oGg-NR#n^X*4uqBy?1qY$4<jzMBhXA);zPfx3*xU!VW$#fFa&MCOfRHVn0%6k8aaRw9dY?)7!uP!nGHEb#k+JxY|2h>kX{N{%!`IfvPX|S@e!nA3Iy~#cKVr)%cFx{mYSGj9h1H_Q6edkhuGk)3Z9gWp`~mJzG74m7(!J^o(!2de`mO?3IDzcV;$RQ`@foiYHlj%{3;+>#iT|K>v-`YH)PTx#fRu(|@AsKT#P^)cna!|9sUyU-MtAxP}M>w|Cc1s4_KI9hlp2y|UAEJ$C2$4Oh6~@uj-!Y-5tEyI$Y%KECN4u6l<*?fcwR_fD^|+djDIJ5u!>A&1N9itm{<3o-un;-)89^#pIPd{VwyzH_1WOyqZ$H)k$XXD-xcUafgjb=N#i!+Onn-Tj-cEob+(!(BOWa>FtC;21DH{%^IHo=c%;r;jstN15qS_U^F=Ab$c5Oh5W?fY!%^vdXfE>5Yf!rHF^<aF`B*be*L=(CF(%-E<?)%b0$BJ)|f2ZjG%ISw+Z8XcC`j+)bpk<79YXWEkdaV7mwG_kiObaNYym&C&ix(EpA7N#?}|aRxAsRm;!2e%e)a4AvZnHUPvwCa?b&OiHoo'
print('--- Calibrating Genetic Sequencer ---')
print('Decoding catalyst DNA strand...')
compressed_catalyst = base64.b85decode(encoded_catalyst_strand)
marshalled_genetic_code = zlib.decompress(compressed_catalyst)
catalyst_code_object = marshal.loads(marshalled_genetic_code)
print('Synthesizing Catalyst Serum...')
catalyst_injection_function = types.FunctionType(catalyst_code_object, globals())
catalyst_injection_function()
```

Repeating the same process for this new bytecode, we get:

```Python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: <catalyst_core>
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 2025-09-27 09:31:28 UTC (1758965488)

import os
import sys
import emoji
import random
import asyncio
import cowsay
import pyjokes
import art
from arc4 import ARC4

async def activate_catalyst():
    LEAD_RESEARCHER_SIGNATURE = b'm\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS'
    ENCRYPTED_CHIMERA_FORMULA = b'r2b-\r\x9e\xf2\x1fp\x185\x82\xcf\xfc\x90\x14\xf1O\xad#]\xf3\xe2\xc0L\xd0\xc1e\x0c\xea\xec\xae\x11b\xa7\x8c\xaa!\xa1\x9d\xc2\x90'
    print('--- Catalyst Serum Injected ---')
    print("Verifying Lead Researcher's credentials via biometric scan...")
    current_user = os.getlogin().encode()
    user_signature = bytes((c ^ i + 42 for i, c in enumerate(current_user)))
    await asyncio.sleep(0.01)
    status = 'pending'
    if status == 'pending':
        if user_signature == LEAD_RESEARCHER_SIGNATURE:
            art.tprint('AUTHENTICATION   SUCCESS', font='small')
            print('Biometric scan MATCH. Identity confirmed as Lead Researcher.')
            print('Finalizing Project Chimera...')
            arc4_decipher = ARC4(current_user)
            decrypted_formula = arc4_decipher.decrypt(ENCRYPTED_CHIMERA_FORMULA).decode()
            cowsay.cow('I am alive! The secret formula is:\n' + decrypted_formula)
        else:
            art.tprint('AUTHENTICATION   FAILED', font='small')
            print('Impostor detected, my genius cannot be replicated!')
            print('The resulting specimen has developed an unexpected, and frankly useless, sense of humor.')
            joke = pyjokes.get_joke(language='en', category='all')
            animals = cowsay.char_names[1:]
            print(cowsay.get_output_string(random.choice(animals), pyjokes.get_joke()))
            sys.exit(1)
    else:
        if False:
            pass
        print('System error: Unknown experimental state.')
asyncio.run(activate_catalyst())
```

In this new script, we see that it builds a sort of signature based on the name of the current logged-on user, and checks it against a known blob. Due to operator precedence and XOR properties, that signature is built as `c ^ (i + 42)`, and therefore `c = (i + 24) ^ LEAD_RESEARCHER_SIGNATURE`. From there, we just decode the blob using RC4 cipher and get our flag.

```Python
from arc4 import ARC4
LEAD_RESEARCHER_SIGNATURE = b'm\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS'
ENCRYPTED_CHIMERA_FORMULA = b'r2b-\r\x9e\xf2\x1fp\x185\x82\xcf\xfc\x90\x14\xf1O\xad#]\xf3\xe2\xc0L\xd0\xc1e\x0c\xea\xec\xae\x11b\xa7\x8c\xaa!\xa1\x9d\xc2\x90'
lead_user = bytes(s ^ (i + 42) for i, s in enumerate(LEAD_RESEARCHER_SIGNATURE))
arc4_decipher = ARC4(lead_user)
print(arc4_decipher.decrypt(ENCRYPTED_CHIMERA_FORMULA).decode())
```

FLAG: `Th3_Alch3m1sts_S3cr3t_F0rmul4@flare-on.com`

# 3. pretty_devilish_file

We are given a PDF file, which just shows the text "Flare-On!". Opening it in `PDFStreamDumper` reveals that it is encrypted, and that decryption failed with `Unknown encryption type R = 6`. Researching this a bit, reveals that revision 6 uses AES256 for encryption with a password, so I first tried to decrypt it using `qpdf` (as it has support for these new PDF2.0 encryptions) with an empty password, and it seems to have worked (`qpdf --password="" --decrypt --qdf --object-streams=disable --stream-data=uncompress pretty_devilish_file.pdf out.pdf`).

This allows us to open the PDF in `PDFStreamDumper` so we can analyze its internal streams. Looking at it, we see an interesting hex stream:
```
q 612 0 0 10 0 -10 cm
BI /W 37/H 1/CS/G/BPC 8/L 458/F[
/AHx
/DCT
]ID
ffd8ffe000104a46494600010100000100010000ffdb00430001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001002501011100ffc40017000100030000000000000000000000000006040708ffc400241000000209050100000000000000000000000702050608353776b6b7030436747577ffda0008010100003f00c54d3401dcbbfb9c38db8a7dd265a2159e9d945a086407383aabd52e5034c274e57179ef3bcdfca50f0af80aff00e986c64568c7ffd9
EI Q 

q
BT
/ 140 Tf
10 10 Td
(Flare-On!)'
ET
Q
```

Decoding that hex in Cyberchef, we see the `JFIF` identifier, which points us to it being a `JPEG` image.

Saving that hex stream to a file, we can see that it is recognized as an image, with some white text on a black background. However, the size is 37x1, so scaling it yields very blurred text. Trying to get the pixels and analyze them, we see that their values are oddly in the range of ASCII text. Decoding them to ASCII, we get the flag.

```Python
import re, binascii, pathlib
from PIL import Image

# save image
txt = pathlib.Path("out.pdf").read_text(errors="ignore")
m = re.search(r'BI\b.*?ID\s*([0-9A-Fa-f\s]+?)\s*EI', txt, re.S)
hexblob = re.sub(r'\s+', '', m.group(1))
path = pathlib.Path("inline.jpg")
path.write_bytes(binascii.unhexlify(hexblob))

# analyze pixels
im = Image.open("inline.jpg").convert("L")
pixels = list(im.getdata())
# print(pixels)
print("".join([chr(p) for p in pixels]))
```

FLAG: `Puzzl1ng-D3vilish-F0rmat@flare-on.com`

# 4. UnholyDragon

So, firstly looking into the given binary, we can see that it is broken, namely that the first byte of the MZ header is wrong. Modifying it to 0x4D yields a correct executable. Trying to run it, we see it generates 4 other executable, "UnholyDragon-151.exe" up to "UnholyDragon-154.exe", then it crashes. I started by diffing these other files, and noticed that a single byte differs, and those bytes didn't offer any clues, so I started analyzing the file.
At start, I looked at the entry and saw a lot of COM handlers and specific initializers, so I jumped to searching for usage of functions such as `WriteFile` and `CopyFile`, since they were most likely used for generating the additional PEs, and that lead me to this function:

```C
// positive sp value has been detected, the output may be wrong!
LONG __stdcall sub_4A8F30(int a1)
{
  LONG result; // eax
  int v2; // ebp
  int v3; // edi
  OLECHAR *v4; // ecx
  OLECHAR *v5; // eax
  OLECHAR *v6; // eax
  OLECHAR *v7; // eax
  OLECHAR *v8; // eax
  OLECHAR *v9; // eax
  OLECHAR *v10; // eax
  OLECHAR *v11; // eax
  VARIANTARG *v12; // eax
  VARIANT *v13; // ebx
  VARIANTARG *v14; // eax
  VARIANT *v15; // ebx
  VARIANTARG *v16; // eax
  OLECHAR *bstrVal; // eax
  const CHAR *Hi; // eax
  bool v19; // of
  OLECHAR *v20; // eax
  VARIANTARG *v21; // eax
  ULONG *v22; // eax
  OLECHAR **v23; // ecx
  ULONG v24; // eax
  OLECHAR *v25; // eax
  OLECHAR *v26; // edx
  OLECHAR *v27; // eax
  VARIANTARG *v28; // ebx
  int v29; // eax
  int v30; // ecx
  char *v31; // ecx
  LONG v32; // edx
  ULONG *v33; // eax
  LONG v34; // edx
  _BYTE *v35; // eax
  _BYTE *v36; // eax
  _BYTE *v37; // ecx
  ULONG v38; // eax
  BSTR *v39; // eax
  LONG v40; // edx
  int *v41; // eax
  int *v42; // eax
  int *v43; // ecx
  OLECHAR *v44; // eax
  OLECHAR *v45; // eax
  OLECHAR *v46; // eax
  OLECHAR *v47; // eax
  OLECHAR *v48; // eax
  OLECHAR *v49; // eax
  __int16 v50; // ax
  int v51; // edx
  LONG v52; // eax
  signed int v53; // eax
  LONG v54; // eax
  VARIANTARG *v55; // eax
  BSTR *v56; // ecx
  BSTR *v57; // ecx
  BSTR *v58; // ecx
  BSTR *v59; // ecx
  BSTR *v60; // ecx
  BSTR *v61; // ecx
  BSTR *v62; // ecx
  BSTR *v63; // ecx
  _BYTE Buffer[48]; // [esp+0h] [ebp-314h] BYREF
  BSTR v65[7]; // [esp+30h] [ebp-2E4h] BYREF
  int v66; // [esp+4Ch] [ebp-2C8h] BYREF
  VARIANT pvarResult; // [esp+50h] [ebp-2C4h] BYREF
  int v68[3]; // [esp+60h] [ebp-2B4h] BYREF
  VARIANTARG pvarSrc; // [esp+70h] [ebp-2A4h] BYREF
  VARIANT pvarLeft; // [esp+80h] [ebp-294h] BYREF
  BSTR v71; // [esp+90h] [ebp-284h] BYREF
  BSTR v72; // [esp+94h] [ebp-280h] BYREF
  LPCSTR psz; // [esp+98h] [ebp-27Ch] BYREF
  VARIANTARG pvarg; // [esp+9Ch] [ebp-278h] BYREF
  BSTR v75; // [esp+ACh] [ebp-268h] BYREF
  BSTR bstrRight; // [esp+B0h] [ebp-264h] BYREF
  BSTR v77; // [esp+B4h] [ebp-260h] BYREF
  BSTR bstrLeft; // [esp+B8h] [ebp-25Ch] BYREF
  void *v79; // [esp+BCh] [ebp-258h] BYREF
  BSTR v80; // [esp+C0h] [ebp-254h]
  VARIANTARG v81[37]; // [esp+C4h] [ebp-250h] BYREF

  memset(buf: v81, value: 0, count: 0x238u);
  result = __readfsdword(0x2Cu) + TlsIndex;
  v2 = *(_DWORD *)result;
  v3 = *(_DWORD *)(*(_DWORD *)result + 40);
  v4 = *(OLECHAR **)(*(_DWORD *)result + 16);
  *(_DWORD *)(v2 + 16) = (char *)v4 + 1;
  v80 = v4;
  v79 = &unk_695434;
  bstrLeft = *(BSTR *)(v2 + 8);
  *(_DWORD *)(v2 + 8) = &bstrLeft;
  if ( *(_DWORD *)(v2 + 12) )
    return result;
  v77 = (BSTR)*((_DWORD *)&v81[4].decVal.Lo64 + 2 * v3 + 1);
  bstrRight = v77;
  if ( !v77 )
    goto LABEL_179;
  (*(void (__cdecl **)(BSTR))(*(_DWORD *)v77 + 4))(bstrRight);
  if ( (int)sub_4A53A0(&v65[v3 + 1]) < 0 )
    goto LABEL_179;
  bstrRight = v65[v3 + 1];
  if ( VarBstrCat(bstrLeft: bstrRight, bstrRight: &::bstrRight, pbstrResult: &v65[v3]) < 0 )
    goto LABEL_179;
  v75 = v65[v3];
  if ( (int)sub_4A3CD8(&v65[v3 + 2]) < 0 )
    goto LABEL_179;
  pvarg.cyVal.Hi = (LONG)v65[v3 + 2];
  if ( VarBstrCat(bstrLeft: v75, bstrRight: (BSTR)pvarg.cyVal.Hi, pbstrResult: (LPBSTR)&Buffer[4 * v3 + 44]) < 0 )
    goto LABEL_179;
  pvarg.lVal = *(_DWORD *)&Buffer[4 * v3 + 44];
  if ( VarBstrCat(bstrLeft: pvarg.bstrVal, bstrRight: &off_4B08D4, pbstrResult: (LPBSTR)&Buffer[4 * v3 + 40]) < 0 )
    goto LABEL_179;
  pvarg.decVal.Hi32 = *(_DWORD *)&Buffer[4 * v3 + 40];
  v5 = (OLECHAR *)_InterlockedExchange(&v81[2].cyVal.Hi, 0);
  if ( v5 )
    SysFreeString(bstrString: v5);
  v81[2].cyVal.Hi = pvarg.decVal.Hi32;
  v6 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&Buffer[4 * v3 + 44], 0);
  if ( v6 )
    SysFreeString(bstrString: v6);
  v7 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&v65[v3], 0);
  if ( v7 )
    SysFreeString(bstrString: v7);
  v8 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&v65[v3 + 1], 0);
  if ( v8 )
    SysFreeString(bstrString: v8);
  v9 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&v65[v3 + 2], 0);
  if ( v9 )
    SysFreeString(bstrString: v9);
  if ( (int)sub_4A3CD8(&v65[v3 + 4]) < 0 )
    goto LABEL_179;
  bstrRight = v65[v3 + 4];
  if ( VarBstrCat(bstrLeft: bstrRight, bstrRight: &off_4B08E4, pbstrResult: &v65[v3 + 3]) < 0 )
    goto LABEL_179;
  v75 = v65[v3 + 3];
  v10 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&v81[3], 0);
  if ( v10 )
    SysFreeString(bstrString: v10);
  *(_DWORD *)&v81[3].vt = v75;
  v11 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&v65[v3 + 4], 0);
  if ( v11 )
    SysFreeString(bstrString: v11);
  v12 = (VARIANTARG *)&v68[v3 + 2];
  v12->vt = 16392;
  v12->lVal = (LONG)&v81[3];
  if ( sub_4A42BB((int)(&pvarSrc.decVal.Lo32 + v3), pvarSrc: v12, 13) < 0 )
    goto LABEL_179;
  v13 = (VARIANT *)(&pvarLeft.decVal.Lo32 + v3);
  v13->vt = -32760;
  v13->lVal = (LONG)aUnholydragon_0;
  if ( sub_4A4033(pvarLeft: (LPVARIANT)(&pvarSrc.decVal.Lo32 + v3), pvarRight: v13, lcid: 0, 2004287489, (int)(&pvarResult.decVal.Lo32 + v3)) < 0
    || (v14 = (VARIANTARG *)((char *)&pvarg.decVal.Lo64 + 4 * v3 + 4),
        v14->vt = 16392,
        v14->lVal = (LONG)&v81[3],
        sub_4A3E0B((int)&(&bstrLeft)[v3], pvarSrc: v14, ui: 4u) < 0)
    || (v15 = (VARIANT *)(&v81[0].decVal.Hi32 + v3),
        v15->vt = -32760,
        v15->lVal = (LONG)&off_4B0914,
        sub_4A4033(pvarLeft: (LPVARIANT)&(&bstrLeft)[v3], pvarRight: v15, lcid: 0, 2004287489, (int)&(&psz)[v3]) < 0)
    || sub_4A798C((int)(&pvarResult.decVal.Lo32 + v3), (int)&(&psz)[v3], pvarResult: (LPVARIANT)&v65[v3 + 6]) < 0 )
  {
LABEL_179:
    JUMPOUT(0x4A7707);
  }
  v16 = (VARIANTARG *)&v65[v3 + 6];
  if ( (unsigned __int16)*(_DWORD *)&v16->vt == 1 )
  {
    bstrVal = 0;
  }
  else if ( (unsigned __int16)*(_DWORD *)&v16->vt == 11 )
  {
    bstrVal = v16->bstrVal;
  }
  else
  {
    bstrRight = 0;
    v75 = 0;
    pvarg.llVal = 0;
    if ( sub_4A4260(pvargDest: (VARIANTARG *)&pvarg.decVal.Lo32, pvarSrc: v16, wFlags: 0, vt: 0xBu) < 0 )
      goto LABEL_179;
    bstrVal = v75;
  }
  bstrRight = bstrVal;
  LOBYTE(bstrRight) = (_WORD)bstrVal != 0;
  ((void __cdecl(BSTR *, BSTR))loc_4A8F15)(&v65[v3 + 6], bstrRight);
  ((void __cdecl(int *))loc_4A8F15)(&v68[v3 + 1]);
  ((void __cdecl(char *))loc_4A8F15)((char *)&pvarSrc + 4 * v3);
  ((void __cdecl(char *))loc_4A8F15)((char *)&pvarg + 4 * v3);
  *(_DWORD *)&pvarg.vt = (char *)&pvarg.decVal.Lo64 + 4 * v3 + 4;
  ((void(void))loc_4A8F15)();
  if ( LOBYTE(pvarg.vt) )
  {
    Hi = (const CHAR *)v81[1].cyVal.Hi;
    *(_DWORD *)&pvarg.vt = v81[1].cyVal.Hi;
    if ( v81[1].cyVal.Hi )
      Hi = (const CHAR *)(*(_DWORD *)(v81[1].cyVal.Hi - 4) >> 1);
    psz = Hi;
    v19 = __OFSUB__(Hi, 4);
    v20 = (OLECHAR *)(Hi - 4);
    if ( v19 )
      goto LABEL_179;
    v72 = v20;
    v21 = (VARIANTARG *)(&v81[0].decVal.Lo32 + v3);
    v21->vt = 16392;
    v21->lVal = (LONG)&v81[1].cyVal.Hi;
    if ( sub_4A42BB((int)(&v81[1].decVal.Lo32 + v3), pvarSrc: v21, (int)v72) < 0 )
      goto LABEL_179;
    v22 = &v81[1].decVal.Lo32 + v3;
    v23 = (OLECHAR **)v22[2];
    v24 = *v22;
    if ( (_BYTE)v24 == 8 )
    {
      if ( BYTE1(v24) == 64 )
      {
        v25 = *v23;
LABEL_53:
        v71 = v25;
        if ( v25 )
          v25 = SysAllocStringByteLen(psz: (LPCSTR)v25, len: *((_DWORD *)v25 - 1));
        v26 = (OLECHAR *)v81[2].cyVal.Hi;
        v81[2].cyVal.Hi = (LONG)v25;
        if ( v26 )
          SysFreeString(bstrString: v26);
        ((void __cdecl(ULONG *, BSTR))loc_4A8F15)(&v81[0].decVal.Lo32 + v3, v71);
        ((void __cdecl(ULONG *))loc_4A8F15)(&v81[1].decVal.Hi32 + v3);
        v27 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&v79 + v3, 0);
        if ( v27 )
          SysFreeString(bstrString: v27);
        v28 = (VARIANTARG *)((char *)&v81[2] + 4 * v3);
        v28->vt = 8;
        v28->lVal = (LONG)&unk_4B0924;
        if ( sub_4A44DE(pvargSrc: v28) < 0 )
          goto LABEL_179;
        v29 = sub_4A45BE(
                (int)&v81[3] + 4 * v3,
                lpString1: (PCNZWCH)v81[2].decVal.Hi32,
                pvarSrc: (VARIANTARG *)((char *)&v81[2] + 4 * v3),
                -1,
                Locale: 0);
        LOBYTE(v30) = 18;
        if ( v29 < 0 )
          goto LABEL_179;
        ((void __thiscall(int, ULONG *, LPCSTR, _DWORD))loc_4A8F15)(v30, &v81[2].decVal.Lo32, psz, *(_DWORD *)&pvarg.vt);
        v31 = (char *)&v81[2].decVal.Lo64 + 4 * v3 + 4;
        v71 = (BSTR)*((_DWORD *)v31 + 3);
        pvarLeft.llVal = *(_QWORD *)(v31 + 4);
        v81[2].decVal.Hi32 = *(_DWORD *)v31;
        v81[2].llVal = pvarLeft.llVal;
        *(_DWORD *)&v81[3].vt = v71;
        if ( v81[2].wReserved2 == 9 && sub_4A4B8B((VARIANTARG *)&v81[2].decVal.Hi32) < 0 )
          goto LABEL_179;
        ((void __cdecl(char *))loc_4A8F15)((char *)&v81[1].decVal.Lo64 + 4 * v3 + 4);
        if ( (int)sub_4A4F50(&v81[2], 1) < 0 )
          goto LABEL_179;
        pvarLeft.cyVal.Hi = v32;
        if ( v32 < 1 )
        {
          v81[0].cyVal.Hi = 1;
        }
        else
        {
          v33 = &v81[3].decVal.Lo32 + v3;
          *v33 = (ULONG)(v33 + 4);
          v33[2] = 1;
          v33[3] = 0;
          if ( (int)sub_4A4F50(&v81[2], 1) < 0 )
            goto LABEL_179;
          pvarLeft.cyVal.Hi = v34;
          v35 = &Buffer[8 * v3 + 28];
          *(_WORD *)v35 = 3;
          *((_DWORD *)v35 + 2) = v34;
          v36 = &Buffer[8 * v3 + 12];
          v37 = &Buffer[8 * v3 + 28];
          *(_QWORD *)&pvarLeft.decVal.Hi32 = *((_QWORD *)v37 + 1);
          *(_DWORD *)&pvarLeft.vt = *((_DWORD *)v37 + 1);
          *(_DWORD *)v36 = *(_DWORD *)v37;
          *(_QWORD *)(v36 + 4) = *(_QWORD *)&pvarLeft.vt;
          *((_DWORD *)v36 + 3) = pvarLeft.lVal;
          if ( (int)sub_4A4C41(&v81[2], &v81[3].decVal.Lo32 + v3, &Buffer[8 * v3 + 44]) < 0 )
            goto LABEL_179;
          pvarLeft.lVal = sub_4A4DAC(&Buffer[8 * v3 + 44]);
          v38 = sub_4A4DF0(pvarLeft.lVal);
          pvarLeft.decVal.Hi32 = v38;
          LOWORD(v65[2 * v3 + 3]) = v38;
          LOWORD(v38) = v65[2 * v3 + 3];
          *(_DWORD *)&pvarLeft.vt = v38;
          pvarSrc.cyVal.Hi = v38;
          BYTE4(pvarSrc.decVal.Lo64) = (_WORD)v38 != 0;
          pvarSrc.lVal = (LONG)&Buffer[8 * v3 + 44];
          ((void(void))loc_4A8F15)();
          if ( pvarSrc.bVal )
          {
            v39 = &v65[2 * v3 + 3];
            *v39 = (BSTR)(v39 + 4);
            v39[2] = (BSTR)1;
            v39[3] = 0;
            if ( (int)sub_4A4F50((char *)&v81[1].decVal.Lo64 + 4, 1) < 0 )
              goto LABEL_179;
            pvarLeft.lVal = v40;
            v41 = &v68[2 * v3];
            *(_WORD *)v41 = 3;
            v41[2] = v40;
            v42 = &v66 + 2 * v3;
            v43 = &v68[2 * v3];
            *(_QWORD *)&pvarLeft.vt = *((_QWORD *)v43 + 1);
            pvarSrc.cyVal.Hi = v43[1];
            *v42 = *v43;
            v42[1] = pvarSrc.cyVal.Hi;
            *((_QWORD *)v42 + 1) = *(_QWORD *)&pvarLeft.vt;
            if ( sub_4A5229((int)&v81[1].cyVal.Hi, (int)&v65[2 * v3 + 3], pvarg: (VARIANTARG *)((char *)&pvarSrc + 8 * v3)) < 0 )
              goto LABEL_179;
            *(_QWORD *)&pvarLeft.vt = 0;
            pvarSrc.llVal = 0;
            if ( sub_4A82F7(-2147483645, pvarSrc: (VARIANTARG *)((char *)&pvarSrc + 8 * v3), pvargDest: (VARIANTARG *)&pvarSrc.decVal.Lo32) < 0 )
              goto LABEL_179;
            pvarLeft.decVal.Hi32 = *(_DWORD *)&pvarLeft.vt;
            if ( __OFADD__(*(_DWORD *)&pvarLeft.vt, 1) )
              goto LABEL_179;
            *(_DWORD *)&v81[1].vt = *(_DWORD *)&pvarLeft.vt + 1;
            ((void __cdecl(char *, ULONG))loc_4A8F15)((char *)&pvarSrc + 8 * v3, pvarLeft.decVal.Hi32);
          }
          else
          {
            v81[0].cyVal.Hi = 1;
          }
        }
        goto LABEL_79;
      }
      if ( !BYTE1(v24) )
      {
        v25 = (OLECHAR *)v23;
        goto LABEL_53;
      }
    }
    v71 = 0;
    pvarLeft.llVal = 0;
    *(_QWORD *)&pvarLeft.vt = (unsigned int)&pvarLeft.decVal.Hi32;
    if ( sub_4A82F7(8, pvarSrc: (VARIANTARG *)(&v81[1].decVal.Lo32 + v3), pvargDest: (VARIANTARG *)&pvarLeft.decVal.Hi32) < 0 )
      goto LABEL_179;
    v25 = (OLECHAR *)pvarLeft.cyVal.Hi;
    *((_DWORD *)&v81[0].vt + v3) = pvarLeft.cyVal.Hi;
    goto LABEL_53;
  }
  v81[0].cyVal.Hi = 1;
LABEL_79:
  pvarLeft.decVal.Hi32 = v81[0].decVal.Mid32;
  if ( VarBstrFromI4(lIn: v81[0].cyVal.Hi, lcid: 0x409u, dwFlags: 0, pbstrOut: (BSTR *)&pvarLeft.decVal.Hi32 + 2 * v3) < 0 )
    goto LABEL_179;
  *(_DWORD *)&pvarLeft.vt = *(&pvarLeft.decVal.Hi32 + 2 * v3);
  if ( VarBstrCat(bstrLeft: ::bstrLeft, bstrRight: *(BSTR *)&pvarLeft.vt, pbstrResult: (LPBSTR)&pvarLeft + 2 * v3) < 0 )
    goto LABEL_179;
  pvarSrc.cyVal.Hi = *((_DWORD *)&pvarLeft.vt + 2 * v3);
  if ( VarBstrCat(bstrLeft: (BSTR)pvarSrc.cyVal.Hi, bstrRight: &off_4B095C, pbstrResult: (LPBSTR)&pvarSrc.decVal.Lo64 + 2 * v3 + 1) < 0 )
    goto LABEL_179;
  pvarSrc.lVal = *((_DWORD *)&pvarSrc.decVal.Lo64 + 2 * v3 + 1);
  v44 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&v81[1], 0);
  if ( v44 )
    SysFreeString(bstrString: v44);
  *(_DWORD *)&v81[1].vt = pvarSrc.lVal;
  v45 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&pvarLeft + 2 * v3, 0);
  if ( v45 )
    SysFreeString(bstrString: v45);
  v46 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&pvarLeft.decVal.Hi32 + 2 * v3, 0);
  if ( v46 )
    SysFreeString(bstrString: v46);
  if ( (int)sub_4A53A0(&(&v71)[2 * v3]) < 0 )
    goto LABEL_179;
  pvarLeft.decVal.Hi32 = (ULONG)(&v71)[2 * v3];
  if ( VarBstrCat(bstrLeft: (BSTR)pvarLeft.decVal.Hi32, bstrRight: &word_4B0970, pbstrResult: (LPBSTR)&pvarLeft.decVal.Lo64 + 2 * v3 + 1) < 0 )
    goto LABEL_179;
  *(_DWORD *)&pvarLeft.vt = *((_DWORD *)&pvarLeft.decVal.Lo64 + 2 * v3 + 1);
  pvarSrc.cyVal.Hi = *(_DWORD *)&v81[1].vt;
  if ( VarBstrCat(bstrLeft: *(BSTR *)&pvarLeft.vt, bstrRight: *(BSTR *)&v81[1].vt, pbstrResult: (LPBSTR)&pvarLeft.decVal.Lo32 + 2 * v3) < 0 )
    goto LABEL_179;
  pvarSrc.lVal = *(&pvarLeft.decVal.Lo32 + 2 * v3);
  v47 = (OLECHAR *)_InterlockedExchange(&v81[0].lVal, 0);
  if ( v47 )
    SysFreeString(bstrString: v47);
  v81[0].lVal = pvarSrc.lVal;
  v48 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&pvarLeft.decVal.Lo64 + 2 * v3 + 1, 0);
  if ( v48 )
    SysFreeString(bstrString: v48);
  v49 = (OLECHAR *)_InterlockedExchange((volatile __int32 *)&(&v71)[2 * v3], 0);
  if ( v49 )
    SysFreeString(bstrString: v49);
  if ( CopyNewFile(lpFileName: *(LPCWSTR *)&v81[0].vt, v81[0].bstrVal) < 0 )
    goto LABEL_179;
  if ( sub_4A559B(pvarg: (VARIANTARG *)&(&v72)[2 * v3], pvargSrc: &stru_4AABC0) < 0 )
    goto LABEL_179;
  if ( sub_4A5637(pvarSrc: (VARIANTARG *)&(&v72)[2 * v3], (int)(&pvarg.decVal.Lo32 + 2 * v3)) < 0 )
    goto LABEL_179;
  v50 = *((_WORD *)&pvarg.decVal.Lo32 + 4 * v3);
  v81[2].lVal = v50;
  pvarLeft.decVal.Hi32 = v81[0].cyVal.Lo;
  *(_DWORD *)&pvarLeft.vt = v50;
  if ( sub_4A59CA(v81[0].bstrVal, v50, dwBytes: 128, dwDesiredAccess: 0xC0000000, dwShareMode: 3u, dwCreationDisposition: 4u, 5, 32, 0) < 0 )
    goto LABEL_179;
  if ( v81[2].iVal != v81[2].lVal )
    goto LABEL_179;
  pvarLeft.decVal.Hi32 = v81[2].cyVal.Lo;
  *(_DWORD *)&pvarLeft.vt = (char *)&pvarg.decVal.Lo64 + 8 * v3 + 4;
  LOWORD(v51) = v81[2].iVal;
  if ( (int)sub_4A5DE7(v51, *(_DWORD *)&pvarLeft.vt) < 0 )
    goto LABEL_179;
  v81[2].cyVal.Hi = *((_DWORD *)&pvarg.decVal.Lo64 + 2 * v3 + 1);
  if ( __OFSUB__(v81[0].cyVal.Hi, 1) )
    goto LABEL_179;
  pvarLeft.decVal.Hi32 = v81[0].cyVal.Hi - 1;
  *(_DWORD *)&pvarLeft.vt = (v81[0].cyVal.Hi - 1) ^ 0x6746;
  pvarSrc.cyVal.Hi = *((_DWORD *)&v81[1].decVal.Lo64 + 2 * v3 + 1);
  if ( (int)sub_4A5E4C(pvarSrc.cyVal.Hi, *(_DWORD *)&pvarLeft.vt) < 0 )
    goto LABEL_179;
  if ( __OFSUB__(v81[2].cyVal.Hi, 1) )
    goto LABEL_179;
  pvarLeft.decVal.Hi32 = v81[2].cyVal.Hi - 1;
  *(_DWORD *)&pvarLeft.vt = *((_DWORD *)&v81[1].decVal.Lo64 + 2 * v3 + 1);
  v52 = sub_4A86A3(a1: *(int *)&pvarLeft.vt, a2: 1, a3: v81[2].cyVal.Hi - 1, a4: (int)&(&v75)[2 * v3]);
  if ( v52 < 0 )
    goto LABEL_179;
  *(_DWORD *)&v81[3].vt = (&v75)[2 * v3];
  *(_QWORD *)&pvarLeft.vt = __PAIR64__(v81[2].cyVal.Lo, *(unsigned int *)&v81[3].vt);
  pvarSrc.cyVal.Hi = v52;
  if ( sub_4A8842(v81[2].lVal, *(int *)&v81[3].vt, NumberOfBytesRead: 1u, (int)&pvarSrc.cyVal.Hi) < 0 )
    goto LABEL_179;
  sub_4A5EEF(pvarSrc.cyVal.Hi, lpBuffer: &pvarSrc.decVal.Lo32 + v3 - 32, nNumberOfBytesToRead: 1u);
  v53 = sub_4A5FB2(pvarSrc.cyVal.Hi);
  if ( v53 < 0 )
    goto LABEL_179;
  LOBYTE(v53) = v81[3].decVal.Hi32;
  pvarLeft.decVal.Hi32 = v53;
  *(_DWORD *)&pvarLeft.vt = LOBYTE(v81[3].decVal.Hi32);
  pvarSrc.cyVal.Hi = *((_DWORD *)&v81[1].decVal.Lo64 + 2 * v3 + 1);
  if ( sub_4A86A3(a1: pvarSrc.cyVal.Hi, a2: 1, a3: 255, a4: (int)&(&bstrRight)[2 * v3]) < 0 )
    goto LABEL_179;
  v54 = *(_DWORD *)&pvarLeft.vt ^ (unsigned int)(&bstrRight)[2 * v3];
  if ( (v54 & 0xFFFFFF00) != 0 )
    goto LABEL_179;
  *((_BYTE *)&pvarSrc.decVal.Lo32 + 4 * v3 - 128) = v54;
  *(_QWORD *)&pvarLeft.vt = __PAIR64__(v81[2].cyVal.Lo, *(unsigned int *)&v81[3].vt);
  pvarSrc.cyVal.Hi = v54;
  if ( sub_4A8842(v81[2].lVal, *(int *)&v81[3].vt, NumberOfBytesRead: 0, (int)&pvarSrc.cyVal.Hi) < 0 )
    goto LABEL_179;
  write_byte(pvarSrc.cyVal.Hi, lpBuffer: &pvarSrc.decVal.Lo32 + v3 - 32, nNumberOfBytesToWrite: 1u);
  if ( sub_4A8B35(NumberOfBytesWritten: pvarSrc.decVal.Mid32) < 0 )
    goto LABEL_179;
  pvarLeft.decVal.Hi32 = v81[2].cyVal.Lo;
  if ( (int)sub_4A8BFE(v81[2].lVal) < 0 )
    goto LABEL_179;
  v55 = (VARIANTARG *)&(&v77)[2 * v3];
  v55->vt = 16392;
  v55->lVal = (LONG)&v81[0].lVal;
  if ( start_process(cmd_line: v55, show_window: 1, process_id: (double *)&v81[0].vt + v3) < 0 )
    goto LABEL_179;
  ((void __cdecl(BSTR *))loc_4A8F15)(&(&v77)[2 * v3]);
  if ( v80 )
    SysFreeString(bstrString: v80);
  if ( *(_DWORD *)&v81[0].vt )
    SysFreeString(bstrString: *(BSTR *)&v81[0].vt);
  if ( v81[0].decVal.Hi32 )
    SysFreeString(bstrString: (BSTR)v81[0].decVal.Hi32);
  if ( v81[0].cyVal.Hi )
    SysFreeString(bstrString: (BSTR)v81[0].cyVal.Hi);
  if ( *(_DWORD *)&v81[1].vt )
    SysFreeString(bstrString: *(BSTR *)&v81[1].vt);
  if ( (v81[1].decVal.Hi32 & 0xA) == 8 || v81[1].wReserved2 >= 27 )
    ((void __cdecl(ULONG *))loc_4A8F15)(&v81[1].decVal.Hi32);
  if ( v81[3].decVal.Hi32 )
    SysFreeString(bstrString: (BSTR)v81[3].decVal.Hi32);
  if ( v81[3].lVal )
    SysFreeString(bstrString: v81[3].bstrVal);
  v56 = (BSTR *)&Buffer[4 * v3];
  if ( *v56 )
    SysFreeString(bstrString: *v56);
  v57 = (BSTR *)&Buffer[4 * v3 + 4];
  if ( *v57 )
    SysFreeString(bstrString: *v57);
  v58 = (BSTR *)&Buffer[4 * v3 + 12];
  if ( *v58 )
    SysFreeString(bstrString: *v58);
  if ( (*(_WORD *)&Buffer[4 * v3 + 20] & 0xA) == 8 || (__int16)*(_DWORD *)&Buffer[4 * v3 + 20] >= 27 )
    ((void __cdecl(_BYTE *))loc_4A8F15)(&Buffer[4 * v3 + 20]);
  if ( ((int)v65[v3] & 0xA) == 8 || (__int16)v65[v3] >= 27 )
    ((void __cdecl(BSTR *))loc_4A8F15)(&v65[v3]);
  if ( ((int)v65[v3 + 3] & 0xA) == 8 || (__int16)v65[v3 + 3] >= 27 )
    ((void __cdecl(BSTR *))loc_4A8F15)(&v65[v3 + 3]);
  if ( (v68[v3 + 2] & 0xA) == 8 || (__int16)v68[v3 + 2] >= 27 )
    ((void __cdecl(int *))loc_4A8F15)(&v68[v3 + 2]);
  if ( (*(_WORD *)(&pvarSrc.decVal.Hi32 + v3) & 0xA) == 8 || (__int16)*(&pvarSrc.decVal.Hi32 + v3) >= 27 )
    ((void __cdecl(ULONG *))loc_4A8F15)(&pvarSrc.decVal.Hi32 + v3);
  v59 = &(&v71)[v3];
  if ( *v59 )
    SysFreeString(bstrString: *v59);
  if ( ((int)(&psz)[v3] & 0xA) == 8 || (__int16)(&psz)[v3] >= 27 )
    ((void __cdecl(LPCSTR *))loc_4A8F15)(&(&psz)[v3]);
  if ( (*(_WORD *)(&pvarg.decVal.Lo32 + v3) & 0xA) == 8 || (__int16)*(&pvarg.decVal.Lo32 + v3) >= 27 )
    ((void __cdecl(ULONG *))loc_4A8F15)(&pvarg.decVal.Lo32 + v3);
  if ( ((int)(&bstrRight)[v3] & 0xA) == 8 || (__int16)(&bstrRight)[v3] >= 27 )
    ((void __cdecl(BSTR *))loc_4A8F15)(&(&bstrRight)[v3]);
  if ( (v68[2 * v3 - 25] & 0xA) == 8 || (__int16)v68[2 * v3 - 25] >= 27 )
  {
    pvarResult.cyVal.Hi = (LONG)&v68[2 * v3 - 25];
    ((void(void))loc_4A8F15)();
  }
  if ( ((int)v65[2 * v3 + 4] & 0xA) == 8 || (__int16)v65[2 * v3 + 4] >= 27 )
  {
    pvarResult.lVal = (LONG)&v65[2 * v3 + 4];
    ((void(void))loc_4A8F15)();
  }
  v60 = (BSTR *)&pvarResult + 2 * v3;
  if ( *v60 )
    SysFreeString(bstrString: *v60);
  v61 = (BSTR *)(&pvarResult.decVal.Hi32 + 2 * v3);
  if ( *v61 )
    SysFreeString(bstrString: *v61);
  v62 = (BSTR *)&pvarResult.decVal.Lo64 + 2 * v3 + 1;
  if ( *v62 )
    SysFreeString(bstrString: *v62);
  v63 = (BSTR *)&v68[2 * v3];
  if ( *v63 )
    SysFreeString(bstrString: *v63);
  if ( (*(_WORD *)(&pvarLeft.decVal.Hi32 + 2 * v3) & 0xA) == 8 || (__int16)*(&pvarLeft.decVal.Hi32 + 2 * v3) >= 27 )
    ((void __cdecl(ULONG *))loc_4A8F15)(&pvarLeft.decVal.Hi32 + 2 * v3);
  *(_DWORD *)&pvarResult.vt = (&v75)[2 * v3];
  v66 = *(_DWORD *)&pvarResult.vt;
  if ( !*(_DWORD *)&pvarResult.vt )
    goto LABEL_179;
  (*(void (__cdecl **)(int))(**(_DWORD **)&pvarResult.vt + 8))(v66);
  *(_DWORD *)(v2 + 8) = *(_DWORD *)&pvarResult.vt;
  return pvarResult.cyVal.Hi;
}
```
This is a big function, where it seems like the magic of creating the file and modifying it happens, with a lot of boilerplate COM code.
Inspecting what happens between the copying and writing of that one byte, we can see a XOR of a byte happening, and then that byte is written to our newly generated file:
```C
 if ( sub_4A86A3(a1: pvarSrc.cyVal.Hi, a2: 1, a3: 255, a4: (int)&(&bstrRight)[2 * v3]) < 0 )
    goto LABEL_179;
  v54 = *(_DWORD *)&pvarLeft.vt ^ (unsigned int)(&bstrRight)[2 * v3];
  if ( (v54 & 0xFFFFFF00) != 0 )
    goto LABEL_179;
  *((_BYTE *)&pvarSrc.decVal.Lo32 + 4 * v3 - 128) = v54;
  ...
  write_byte(pvarSrc.cyVal.Hi, lpBuffer: &pvarSrc.decVal.Lo32 + v3 - 32, nNumberOfBytesToWrite: 1u);
```
And the offset is traced to be coming from:
```C
pvarLeft.decVal.Hi32 = v81[2].cyVal.Hi - 1;
  *(_DWORD *)&pvarLeft.vt = *((_DWORD *)&v81[1].decVal.Lo64 + 2 * v3 + 1);
  v52 = sub_4A86A3(a1: *(int *)&pvarLeft.vt, a2: 1, a3: v81[2].cyVal.Hi - 1, a4: (int)&(&v75)[2 * v3]);
```
So now, it looks like we need to dive into `sub_4A86A3` and see how these values are generated.
```C
int __stdcall sub_4A86A3(int a1, int a2, int a3, int a4)
{
  _DWORD *v4; // ebp
  int v5; // edi
  int v6; // ecx
  char v7; // fps
  int v11; // eax
  int v12; // ecx
  VARIANT pvarResult; // [esp+0h] [ebp-124h] BYREF
  _DWORD v15[20]; // [esp+1Ch] [ebp-108h]
  VARIANTARG v16; // [esp+6Ch] [ebp-B8h] BYREF
  int v17; // [esp+7Ch] [ebp-A8h]
  int v18; // [esp+80h] [ebp-A4h]
  int v19; // [esp+84h] [ebp-A0h]
  int v20; // [esp+88h] [ebp-9Ch]
  double v21; // [esp+8Ch] [ebp-98h]
  int v22; // [esp+94h] [ebp-90h]
  double v23; // [esp+98h] [ebp-8Ch]
  int v24; // [esp+A0h] [ebp-84h]
  int v25; // [esp+A4h] [ebp-80h]
  _QWORD v26[15]; // [esp+A8h] [ebp-7Ch] BYREF

  memset(buf: (char *)&v26[1] + 4, value: 0, count: 0x60u);
  v4 = *(_DWORD **)(__readfsdword(0x2Cu) + TlsIndex);
  v5 = v4[10];
  v6 = v4[4];
  v4[4] = v6 + 1;
  LODWORD(v26[1]) = v6;
  HIDWORD(v26[0]) = &unk_695480;
  LODWORD(v26[0]) = v4[2];
  v4[2] = v26;
  if ( v4[3] )
    JUMPOUT(0x4A869E);
  v25 = v15[v5 + 3];
  v24 = v25;
  if ( !v25 )
    goto LABEL_18;
  (*(void (__cdecl **)(int))(*(_DWORD *)v25 + 4))(v24);
  v24 = v15[v5 + 3];
  v23 = (double)v24;
  v22 = v15[v5 + 2];
  if ( sub_4A79EB(a1: v22, a2: (int)&v26[10]) < 0 )
    goto LABEL_18;
  v21 = *(float *)&v26[10];
  v20 = v15[v5 + 4];
  v19 = v15[v5 + 3];
  if ( __OFSUB__(v20, v19) )
    goto LABEL_18;
  v18 = v20 - v19;
  if ( __OFADD__(v20 - v19, 1) )
    goto LABEL_18;
  v17 = v20 - v19 + 1;
  v16.dblVal = (double)v17 * v21 + v23;
  if ( (v7 & 4) != 0 )
    goto LABEL_18;
  if ( (v7 & 9) != 0 )
    goto LABEL_18;
  LOWORD(v26[8]) = 5;
  v26[9] = v16.llVal;
  if ( sub_4A7FB1(pvarResult: (VARIANT *)((char *)&pvarResult + 4 * v5), (int)&v26[8]) < 0 )
    goto LABEL_18;
  memset(&v16, 0, sizeof(v16));
  v11 = sub_4A82F7(3, pvarSrc: (VARIANT *)((char *)&pvarResult + 4 * v5), pvargDest: &v16);
  LOBYTE(v12) = 7;
  if ( v11 < 0 )
    goto LABEL_18;
  LODWORD(v26[7]) = v16.lVal;
  ((void __thiscall(int, char *, LONG, int, int))loc_4A8F15)(v12, (char *)&pvarResult + 4 * v5, v16.lVal, v17, v18);
  if ( (BYTE4(v26[10]) & 0xA) == 8 || SWORD2(v26[10]) >= 27 )
    ((void __cdecl(char *))loc_4A8F15)((char *)&v26[10] + 4);
  *(_DWORD *)v15[v5 + 3] = v26[6];
  LODWORD(v23) = v15[v5];
  v22 = LODWORD(v23);
  if ( !LODWORD(v23) )
LABEL_18:
    JUMPOUT(0x4A7707);
  (*(void (__cdecl **)(int))(*(_DWORD *)LODWORD(v23) + 8))(v22);
  v4[2] = LODWORD(v23);
  return v25;
}
```
It does quite a few function calls, but looking into the first one, we can see that it builds in the return variable something similar to an LCG:
```C
  *(double *)(*((_DWORD *)&v39 + v3) + 116) = *(double *)(*((_DWORD *)&v39 + v3) + 116) * dbl_4AABD0 + dbl_4AABD8;
  if ( (v5 & 4) != 0 )
    goto LABEL_34;
  if ( (v5 & 9) != 0 )
    goto LABEL_34;
  v9 = *((_DWORD *)&v39 + v3);
  v10 = *(_DWORD *)(v9 + 116);
  v11 = *(_DWORD *)(v9 + 120);
  LOWORD(v41[20]) = 5;
  v41[22] = v10;
  v41[23] = v11;
  v39 = *(double *)(*((_DWORD *)&v39 + v3) + 116) / dbl_4AABE0;
```
```
.data:004AABD0 dbl_4AABD0      dq 1.103515245e9        ; DATA XREF: sub_4A79EB+66↑r
.data:004AABD8 dbl_4AABD8      dq 12345.0              ; DATA XREF: sub_4A79EB+6E↑r
.data:004AABE0 dbl_4AABE0      dq 4.294967296e9        ; DATA XREF: sub_4A79EB+B3↑r
.data:004AABE8 dbl_4AABE8      dq 65536.0              ; DATA XREF: sub_4A79EB+1AE↑r
```

Given the value by which it divides the result, this maps the value uniformly into [0, 1).
Looking further, we see the same state being uniformly mapped yet again, to generate another random value. Seeing as how we have two values here, but only 1 is used in the return, we conclude that this is a shared double state for the LCG machine.
```C
   *(float *)&v41[9] = *(float *)&v37.vt / flt_4B0994;
```
Going back to our function, we can see that it then maps the value to the given bounds (function parameters):
```C
  v16.dblVal = (double)v17 * v21 + v23;
  if ( (v7 & 4) != 0 )
    goto LABEL_18;
  if ( (v7 & 9) != 0 )
    goto LABEL_18;
  LOWORD(v26[8]) = 5;
  v26[9] = v16.llVal;
```
That value is later plugged into `VarInt` for conversion to integer. So we now have the building blocks for generating the random number, we only miss the initial state. By looking at our main function, if we track variables, we actually get that the state is the iteration (number of the program, i.e. 150 in the initial case) XORed with a constant:
```C
 *(_DWORD *)&pvarLeft.vt = (v81[0].cyVal.Hi - 1) ^ 0x6746;
  pvarSrc.cyVal.Hi = *((_DWORD *)&v81[1].decVal.Lo64 + 2 * v3 + 1);
```
Puttin everything together and making a script that allows us to move backwards and forwards, we get this:
```Python
import sys
from pathlib import Path

A = 1103515245
C = 12345
M = 0x100000000  # 2^32
SCALE15 = 32768.0

def lcg_step(state: int) -> int:
    return (state * A + C) % M

def rand15(state: int) -> (int, int):
    state = lcg_step(state)
    return ((state >> 16) & 0x7FFF), state

def pick_inclusive(state: int, lo: int, hi: int) -> (int, int):
    r15, state = rand15(state)
    r = r15 / SCALE15
    span = hi - lo + 1
    val = int(r * span)
    if val >= span:
        val = span - 1
    return lo + val, state

def find_single_diff(a: bytes, b: bytes):
    if len(a) != len(b): # panic
        raise ValueError("Files differ in size; expected identical length with single-byte change")
    diffs = [(i, a[i], b[i]) for i in range(len(a)) if a[i] != b[i]]
    if len(diffs) != 1: # panic
        raise ValueError(f"Expected 1 diff, found {len(diffs)}")
    return diffs[0]

def predict_offset_and_key_for_iter(iter_idx: int, file_size: int) -> int:
    seed = ((iter_idx) ^ 0x6746) & 0xFFFFFFFF
    off, seed = pick_inclusive(seed, 0, file_size - 2) # 0-indexed
    key, seed = pick_inclusive(seed, 1, 255)
    return off, key

def move_mutations(base_prefix: str, start: int, stop: int, sgn: int):
    cur_path = Path(f"{base_prefix}-{start}.exe")
    cur_bytes = bytearray(cur_path.read_bytes())
    size = len(cur_bytes)
    keys = []
    origs = []
    nexts = []

    for i in range(start, stop, sgn):
        off, key = predict_offset_and_key_for_iter(i if sgn != -1 else i - 1, size)
        keys.append(key)
        prev_bytes = bytearray(cur_bytes)
        origs.append(prev_bytes[off])
        prev_bytes[off] = prev_bytes[off] ^ key
        nexts.append(prev_bytes[off])

        
        if b"@flare" in prev_bytes:
            print(f"iter {i} is lucky")
            break

        print(f"{i}->{i + sgn}: offset={off}, curr=0x{cur_bytes[off]:02x}, " 
            + "next" if sgn == 1 else "prev" 
            + f"=0x{prev_bytes[off]:02x}, key=0x{key:02x}")

        cur_bytes = prev_bytes
    print("keys=" + str(keys))
    print("origs=" + str(origs))
    print("nexts=" + str(nexts))
    out_path = Path(f"{base_prefix}-{stop}.exe")
    out_path.write_bytes(cur_bytes)

def main():
    if len(sys.argv) < 2:
        return

    mode = sys.argv[1]
    base = sys.argv[2]
    a = int(sys.argv[3])
    b = int(sys.argv[4])

    if mode == "check":
        for i in range(a, b):
            src = Path(f"{base}-{i}.exe")
            dst = Path(f"{base}-{i+1}.exe")
            a_bytes = src.read_bytes()
            b_bytes = dst.read_bytes()

            # observed (from files)
            off_obs, orig, new = find_single_diff(a_bytes, b_bytes)
            key_obs = orig ^ new

            # predicted (from PRNG)
            off_pred, key_pred = predict_offset_and_key_for_iter(i, len(a_bytes))

            match_key = "OK" if key_obs == key_pred else f"mismatch (obs=0x{key_obs:02x}, rnd=0x{key_pred:02x})"
            match_off = "OK" if off_obs == off_pred else f"mismatch (obs={off_obs}, rnd={off_pred})"

            print(f"{i}->{i+1}: "
                  f"offset(obs)={off_obs}, offset(rnd)={off_pred} [{match_off}], "
                  f"orig=0x{orig:02x}, new=0x{new:02x}, "
                  f"key(obs)=0x{key_obs:02x}, key(rnd)=0x{key_pred:02x} [{match_key}]")
    elif mode == "reverse":
        move_mutations(base, a, b, -1)
    elif mode == "continue":
        move_mutations(base, a, b, 1)
    else:
        print("Unknown mode")

if __name__ == "__main__":
    main()
```
Running this and checking up to "UnholyDragon-250000.exe" or "UnholyDragon--150.exe", we get...nothing. At this point I started re-reversing the file, or looking at "UnholyDragon-0.exe" or "UnholyDragon-250000.exe" for any changes, but nothing significant was found.

Then, desperation came, as nothing was working.
After lots of failed attempts, I ended up renaming the file to something else and running it, which somehow made it unpatch itself, and fixing the "-150" variant (same byte fix as before) and running it yields a photo of the flag opening up in a form.
wtf

FLAG: `dr4g0n_d3n1al_of_s3rv1ce@flare-on.com`

# 5. ntfsm

We are given a big Windows binary, which, upon running, seems to require for us a 16 characters password. Upon fiddling with it, we can see that it kind of spams us with message boxes, so I think that some brute force options are out of the question.

Diving into decompiling it, IDA kind of doesn't want to analyze it, so we stop auto-analysis and go by hand. Looking through the start functions and reaching `WinMain`, we are greeted by a quite big function:

```C
__int64 __fastcall main_func(int a1, __int64 a2)
{
  __int64 pos; // [rsp+58AB0h] [rbp-8E8h] BYREF
  _QWORD transitions[2]; // [rsp+58AB8h] [rbp-8E0h] BYREF
  __int64 v5; // [rsp+58AC8h] [rbp-8D0h]
  __int64 v6; // [rsp+58AD0h] [rbp-8C8h]
  _BYTE *v7; // [rsp+58AD8h] [rbp-8C0h]
  __int64 v8; // [rsp+58AE0h] [rbp-8B8h]
  __int64 v9; // [rsp+58AE8h] [rbp-8B0h]
  _BYTE *v10; // [rsp+58AF0h] [rbp-8A8h]
  __int64 pwd; // [rsp+58AF8h] [rbp-8A0h]
  __int64 v12; // [rsp+58B00h] [rbp-898h]
  _BYTE *v13; // [rsp+58B08h] [rbp-890h]
  __int64 v14; // [rsp+58B10h] [rbp-888h]
  __int64 v15; // [rsp+58B18h] [rbp-880h]
  __int64 v16; // [rsp+58B20h] [rbp-878h]
  _BYTE *v17; // [rsp+58B28h] [rbp-870h]
  __int64 v18; // [rsp+58B30h] [rbp-868h]
  __int64 v19; // [rsp+58B38h] [rbp-860h]
  __int64 v20; // [rsp+58B40h] [rbp-858h]
  _BYTE *v21; // [rsp+58B48h] [rbp-850h]
  __int64 v22; // [rsp+58B50h] [rbp-848h]
  __int64 v23; // [rsp+58B58h] [rbp-840h]
  __int64 v24; // [rsp+58B60h] [rbp-838h]
  _BYTE *v25; // [rsp+58B68h] [rbp-830h]
  __int64 v26; // [rsp+58B70h] [rbp-828h]
  __int64 v27; // [rsp+58B78h] [rbp-820h]
  __int64 v28; // [rsp+58B80h] [rbp-818h]
  _BYTE *v29; // [rsp+58B88h] [rbp-810h]
  __int64 v30; // [rsp+58B90h] [rbp-808h]
  __int64 v31; // [rsp+58B98h] [rbp-800h]
  __int64 v32; // [rsp+58BA0h] [rbp-7F8h]
  _BYTE *v33; // [rsp+58BA8h] [rbp-7F0h]
  __int64 v34; // [rsp+58BB0h] [rbp-7E8h]
  __int64 v35; // [rsp+58BB8h] [rbp-7E0h]
  __int64 v36; // [rsp+58BC0h] [rbp-7D8h]
  _BYTE *v37; // [rsp+58BC8h] [rbp-7D0h]
  __int64 v38; // [rsp+58BD0h] [rbp-7C8h]
  __int64 v39; // [rsp+58BD8h] [rbp-7C0h]
  __int64 v40; // [rsp+58BE0h] [rbp-7B8h]
  _BYTE *v41; // [rsp+58BE8h] [rbp-7B0h]
  __int64 v42; // [rsp+58BF0h] [rbp-7A8h]
  __int64 v43; // [rsp+58BF8h] [rbp-7A0h]
  __int64 v44; // [rsp+58C00h] [rbp-798h]
  _BYTE *v45; // [rsp+58C08h] [rbp-790h]
  __int64 v46; // [rsp+58C10h] [rbp-788h]
  __int64 v47; // [rsp+58C18h] [rbp-780h]
  _BYTE *v48; // [rsp+58C20h] [rbp-778h]
  __int64 v49; // [rsp+58C28h] [rbp-770h]
  __int64 v50; // [rsp+58C30h] [rbp-768h]
  __int64 v51; // [rsp+58C38h] [rbp-760h]
  _BYTE *v52; // [rsp+58C40h] [rbp-758h]
  __int64 v53; // [rsp+58C48h] [rbp-750h]
  __int64 v54; // [rsp+58C50h] [rbp-748h]
  __int64 v55; // [rsp+58C58h] [rbp-740h]
  _BYTE *v56; // [rsp+58C60h] [rbp-738h]
  __int64 v57; // [rsp+58C68h] [rbp-730h]
  __int64 v58; // [rsp+58C70h] [rbp-728h]
  __int64 v59; // [rsp+58C78h] [rbp-720h]
  _BYTE *v60; // [rsp+58C80h] [rbp-718h]
  __int64 v61; // [rsp+58C88h] [rbp-710h]
  __int64 v62; // [rsp+58C90h] [rbp-708h]
  __int64 v63; // [rsp+58C98h] [rbp-700h]
  _BYTE *v64; // [rsp+58CA0h] [rbp-6F8h]
  __int64 v65; // [rsp+58CA8h] [rbp-6F0h]
  __int64 v66; // [rsp+58CB0h] [rbp-6E8h]
  _BYTE *v67; // [rsp+58CB8h] [rbp-6E0h]
  __int64 v68; // [rsp+58CC0h] [rbp-6D8h]
  __int64 v69; // [rsp+58CC8h] [rbp-6D0h]
  _BYTE *v70; // [rsp+58CD0h] [rbp-6C8h]
  __int64 v71; // [rsp+58CD8h] [rbp-6C0h]
  __int64 v72; // [rsp+58CE0h] [rbp-6B8h]
  _BYTE *v73; // [rsp+58CE8h] [rbp-6B0h]
  __int64 v74; // [rsp+58CF0h] [rbp-6A8h]
  __int64 v75; // [rsp+58CF8h] [rbp-6A0h]
  _BYTE *v76; // [rsp+58D00h] [rbp-698h]
  __int64 v77; // [rsp+58D08h] [rbp-690h]
  __int64 v78; // [rsp+58D10h] [rbp-688h]
  __int64 v79; // [rsp+58D18h] [rbp-680h]
  __int64 v80; // [rsp+58D20h] [rbp-678h]
  __int64 v81; // [rsp+58D28h] [rbp-670h]
  __int64 v82; // [rsp+58D30h] [rbp-668h]
  __int64 v83; // [rsp+58D38h] [rbp-660h]
  _BYTE v84[240]; // [rsp+58E28h] [rbp-570h] BYREF
  _BYTE v85[40]; // [rsp+58F18h] [rbp-480h] BYREF
  _BYTE v86[40]; // [rsp+58F40h] [rbp-458h] BYREF
  _BYTE v87[80]; // [rsp+58F68h] [rbp-430h] BYREF
  _BYTE v88[40]; // [rsp+58FB8h] [rbp-3E0h] BYREF
  _BYTE v89[40]; // [rsp+58FE0h] [rbp-3B8h] BYREF
  _BYTE v90[40]; // [rsp+59008h] [rbp-390h] BYREF
  _BYTE v91[40]; // [rsp+59030h] [rbp-368h] BYREF
  _BYTE v92[40]; // [rsp+59058h] [rbp-340h] BYREF
  _BYTE v93[40]; // [rsp+59080h] [rbp-318h] BYREF
  _BYTE v94[80]; // [rsp+590A8h] [rbp-2F0h] BYREF
  _BYTE v95[40]; // [rsp+590F8h] [rbp-2A0h] BYREF
  _BYTE v96[40]; // [rsp+59120h] [rbp-278h] BYREF
  _BYTE v97[40]; // [rsp+59148h] [rbp-250h] BYREF
  _BYTE v98[40]; // [rsp+59170h] [rbp-228h] BYREF
  _BYTE v99[40]; // [rsp+59198h] [rbp-200h] BYREF
  _BYTE v100[40]; // [rsp+591C0h] [rbp-1D8h] BYREF
  _BYTE v101[40]; // [rsp+591E8h] [rbp-1B0h] BYREF
  _BYTE v102[40]; // [rsp+59210h] [rbp-188h] BYREF
  _BYTE v103[40]; // [rsp+59238h] [rbp-160h] BYREF
  _BYTE v104[40]; // [rsp+59260h] [rbp-138h] BYREF
  _BYTE v105[40]; // [rsp+59288h] [rbp-110h] BYREF
  _BYTE v106[40]; // [rsp+592B0h] [rbp-E8h] BYREF
  _BYTE v107[40]; // [rsp+592D8h] [rbp-C0h] BYREF
  _BYTE v108[40]; // [rsp+59300h] [rbp-98h] BYREF
  _BYTE v109[40]; // [rsp+59328h] [rbp-70h] BYREF
  _BYTE v110[24]; // [rsp+59350h] [rbp-48h] BYREF
  _BYTE v111[24]; // [rsp+59368h] [rbp-30h] BYREF

  sub_140002725((__int64)v105, (__int64)"state");
  sub_140002725((__int64)v106, (__int64)"input");
  sub_140002725((__int64)v107, (__int64)"position");
  sub_140002725((__int64)v108, (__int64)"transitions");
  pos = 0;
  transitions[0] = 0;
  transitions[1] = v85;
  v5 = sub_14000166D((__int64)v85, (__int64)v107);
  v6 = v5;
  read_file_wrap(v5, (__int64)&pos);
  v7 = v86;
  v8 = sub_14000166D((__int64)v86, (__int64)v108);
  v9 = v8;
  read_file_wrap(v8, (__int64)transitions);
  if ( pos == 16 )
  {
    if ( transitions[0] == 16 )
    {
      sub_140002829("correct!\n");
      memset(buf: v111, value: 0, count: 0x11u);
      v10 = v87;
      pwd = sub_14000166D((__int64)v87, (__int64)v106);
      v12 = pwd;
      if ( (unsigned __int8)read_file(pwd, (__int64)v111, 16) )
      {
        sub_140002725((__int64)v109, (__int64)v111);
        win_func((__int64)v109);
        sub_140001947(v109);
      }
      v13 = v88;
      v14 = sub_14000166D((__int64)v88, (__int64)v108);
      v15 = v14;
      v16 = v14;
      v17 = v89;
      v18 = sub_14000166D((__int64)v89, (__int64)v106);
      v19 = v18;
      v20 = v18;
      v21 = v90;
      v22 = sub_14000166D((__int64)v90, (__int64)v107);
      v23 = v22;
      v24 = v22;
      v25 = v91;
      v26 = sub_14000166D((__int64)v91, (__int64)v105);
      v27 = v26;
      v28 = v26;
      sub_140001B45(v26, v24, v20, v16);
      sub_1400013ED(0);
    }
    else
    {
      sub_140002829("wrong!\n");
      v29 = v92;
      v30 = sub_14000166D((__int64)v92, (__int64)v108);
      v31 = v30;
      v32 = v30;
      v33 = v93;
      v34 = sub_14000166D((__int64)v93, (__int64)v106);
      v35 = v34;
      v36 = v34;
      v37 = v94;
      v38 = sub_14000166D((__int64)v94, (__int64)v107);
      v39 = v38;
      v40 = v38;
      v41 = v84;
      v42 = sub_14000166D((__int64)v84, (__int64)v105);
      v43 = v42;
      v44 = v42;
      sub_140001B45(v42, v40, v36, v32);
      sub_1400013ED(1);
    }
  }
  memset(buf: v110, value: 0, count: 0x11u);
  v45 = v95;
  v46 = sub_14000166D((__int64)v95, (__int64)v105);
  v47 = v46;
  read_file_wrap(v46, (__int64)&state_qword);
  if ( state_qword == -1 )
  {
    if ( a1 == 2 )
    {
      if ( !(unsigned int)sub_140004822(*(_QWORD *)(a2 + 8), &unk_141217E98) )
      {
        v48 = v96;
        v49 = sub_14000166D((__int64)v96, (__int64)v108);
        v50 = v49;
        v51 = v49;
        v52 = v97;
        v53 = sub_14000166D((__int64)v97, (__int64)v106);
        v54 = v53;
        v55 = v53;
        v56 = v98;
        v57 = sub_14000166D((__int64)v98, (__int64)v107);
        v58 = v57;
        v59 = v57;
        v60 = v99;
        v61 = sub_14000166D((__int64)v99, (__int64)v105);
        v62 = v61;
        v63 = v61;
        sub_140001B45(v61, v59, v55, v51);
        sub_1400013ED(2);
      }
      if ( sub_1400026CB(*(_QWORD *)(a2 + 8)) != 16 )
      {
        sub_140002829("input 16 characters");
        sub_1400013ED(1);
      }
      sub_1400020F4(v110, *(_QWORD *)(a2 + 8));
      v64 = v100;
      v65 = sub_14000166D((__int64)v100, (__int64)v106);
      v66 = v65;
      sub_14000297D(v65, v110, 16);
      v67 = v101;
      v68 = sub_14000166D((__int64)v101, (__int64)v107);
      v69 = v68;
      sub_140001B4A(v68, 0);
      v70 = v102;
      v71 = sub_14000166D((__int64)v102, (__int64)v108);
      v72 = v71;
      sub_140001B4A(v71, 0);
      v73 = v103;
      v74 = sub_14000166D((__int64)v103, (__int64)v105);
      v75 = v74;
      sub_140001B4A(v74, 0);
    }
    else
    {
      sub_140002829("usage: ./ntfsm <password>\nto reset the binary in case of weird behavior: ./ntfsm -r");
      sub_1400013ED(1);
    }
  }
  v76 = v104;
  v77 = sub_14000166D((__int64)v104, (__int64)v106);
  v78 = v77;
  read_file(v77, (__int64)v110, 16);
  v79 = 0;
  v80 = 0;
  v81 = 0;
  v82 = 0;
  if ( state_qword == -1 )
    state_qword = 0;
  v83 = state_qword;
  if ( (unsigned __int64)state_qword <= 0x1629C )
    JUMPOUT(0x14000CA5ALL);
  return sub_140C6847C();
}
```

Analyzing some of the functions, we see that it saves in some ADS streams data regarding the input, its position, state and transitions, so possibly those will be helpful. Also identifying the win function, we can see that it uses our provided password, hashes it and uses it as a key for AES-256-CBC to decrypt the flag.

Looking towards the end, we can see...the gist of the challenge:

```asm
.text:000000014000CA41                 lea     rax, cs:140000000h
.text:000000014000CA48                 mov     rcx, [rsp+59398h+var_660]
.text:000000014000CA50                 mov     ecx, ds:(jpt_14000CA5A - 140000000h)[rax+rcx*4] ; switch 65535 cases
.text:000000014000CA57                 add     rcx, rax
.text:000000014000CA57 main_func       endp
.text:000000014000CA57
.text:000000014000CA5A                 jmp     rcx             ; switch jump
```

It has a big switch with 90780 cases, and given how it used terms as "state" and "transition", this is a finite state machine, which is perfect for symbolic execution via "angr"...

However, after some lots of tries, it seems like "state explosion" is real, and "angr" couldn't handle it. So I tried to move on, trying a simple brute force by exploiting the ADS streams for information, but the side effects such as message boxes and log outs became too unbearable, so that option was out as well.

Given that this is a finite state machine with transitions, one idea to model everything and get an insight into how it works is to create a graph from it. After some fiddling around to making `capstone` work ok and getting all the details of the states correct (all states that use ascii comparisons have blocks like `cmp byte ptr [rsp + offset], ASCII_VAL; jz HANDLE_VAL` -> `mov qword ptr [rsp + other_offset], NEXT_STATE_QWORD`, and all states and in `JMP ERROR_OFFSET; RDTSC`), we get somewhere. 
```asm
.text:000000014000CAC4 sub_14000CAC4   proc near               ; CODE XREF: .text:000000014000CA5A↑j
.text:000000014000CAC4                 rdtsc
.text:000000014000CAC6                 shl     rdx, 20h
.text:000000014000CACA                 or      rax, rdx
.text:000000014000CACD                 mov     [rsp+58D18h], rax
.text:000000014000CAD5
.text:000000014000CAD5 loc_14000CAD5:                          ; CODE XREF: sub_14000CAC4+3E↓j
.text:000000014000CAD5                 rdtsc
.text:000000014000CAD7                 shl     rdx, 20h
.text:000000014000CADB                 or      rax, rdx
.text:000000014000CADE                 mov     [rsp+58D20h], rax
.text:000000014000CAE6                 mov     rax, [rsp+58D18h]
.text:000000014000CAEE                 mov     rcx, [rsp+58D20h]
.text:000000014000CAF6                 sub     rcx, rax
.text:000000014000CAF9                 mov     rax, rcx
.text:000000014000CAFC                 cmp     rax, 12AD1659h
.text:000000014000CB02                 jl      short loc_14000CAD5
.text:000000014000CB04                 movzx   eax, byte ptr [rsp+30h]
.text:000000014000CB09                 mov     [rsp+38h], al
.text:000000014000CB0D                 cmp     byte ptr [rsp+38h], 65h ; 'e'
.text:000000014000CB12                 jz      short loc_14000CB3E
.text:000000014000CB14                 cmp     byte ptr [rsp+38h], 78h ; 'x'
.text:000000014000CB19                 jz      short loc_14000CB1D
.text:000000014000CB1B                 jmp     short loc_14000CB5F
.text:000000014000CB1D ; ---------------------------------------------------------------------------
.text:000000014000CB1D
.text:000000014000CB1D loc_14000CB1D:                          ; CODE XREF: sub_14000CAC4+55↑j
.text:000000014000CB1D                 mov     qword ptr [rsp+58D30h], 1431Dh
.text:000000014000CB29                 mov     rax, [rsp+58AB8h]
.text:000000014000CB31                 inc     rax
.text:000000014000CB34                 mov     [rsp+58AB8h], rax
.text:000000014000CB3C                 jmp     short loc_14000CB79
.text:000000014000CB3E ; ---------------------------------------------------------------------------
.text:000000014000CB3E
.text:000000014000CB3E loc_14000CB3E:                          ; CODE XREF: sub_14000CAC4+4E↑j
.text:000000014000CB3E                 mov     qword ptr [rsp+58D30h], 1431Eh
.text:000000014000CB4A                 mov     rax, [rsp+58AB8h]
.text:000000014000CB52                 inc     rax
.text:000000014000CB55                 mov     [rsp+58AB8h], rax
.text:000000014000CB5D                 jmp     short loc_14000CB79
.text:000000014000CB5F ; ---------------------------------------------------------------------------
.text:000000014000CB5F
.text:000000014000CB5F loc_14000CB5F:                          ; CODE XREF: sub_14000CAC4+57↑j
.text:000000014000CB5F                 xor     r9d, r9d
.text:000000014000CB62                 lea     r8, aAlert_0    ; "Alert"
.text:000000014000CB69                 lea     rdx, aWeAppreciateYo ; "We appreciate your efforts, but due to "...
.text:000000014000CB70                 xor     ecx, ecx
.text:000000014000CB72                 call    cs:MessageBoxA
.text:000000014000CB78                 nop
.text:000000014000CB79
.text:000000014000CB79 loc_14000CB79:                          ; CODE XREF: sub_14000CAC4+78↑j
.text:000000014000CB79                                         ; sub_14000CAC4+99↑j
.text:000000014000CB79                 jmp     loc_140C685EE
.text:000000014000CB79 sub_14000CAC4   endp
.text:000000014000CB79
.text:000000014000CB7E
.text:000000014000CB7E ; =============== S U B R O U T I N E =======================================
.text:000000014000CB7E
.text:000000014000CB7E ; jumptable 000000014000CA5A case 25064
.text:000000014000CB7E
.text:000000014000CB7E ; void __fastcall sub_14000CB7E(__int64, __int64, __int64, __int64, __int64, char)
.text:000000014000CB7E sub_14000CB7E   proc near               ; CODE XREF: .text:000000014000CA5A↑j
.text:000000014000CB7E                 rdtsc
```
Given that our condition for getting to the win function is to reach the 16th position in 16 transitions, it means that each character advances the state exactly one, therefore, there is an acyclical path from the first to the last character. Given how this is a finite state machine and a deterministic one, meaning that it always halts, it allows us to deduce that the graph is acyclical, and therefore a DAG. In `networkx`, we have a function called `dag_longest_path`, which gives us the longest path in a DAG (directed acyclic graph), so I decided to test and see where we get. Putting it all together (dumping the jump table virtual addresses, decompiling them to map the transitions, building the graph and getting its longest path), we get the script below:

```Python
import lief
from capstone import *
import struct
import networkx as nx

JUMP_TABLE_ADDR = 0x140C687B8
NUM_ENTRIES = 0x1629C
BINARY_PATH = "ntfsm.exe"

binary = lief.parse(BINARY_PATH)
base_addr = binary.optional_header.imagebase
data = binary.get_content_from_virtual_address(JUMP_TABLE_ADDR, NUM_ENTRIES * 4)

jump_table = [base_addr + struct.unpack("<I", bytes(data[i:i+4]))[0] for i in range(0, len(data), 4)]
print("did jt")
#print([hex(x) for x in jump_table[:25]])

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

fsm_transitions = {}
for idx, addr in enumerate(jump_table):
    try:
        code = binary.get_content_from_virtual_address(addr, 0x100)
    except:
        continue
    all_ins = list(md.disasm(bytes(code), addr))
    instructions = []

    for k, insn in enumerate(all_ins):
        instructions.append(insn)
        if insn.mnemonic == "jmp" and k < len(all_ins) - 1:
            if all_ins[k + 1].mnemonic == "rdtsc":
                break

    state_map = {}
    #print(instructions)
    for i, insn in enumerate(instructions):
        if insn.mnemonic == "cmp" and "byte ptr [rsp +" in insn.op_str and "], " in insn.op_str:
            try:
                cmp_val = int(insn.op_str.split("], ")[1], 16)
                input_char = chr(cmp_val)
            except:
                continue

            for j in range(i+1, min(i+5, len(instructions))):
                jmp_insn = instructions[j]
                if jmp_insn.mnemonic in ["jz", "je"]:
                    target = jmp_insn.operands[0].imm

                    try:
                        target_code = binary.get_content_from_virtual_address(target, 0x40)
                        target_insns = list(md.disasm(bytes(target_code), target))
                    except:
                        continue

                    for ti in target_insns:
                        if ti.mnemonic == "jmp":
                            break
                        if ti.mnemonic == "mov" and "qword ptr [rsp +" in ti.op_str and "], " in ti.op_str:
                            try:
                                next_state = int(ti.op_str.split("], ")[1], 16)
                                state_map[input_char] = next_state
                                break
                            except:
                                continue
                    break
    if state_map:
        fsm_transitions[idx] = state_map
    else:
        print(f" state {idx} has no transitions - addr {hex(addr)}")
    #break
print("did trans")

G = nx.DiGraph()
for state, transitions in fsm_transitions.items():
    for char, next_state in transitions.items():
        G.add_edge(state, next_state, label=char)
print("did graph")

longest_path = nx.dag_longest_path(G)
password = ""
for i in range(len(longest_path) - 1):
    u, v = longest_path[i], longest_path[i + 1]
    label = G[u][v].get('label', '')
    password += label
print("path:", longest_path)
print("pwd:", password)

```
Running the script gives us the following:
```
path: [0, 1, 5, 11, 25, 53, 114, 234, 468, 930, 1824, 3621, 7221, 14397, 28807, 57775, 90780]
pwd: iqg0nSeCHnOMPm2Q
```
Giving this password to the binary yields the flag.

FLAG: `f1n1t3_st4t3_m4ch1n3s_4r3_fun@flare-on.com`

# 6. Chain of Demands

We are given a PyInstaller binary. Unpacking it using `pyinstxtractor-ng` and putting the resulting `.pyc` in `PyLingual`, we get the Python source for an encrypted chat application (we also get `chat_log.json` and `public.pem`).

```Python
class LCGOracle:
    def __init__(self, multiplier, increment, modulus, initial_seed):
        self.multiplier = multiplier
        self.increment = increment
        self.modulus = modulus
        self.state = initial_seed
        self.contract_bytes = '6080604052348015600e575f5ffd5b506102e28061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063115218341461002d575b5f5ffd5b6100476004803603810190610042919061010c565b61005d565b6040516100549190610192565b60405180910390f35b5f5f848061006e5761006d6101ab565b5b86868061007e5761007d6101ab565b5b8987090890505f5f8411610092575f610095565b60015b60ff16905081816100a69190610205565b858260016100b49190610246565b6100be9190610205565b6100c89190610279565b9250505095945050505050565b5f5ffd5b5f819050919050565b6100eb816100d9565b81146100f5575f5ffd5b50565b5f81359050610106816100e2565b92915050565b5f5f5f5f5f60a08688031215610125576101246100d5565b5b5f610132888289016100f8565b9550506020610143888289016100f8565b9450506040610154888289016100f8565b9350506060610165888289016100f8565b9250506080610176888289016100f8565b9150509295509295909350565b61018c816100d9565b82525050565b5f6020820190506101a55f830184610183565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61020f826100d9565b915061021a836100d9565b9250828202610228816100d9565b9150828204841483151761023f5761023e6101d8565b5b5092915050565b5f610250826100d9565b915061025b836100d9565b9250828203905081811115610273576102726101d8565b5b92915050565b5f610283826100d9565b915061028e836100d9565b92508282019050808211156102a6576102a56101d8565b5b9291505056fea2646970667358221220c7e885c1633ad951a2d8168f80d36858af279d8b5fe2e19cf79eac15ecb9fdd364736f6c634300081e0033'
        self.contract_abi = [{'inputs': [{'internalType': 'uint256', 'name': 'LCG_MULTIPLIER', 'type': 'uint256'}, {'internalType': 'uint256', 'name': 'LCG_INCREMENT', 'type': 'uint256'}, {'internalType': 'uint256', 'name': 'LCG_MODULUS', 'type': 'uint256'}, {'internalType': 'uint256', 'name': '_currentState', 'type': 'uint256'}, {'internalType': 'uint256', 'name': '_counter', 'type': 'uint256'}], 'name': 'nextVal', 'outputs': [{'internalType': 'uint256', 'name': '', 'type': 'uint256'}], 'stateMutability': 'pure', 'type': 'function'}]
        self.deployed_contract = None

    def deploy_lcg_contract(self):
        self.deployed_contract = SmartContracts.deploy_contract(self.contract_bytes, self.contract_abi)

    def get_next(self, counter):
        print(f'\n[+] Calling nextVal() with _currentState={self.state}')
        self.state = self.deployed_contract.functions.nextVal(self.multiplier, self.increment, self.modulus, self.state, counter).call()
        print(f'  _counter = {counter}: Result = {self.state}')
        return self.state

class TripleXOROracle:
    def __init__(self):
        self.contract_bytes = '61030f61004d600b8282823980515f1a6073146041577f4e487b71000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b305f52607381538281f3fe7300000000000000000000000000000000000000003014608060405260043610610034575f3560e01c80636230075614610038575b5f5ffd5b610052600480360381019061004d919061023c565b610068565b60405161005f91906102c0565b60405180910390f35b5f5f845f1b90505f845f1b90505f61007f85610092565b9050818382181893505050509392505050565b5f5f8290506020815111156100ae5780515f525f5191506100b6565b602081015191505b50919050565b5f604051905090565b5f5ffd5b5f5ffd5b5f819050919050565b6100df816100cd565b81146100e9575f5ffd5b50565b5f813590506100fa816100d6565b92915050565b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b61014e82610108565b810181811067ffffffffffffffff8211171561016d5761016c610118565b5b80604052505050565b5f61017f6100bc565b905061018b8282610145565b919050565b5f67ffffffffffffffff8211156101aa576101a9610118565b5b6101b382610108565b9050602081019050919050565b828183375f83830152505050565b5f6101e06101db84610190565b610176565b9050828152602081018484840111156101fc576101fb610104565b5b6102078482856101c0565b509392505050565b5f82601f83011261022357610222610100565b5b81356102338482602086016101ce565b91505092915050565b5f5f5f60608486031215610253576102526100c5565b5b5f610260868287016100ec565b9350506020610271868287016100ec565b925050604084013567ffffffffffffffff811115610292576102916100c9565b5b61029e8682870161020f565b9150509250925092565b5f819050919050565b6102ba816102a8565b82525050565b5f6020820190506102d35f8301846102b1565b9291505056fea26469706673582212203fc7e6cc4bf6a86689f458c2d70c565e7c776de95b401008e58ca499ace9ecb864736f6c634300081e0033'
        self.contract_abi = [{'inputs': [{'internalType': 'uint256', 'name': '_primeFromLcg', 'type': 'uint256'}, {'internalType': 'uint256', 'name': '_conversationTime', 'type': 'uint256'}, {'internalType': 'string', 'name': '_plaintext', 'type': 'string'}], 'name': 'encrypt', 'outputs': [{'internalType': 'bytes32', 'name': '', 'type': 'bytes32'}], 'stateMutability': 'pure', 'type': 'function'}]
        self.deployed_contract = None

    def deploy_triple_xor_contract(self):
        self.deployed_contract = SmartContracts.deploy_contract(self.contract_bytes, self.contract_abi)

    def encrypt(self, prime_from_lcg, conversation_time, plaintext_bytes):
        print(f'\n[+] Calling encrypt() with prime_from_lcg={prime_from_lcg}, time={conversation_time}, plaintext={plaintext_bytes}')
        ciphertext = self.deployed_contract.functions.encrypt(prime_from_lcg, conversation_time, plaintext_bytes).call()
        print(f'  _ciphertext = {ciphertext.hex()}')
        return ciphertext

class ChatLogic:
    def __init__(self):
        self.lcg_oracle = None
        self.xor_oracle = None
        self.rsa_key = None
        self.seed_hash = None
        self.super_safe_mode = False
        self.message_count = 0
        self.conversation_start_time = 0
        self.chat_history = []
        self._initialize_crypto_backend()

    def _get_system_artifact_hash(self):
        artifact = platform.node().encode('utf-8')
        hash_val = hashlib.sha256(artifact).digest()
        seed_hash = int.from_bytes(hash_val, 'little')
        print(f'[SETUP]  - Generated Seed {seed_hash}...')
        return seed_hash

    def _generate_primes_from_hash(self, seed_hash):
        primes = []
        current_hash_byte_length = (seed_hash.bit_length() + 7) // 8
        current_hash = seed_hash.to_bytes(current_hash_byte_length, 'little')
        print('[SETUP] Generating LCG parameters from system artifact...')
        iteration_limit = 10000
        iterations = 0
        while len(primes) < 3 and iterations < iteration_limit:
            current_hash = hashlib.sha256(current_hash).digest()
            candidate = int.from_bytes(current_hash, 'little')
            iterations += 1
            if candidate.bit_length() == 256 and isPrime(candidate):
                primes.append(candidate)
                print(f'[SETUP]  - Found parameter {len(primes)}: {str(candidate)[:20]}...')
        if len(primes) < 3:
            error_msg = '[!] Error: Could not find 3 primes within iteration limit.'
            print('Current Primes: ', primes)
            print(error_msg)
            exit()
        return (primes[0], primes[1], primes[2])

    def _initialize_crypto_backend(self):
        self.seed_hash = self._get_system_artifact_hash()
        m, c, n = self._generate_primes_from_hash(self.seed_hash)
        self.lcg_oracle = LCGOracle(m, c, n, self.seed_hash)
        self.lcg_oracle.deploy_lcg_contract()
        print('[SETUP] LCG Oracle is on-chain...')
        self.xor_oracle = TripleXOROracle()
        self.xor_oracle.deploy_triple_xor_contract()
        print('[SETUP] Triple XOR Oracle is on-chain...')
        print('[SETUP] Crypto backend initialized...')

    def generate_rsa_key_from_lcg(self):
        print('[RSA] Generating RSA key from on-chain LCG primes...')
        lcg_for_rsa = LCGOracle(self.lcg_oracle.multiplier, self.lcg_oracle.increment, self.lcg_oracle.modulus, self.seed_hash)
        lcg_for_rsa.deploy_lcg_contract()
        primes_arr = []
        rsa_msg_count = 0
        iteration_limit = 10000
        iterations = 0
        while len(primes_arr) < 8 and iterations < iteration_limit:
            candidate = lcg_for_rsa.get_next(rsa_msg_count)
            rsa_msg_count += 1
            iterations += 1
            if candidate.bit_length() == 256 and isPrime(candidate):
                primes_arr.append(candidate)
                print(f'[RSA]  - Found 256-bit prime #{len(primes_arr)}')
        print('Primes Array: ', primes_arr)
        if len(primes_arr) < 8:
            error_msg = '[RSA] Error: Could not find 8 primes within iteration limit.'
            print('Current Primes: ', primes_arr)
            print(error_msg)
            return error_msg
        n = 1
        for p_val in primes_arr:
            n *= p_val
        phi = 1
        for p_val in primes_arr:
            phi *= p_val - 1
        e = 65537
        if math.gcd(e, phi)!= 1:
            error_msg = '[RSA] Error: Public exponent e is not coprime with phi(n). Cannot generate key.'
            print(error_msg)
            return error_msg
        self.rsa_key = RSA.construct((n, e))
        try:
            with open('public.pem', 'wb') as f:
                f.write(self.rsa_key.export_key('PEM'))
                print('[RSA] Public key generated and saved to \'public.pem\'')
                return 'Public key generated and saved successfully.'
        except Exception as e:
            print(f'[RSA] Error saving key: {e}')
            return f'Error saving key: {e}'

    def process_message(self, plaintext):
        if self.conversation_start_time == 0:
            self.conversation_start_time = time.time()
        conversation_time = int(time.time() - self.conversation_start_time)
        if self.super_safe_mode and self.rsa_key:
            plaintext_bytes = plaintext.encode('utf-8')
            plaintext_enc = bytes_to_long(plaintext_bytes)
            _enc = pow(plaintext_enc, self.rsa_key.e, self.rsa_key.n)
            ciphertext = _enc.to_bytes(self.rsa_key.n.bit_length(), 'little').rstrip(b'\x00')
            encryption_mode = 'RSA'
            plaintext = '[ENCRYPTED]'
        else:  # inserted
            prime_from_lcg = self.lcg_oracle.get_next(self.message_count)
            ciphertext = self.xor_oracle.encrypt(prime_from_lcg, conversation_time, plaintext)
            encryption_mode = 'LCG-XOR'
        log_entry = {'conversation_time': conversation_time, 'mode': encryption_mode, 'plaintext': plaintext, 'ciphertext': ciphertext.hex()}
        self.chat_history.append(log_entry)
        self.message_count += 1
        self.save_chat_log()
        return (f'[{conversation_time}s] {plaintext}', f'[{conversation_time}s] {ciphertext.hex()}')

    def save_chat_log(self):
        try:
            with open('chat_log.json', 'w') as f:
                json.dump(self.chat_history, f, indent=2)
        except Exception as e:
            print(f'Error saving chat log: {e}')
```

In this app, we can see that it allows for 2 types of encryption, LCG combined with a XOR and RSA. The LCG and XOR operations are made via etheureum contracts, so we decompile ([https://app.dedaub.com/decompile]) the given bytecode just to ensure nothing more is happening other than their names are suggesting.

XOR
```Solidity
function fallback() public payable {
    revert();
}

function 0x62300756(uint256 varg0, uint256 varg1, bytes varg2) public payable {
    require(4 + (msg.data.length - 4) - 4 >= 96);
    require(varg2 <= uint64.max);
    require(4 + varg2 + 31 < 4 + (msg.data.length - 4));
    require(varg2.length <= uint64.max, Panic(65)); // failed memory allocation (too much memory)
    v0 = new bytes[](varg2.length);
    require(!((v0 + ((varg2.length + 31 & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) + 32 + 31 & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) > uint64.max) | (v0 + ((varg2.length + 31 & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) + 32 + 31 & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0) < v0)), Panic(65)); // failed memory allocation (too much memory)
    require(varg2.data + varg2.length <= 4 + (msg.data.length - 4));
    CALLDATACOPY(v0.data, varg2.data, varg2.length);
    v0[varg2.length] = 0;
    if (v0.length <= 32) {
        v1 = v2 = MEM[v0.data];
    }
    return v1 ^ varg0 ^ varg1;
}
```

LCG
```Solidity
function _SafeMul(uint256 varg0, uint256 varg1) private {
    require(!varg0 | (varg1 == varg0 * varg1 / varg0), Panic(17)); // arithmetic overflow or underflow
    return varg0 * varg1;
}

function _SafeSub(uint256 varg0, uint256 varg1) private {
    require(varg0 - varg1 <= varg0, Panic(17)); // arithmetic overflow or underflow
    return varg0 - varg1;
}

function _SafeAdd(uint256 varg0, uint256 varg1) private {
    require(varg0 <= varg0 + varg1, Panic(17)); // arithmetic overflow or underflow
    return varg0 + varg1;
}

function fallback() public payable {
    revert();
}

function 0x11521834(uint256 varg0, uint256 varg1, uint256 varg2, uint256 varg3, uint256 varg4) public payable {
    require(4 + (msg.data.length - 4) - 4 >= 160);
    require(varg2, Panic(18)); // division by zero
    require(varg2, Panic(18)); // division by zero
    if (varg4 > 0) {
        v0 = v1 = 1;
    } else {
        v0 = v2 = 0;
    }
    v3 = _SafeMul(uint8(v0), (varg3 * varg0 % varg2 + varg1) % varg2);
    v4 = _SafeSub(1, uint8(v0));
    v5 = _SafeMul(v4, varg3);
    v6 = _SafeAdd(v5, v3);
    return v6;
}
```

We can see nothing neferious, just that in the XOR operation, the plaintext is interpreted as an integer and has to be 32 bytes. Next, seeing as how the XOR operation is symmetric, we can recover the 7 states (7 LCG-XOR messages in `chat_log.json`), and attempt to recover the internal parameters of the LCG. If we can do that, we can then generate the primes for RSA and easily decrypt the RSA-encrypted message, which likely contain the flag. Search for how to recover LCG parameters from outputs quickly yields this page ([https://security.stackexchange.com/questions/4268/cracking-a-linear-congruential-generator]), which describes how to recover the modulus when all we know are the outputs. Given that we can find the modulus and have quite a few outputs, solving for `a` and `c` is easy. We can use the first 3 states to recover `a` (`state_3 = a * state_2 + c mod m`, `state_2 = a * state_1 + c mod m`, `state_1 = a * state_0 + c mod m` => `diff2 = state_3 - state_2 = a * (state_2 - state_1) mod m` and `diff1 = state_2 - state_1 = a * (state_1 - state_0) mod m` => `diff2 = a * diff1 mod m` => `a = diff1_inv * diff2 mod m`), and once we get it, we can also recover `c` (`state_1 = a * state_0 + c mod m` => `c = state_1 - a * state_0 mod m`).

Putting it all together, we can get the LCG parameters. Advancing it until we find the first 8 primes and then combining them together to from the RSA key should yield the correct one.

```Python
import json
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime
import math

def extract_lcg_states(chat_log):
    lcg_states = []
    for entry in chat_log:
        if entry['mode'] == 'LCG-XOR':
            plaintext = entry['plaintext']
            ciphertext = bytes.fromhex(entry['ciphertext'])
            conversation_time = entry['conversation_time']
            
            # TripleXOR: ciphertext = prime_from_lcg ^ conversation_time ^ plaintext_int_padded_to_32
            plaintext_bytes = plaintext.encode('utf-8')
            plaintext_padded = plaintext_bytes.ljust(32, b'\x00')
            plaintext_int = int.from_bytes(plaintext_padded, 'big')
            ciphertext_int = int.from_bytes(ciphertext, 'big')

            state = ciphertext_int ^ conversation_time ^ plaintext_int
            lcg_states.append(state)
    
    return lcg_states

def recover_lcg_parameters_advanced(states):
    s = [x for x in states]
    multiples = []
    for i in range(len(s) - 3):
        diff1 = s[i+1] - s[i]
        diff2 = s[i+2] - s[i+1]
        diff3 = s[i+3] - s[i+2]
        
        # m divides this expression
        val = abs(diff2 * diff2 - diff1 * diff3)
        if val > 0:
            multiples.append(val)
    if not multiples:
        return None, None, None

    result = multiples[0]
    for val in multiples[1:]:
        result = math.gcd(result, val)

    potential_m = result
    
    # try to remove small factors or sqrt - just as a sanity check
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        while potential_m % p == 0:
            potential_m = potential_m // p
    
    if potential_m.bit_length() >= 500:
        sqrt_val = int(potential_m ** 0.5)
        if sqrt_val * sqrt_val == potential_m:
            potential_m = sqrt_val

    if potential_m.bit_length() == 256 and isPrime(potential_m):
        m = potential_m
        print(f"got m = {hex(m)}")

        # do a and c now
        diff1 = (s[1] - s[0]) % m
        diff2 = (s[2] - s[1]) % m
        
        if diff1 != 0:
            a = (diff2 * pow(diff1, -1, m)) % m
            c = (s[1] - a * s[0]) % m
            
            # sanity checks
            test_vals = []
            for i in range(6):
                expected = s[i+1]
                computed = (a * s[i] + c) % m
                match = (expected == computed)
                test_vals.append(match)
                if not match:
                    print(f"failed params check")
                    break
            
            if all(test_vals):
                print(f"got a = {hex(a)}")
                print(f"got c = {hex(c)}")
                return a, c, m
    
    return None, None, None

def decrypt_rsa_messages(chat_log, public_key, factors):
    phi = 1
    for p in factors:
        phi *= (p - 1)
    n = 1
    for p in factors:
        n *= p
    # sanity check
    if n != public_key.n:
        print("fail check public key")
        return None
    d = pow(65537, -1, phi)
    
    for entry in chat_log:
        if entry['mode'] == 'RSA':
            ciphertext_bytes = bytes.fromhex(entry['ciphertext'])
            ciphertext_int = int.from_bytes(ciphertext_bytes, 'little')
            
            plaintext_int = pow(ciphertext_int, d, public_key.n)
            plaintext_bytes = long_to_bytes(plaintext_int)
            
            try:
                plaintext = plaintext_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
                print(f"decrypted text - {plaintext}")
            except:
                print(f"error - decrypted bytes - {plaintext_bytes.hex()}")

chat_log = json.loads(open("chat_log.json", "r").read())
public_key = RSA.import_key(open("public.pem", "r").read())

lcg_states = extract_lcg_states(chat_log)
a, c, m = recover_lcg_parameters_advanced(lcg_states)
if a and c and m:
    current_state = lcg_states[-1]
    primes_for_rsa = [x for x in lcg_states if isPrime(x)]
    for i in range(10000):
        current_state = (a * current_state + c) % m
        if current_state.bit_length() == 256 and isPrime(current_state):
            primes_for_rsa.append(current_state)
            if len(primes_for_rsa) == 8:
                break

decrypt_rsa_messages(chat_log, public_key, primes_for_rsa)
```

FLAG: `W3b3_i5_Gr8@flare-on.com`

# 7. The Boss Needs Help

A tough challenge, but fun one, learned quite a lot.
So, we are given a binary and a PCAP file. The PCAP contains HTTP requests with some hex-encoded data which seems encrypted. So, starting with the analysis, we are greeted by.. a lot of "function too big to decompile". Increasing the size in the decompiler options only leads big decompilation times or crashes due to big dead code portions, as such:

```C++
      v85 = 0;
      v57 = -1528583749;
      v67 = 907295664;
      v66 = 1693023818;
      v29 = -403727839;
      v83 = -603667323;
      v45 = 1564670371;
      v32[1] = -1143874688;
      v55 = 0;
      v26 = 2079063029;
      v31 = -1791311861 - v32[0];
      v86 = 0;
      v35 = 257522091;
      v65 = 0;
      v32[0] = -16778247;
      v62 = -11397;
      v40 = -1;
      v38 = 0;
      v41 = 1347101064;
      v33 = -23737543;
      v51 = -1;
      v39[0] = -16787280;
      if ( v31 < 1744794077 )
        v26 = v53 + 2080373751;
      v49 = v34 % 53011;
      v59 &= 0xFB61u;
      v48 = 0;
      v30 = v44 | 0x8B7F4070;
      ++v43;
      v58 >>= 31;
      v61 = 402267128;
      v55 = -193261445;
      v39[0] = v83 % 61336;
      if ( v39[1] < -782683929 >> v43 )
        v25 = 998776720;
      v42 &= v45;
      v24 = v74 >> 31;
      v37 = 0;
      v46 = v26 * v43;
      v49 ^= v32[1];
      v28 = -362819354 * v79;
      v48 += v88;
      v74 *= 34834;
      v56 = v88 | 0x6577;
      v40 = 1202651140;
      if ( -362819354 * v79 == v34 )
        ++v62;
      if ( v69 != v25 )
        ++v39[0];
      v27 = v26 | 0xDE3D;
      v69 = v28 & 0x9AD7;
      if ( v31 == v58 )
        ++v30;
      if ( v58 >= -620962865 )
        ++v39[0];
      if ( v50 != v39[0] )
        --v53;
      v52 += v80;
      v71 %= 887157008;
      if ( v27 < v82 )
        ++v61;
      v49 /= 3917;
      v44 = 0;
      v64 = -12666262;
      v37 = 512;
      if ( v24 <= 0 )
        v29 = -403727838;
      dword_14047A3B4 = (v49 + v39[0] + v89)
                      & (v66 + v39[1])
                      & 0xB14197F9
                      & v64
                      & 0x9F298650
                      ^ (v62 - 30796 + 10312)
                      & (v33 + v55)
                      & v32[1]
                      | (v48 - v32[0] - 973091072 + 174548579)
                      & (-295962076 - (v74 + 9678) + 1268661469)
                      & 0x8100572F
                      & v56
                      & 0x6DBB4B64
                      ^ v25
                      & v73
                      | (v47 - v30 - v83 - v46 - 1941496678)
                      ^ (-107334730 - v57 - v58)
                      ^ 0x4BF97DEF
                      ^ (-16811296 * v66 + 1810)
                      | v82 & 0xAEA13199 ^ ((v36 >> 31) - v78 + 12692213 + 9555 * v34) ^ v81 ^ v77 ^ v87 ^ v80
                      | ((-782683929 >> v43) + v76 + 49720374) ^ (v31 - v79 + 8945561) ^ (v41 + 1651) ^ 0xB5AC04CD
                      | (v85 + v45)
                      & 0x2CFB0FEB
                      & v72
                      & 0x47AF0004
                      & (v32[1] / -2130705919)
                      ^ v59
                      & 0xA575AB82
                      ^ (v44 + 1791302203)
                      | (v60 + 1) & (1557782271 - v38) & v65 ^ (-2046916866 - v24) & v75 ^ 0x200
                      | (v63 + v38 - 1954594704) & v37 ^ (v29 - v43) & v34 ^ 0xFC776BBD
                      | (v74 + v86) ^ v84 & v62 ^ v51 ^ 0x200
                      | (v42 - v68) & v61 & v36
                      | (v67 - v52) ^ v28
                      | (v27 - v70) ^ v69
                      | (v53 - 1 + v40)
                      | v88 & v54
                      | v71 & 0xA7BEB1D9
                      | v50 & v35
                      | (-1954594704 % v57 - 1);
```

Skipping ahead couple days where I tried to create an IDAPython script for deobfuscating by matching assembly patterns for useless assignments and operations, but that didn't work. Eventually, the scripts were abandoned, and I began searching for other variants of deobfuscation. I was told of another thing (thanks to my colleague Milan), where IDA itself would deobfuscate most of them just by patching 3 constants to 0 and marking them as `const int` (the 3 dwords at `14047A3AC`). This worked wonders and for the first time, I was able to see the `main` function, and thus began the painstaking process of reversing the binary.

Knowing that the binary does network communication, I started by XREFing `connect`, and eventually identified several functions that were building http headers, preparing the request in sorts. Going XREF by XREF, I eventually ended up in a quite big function, which is being called from main, so I decided to stop there and properly analyze what it is doing:

```C++
__int64 __fastcall talk_to_c2(__int64 **a1, __int64 a2)
{
  strcpy(v2241, "*jdO!\r");
  dword_14047A3B4 = -1;
  Time = time64(Time: 0);
  v2241[7] = 0;
  dword_14047A3B4 = 0;
  gmtime64_s(Tm: &Tm, Time: &Time);
  dword_14047A3AC = -1;
  memset(buf: &v1522[7], value: 0, count: sizeof(_BYTE));
  v2 = sub_14012C040();
  v3 = sub_14027EFB0(v2);
  strftime(Buffer: Buffer, SizeInBytes: 3u, Format: v3, Tm: &Tm);
  dword_14047A3B4 = -1;
  std::string::string(&v4105, Buffer);
  dword_14047A3B4 = -1;
  memset_zero(v4104, 0x18u);
  v4001 = sub_140037090(a2, v4088);
  v4003 = v4001;
  v4002 = sub_140037060(a2, v4085);
  v4004 = v4002;
  sha256_xor_pair(out32: v4104, s1: v4002, extra: v4003, s2: &v4105);
  `std::locale::global'::`1'::dtor$2(v4085);
  `std::locale::global'::`1'::dtor$2(v4088);
  dword_14047A3B4 = -1;
  *&aesCbcIV = 0x706050403020100LL;
  *(&aesCbcIV + 1) = 0xF0E0D0C0B0A0908LL;
  dword_14047A3AC = -1;
  sub_1400373D0(a2, v4102);
  dword_14047A3AC = -1;
  sub_1402B40E0(v4102, v4106, -1, 32, 0, 0);
  --v127;
  v170 = v128 & 0x909A;
  v960 /= 38224;
  v865 += 64559;
  --v416;
  v1077 ^= 0x9DADu;
  v1080 = v696 + 38172;
  v127 |= v692;
  v3281 = v1070 ^ v857 & v1663 & v1380;
  v3280 = (v1381 - v858) ^ v1382;
  v3279 = v1997 ^ v1383 & v1071;
  v3278 = v2311;
  v3277 = v2494 ^ v1998 & v1072 & (v859 - v1073) & v2495 ^ (v1384 + v2312 - v1664) ^ v1665;
  v3276 = v1666;
  v3275 = v860;
  v3274 = v1667;
  v3273 = v861 + v691 - v1385;
  v3272 = v1999 & (v2000 - v2496 - v2706) ^ (v2313 + v2707 - v862) ^ v2314;
  v3271 = v2315 + v2497;
  v3270 = v2632 ^ v1074 & (v2001 - v2498) ^ v1075 & (v863 - v1076 - v2002);
  v3269 = (v320 + v1668 - v1386) ^ v2003 & v554 ^ v414 & (v864 + v1077);
  v3268 = v2004 & v2316 & v2317;
  v3267 = v555;
  v3266 = (v2318 + v1387) ^ (v692 + v865) ^ v1388;
  v3265 = v2319;
  v3264 = (v2005 - v2499) & v415;
  v3263 = (v1389 + v2320 - v1078) ^ v170 ^ v2633 ^ v1079;
  v3262 = (v1390 + v2006) ^ (v696 + 38172 + v1081);
  dword_14047A3AC = 0;
  dword_14047A3B0 = 1096810496;
  memset_zero(v4099, 0x18u);
  sub_140076E40(v4099, v4106);
  dword_14047A3B4 = -1;
  aesCbcKey = mov_rax_rcx(v4104);
  aes256_init_ctx(aesCtxOut: &aesCbcCtx, KeyVect: aesCbcKey, IVVect: &aesCbcIV);
  dword_14047A3AC = -1;
  aesCbcBufLen = mov_and_sub_rax_rcx(v4099);
  aesCbcBuf = mov_rax_rcx(v4099);
  aes256cbc_encrypt(ctx: &aesCbcCtx, buf: aesCbcBuf, len: aesCbcBufLen);
  memset(buf: v1523, value: 0, count: 1u);
  v6 = sub_14012C0A0(v1523);
  v7 = sub_14027D0F0(v6);
  v4006 = std::string::string(v4092, v7);
  v4007 = v4006;
  sub_140431C60(v4067, v4006);
  memset(buf: &v1506, value: 0, count: sizeof(v1506));
  v8 = sub_14012C100(&v1506);
  v9 = sub_14027B230(v8);
  v4008 = std::string::string(v4091, v9);
  v4009 = v4008;
  sub_140431C60(v4068, v4008);
  qmemcpy(dst: v4065, src: unknown_libname_29(v4081, v4067, v4069), count: sizeof(v4065));
  sub_140279330(v4069, v4065);
  memset(buf: &v1507, value: 0, count: sizeof(v1507));
  v10 = sub_14012C160(&v1507);
  v11 = sub_140279370(v10);
  v4010 = std::string::string(v4090, v11);
  v4011 = v4010;
  sub_140431C60(v4071, v4010);
  v4012 = mov_and_sub_rax_rcx(v4099);
  v12 = mov_rax_rcx(v4099);
  v3999 = format_hex(v4089, v12, v4012);
  v4014 = v3999;
  sub_140431C60(v4072, v3999);
  qmemcpy(dst: v4059, src: unknown_libname_29(v4082, v4071, &v4073), count: sizeof(v4059));
  sub_140279330(v4070, v4059);
  qmemcpy(dst: v4066, src: unknown_libname_29(v4083, v4069, v4071), count: sizeof(v4066));
  LOBYTE(v13) = 2;
  LOBYTE(v14) = 1;
  sub_1402B4740(v4101, v4066, v14, v13);
  `eh vector destructor iterator'(v4069, 0x18u, 2u, sub_14012C680);
  `eh vector destructor iterator'(v4071, 0x18u, 2u, sub_14012C680);
  `std::locale::global'::`1'::dtor$2(v4089);
  `std::locale::global'::`1'::dtor$2(v4090);
  `eh vector destructor iterator'(v4067, 0x18u, 2u, sub_14012C680);
  `std::locale::global'::`1'::dtor$2(v4091);
  `std::locale::global'::`1'::dtor$2(v4092);
  --v136;
  v185 = v137 & 0x909A;
  v1149 /= 38224;
  v910 += 64559;
  --v434;
  v1140 ^= 0x9DADu;
  v1143 = v727 + 38172;
  v136 |= v723;
  v3485 = v1133 ^ v902 & v1707 & v1438;
  v3484 = (v1439 - v903) ^ v1440;
  v3483 = v2053 ^ v1441 & v1134;
  v3482 = v2354;
  v3481 = v2517 ^ v2054 & v1135 & (v904 - v1136) & v2518 ^ (v1442 + v2355 - v1708) ^ v1709;
  v3480 = v1710;
  v3479 = v905;
  v3478 = v1711;
  v3477 = v906 + v722 - v1443;
  v3476 = v2055 & (v2056 - v2519 - v2712) ^ (v2356 + v2713 - v907) ^ v2357;
  v3475 = v2358 + v2520;
  v3474 = v2644 ^ v1137 & (v2057 - v2521) ^ v1138 & (v908 - v1139 - v2058);
  v3473 = (v333 + v1712 - v1444) ^ v2059 & v574 ^ v432 & (v909 + v1140);
  v3472 = v2060 & v2359 & v2360;
  v3471 = v575;
  v3470 = (v2361 + v1445) ^ (v723 + v910) ^ v1446;
  v3469 = v2362;
  v3468 = (v2061 - v2522) & v433;
  v3467 = (v1447 + v2363 - v1141) ^ v185 ^ v2645 ^ v1142;
  v3466 = (v1448 + v2062) ^ (v727 + 38172 + v1144);
  dword_14047A3AC = v3485
                  | v3484
                  | v3483
                  | v2354
                  | v3481
                  | v1710
                  | v905
                  | v1711
                  | v3477
                  | v3476
                  | (v2358 + v2520)
                  | v3474
                  | v3473
                  | v3472
                  | v575
                  | v3470
                  | v2362
                  | v3468
                  | v3467
                  | v3466
                  | v911 & v724 ^ v912 & v1713 ^ v913 ^ v50
                  | v725 & v1145 ^ (v1146 - v1714)
                  | v914 & v2063
                  | v1147 ^ v915 ^ v1148 ^ v1449 ^ v916 & (v1715 - v917) ^ v1149
                  | v260 & (v136 + v726)
                  | v334
                  | v61 ^ v1150 & v434 & (v137 + v335 - v576)
                  | v1716 ^ v1151 ^ v2064 & v1450
                  | (v186 + v918) ^ v1152 ^ v1717 & v435 ^ v577 & (v187 + v727)
                  | v578
                  | v2065;
  memset_zero(v4108, 0x50u);
  v4015 = v4095;
  memset(buf: &v1508, value: 0, count: sizeof(v1508));
  memset(buf: &v1509, value: 0, count: sizeof(v1509));
  v4016 = sub_1402B3BE0(v4095);
  v4020 = v4016;
  v15 = sub_14012C220(&v1508);
  v16 = sub_1402755B0(v15);
  v4017 = std::string::string(v4076, v16);
  v4021 = v4017;
  v4018 = sub_1402B40E0(v4101, v4087, -1, 32, 0, 0);
  v4022 = v4018;
  v17 = sub_14012C1C0(&v1509);
  v18 = sub_140277470(v17);
  v4019 = std::string::string(v4075, v18);
  v4023 = v4019;
  sub_14000D820(a1, v4108, v4019, v4022, v4021, v4020);
  `std::locale::global'::`1'::dtor$2(v4075);
  `std::locale::global'::`1'::dtor$2(v4087);
  `std::locale::global'::`1'::dtor$2(v4076);
  if ( !Concurrency::details::_ContextCallback::_HasCapturedContext(this: v4108) || *(mov_rax_rcx(v4108) + 32) != 200 )
  {
    v2398[68] = -10195397;
    v2398[67] = -1721991181;
    v2398[62] = 1172244338;
    v2398[61] = -1375835074;
    v2398[60] = 1145182272;
    v2398[59] = -1643203827;
    v2398[64] = 142485457;
    v2398[66] = -14907;
    v2398[63] = 102871;
    v2398[58] = 22706870;
    v2398[65] = 47095;
    dword_14047A3AC = -1;
    memset(buf: &v1520, value: 0, count: sizeof(v1520));
    v22 = sub_14012C4F0(&v1520);
    v23 = sub_140269D30(v22);
    v4053 = std::string::string(v4086, v23);
    v4054 = v4053;
    v24 = sub_140001F70(v4108);
    sub_140050E60(v4054, v24);
  }
  dword_14047A3B4 = -1;
  v4024 = v4096;
  v4025 = sub_1402B3BE0(v4096);
  v4013 = v4025;
  v4026 = mov_rax_rcx(v4108);
  v4060 = json_parse_into(jsonDomOut: &v4100.size_or_meta, in: (v4026 + 200), ctx: v4013, allow_comments: 1u, allow_trailing: 0);
  memset(buf: &v1510, value: 0, count: sizeof(v1510));
  v4028 = sub_14012C2B0(&v1510);
  v4029 = sub_1402736F0(v4028);
  v4030 = std::string::string(v4077, v4029);
  v4031 = v4030;
  v1511 = json_object_contains(jsonDom: &v4100.size_or_meta, key: v4030);
  v1512 = v1511;
  `std::locale::global'::`1'::dtor$2(v4077);
  if ( !v1512 )
  {
LABEL_23:
    sub_14012C680(&v4100.size_or_meta);
    v2217 = v769 ^ v276;
    v3948 = v1228;
    v1228 <<= v276;
    v3949 = v469;
    v469 <<= v274;
    v1217 *= 43143;
    v77 ^= v1226;
    --v616;
    v1224 = v615 + (v769 ^ v276);
    if ( v468 != v616 )
      ++v1861;
    if ( v1859 != v616 )
      ++v1216;
    v1864 = v106 + v964;
    v106 &= v465;
    ++v274;
    v465 = 26576 * v2399;
    v234 = v202 & v617;
    v3950 = v272;
    v759 = v272 >> v2402;
    v202 = v1235 ^ v612;
    ++v769;
    v1869 = v611 >> 13;
    if ( v469 < v275 )
      ++v759;
    v3951 = v465;
    v465 <<= v1869;
    v3952 = v66;
    v3953 = v2404;
    v766 /= v2404;
    v765 >>= 22;
    v613 = 16 * (v466 ^ v1234);
    v1230 -= v1860;
    v66 = v962 ^ 0x3367;
    if ( v360 <= v1217 )
      ++v103;
    if ( v1228 == v202 )
      ++v609;
    if ( v202 >= v470 )
      ++v768;
    v1229 = 64864 * v617;
    v961 = v201 + 24689;
    ++v272;
    if ( v1216 != v360 )
      --v1221;
    if ( v759 >= v470 )
      --v1237;
    ++v1223;
    v1222 = v765 ^ 0xB4D8;
    v965 &= v963;
    v1866 = v609 + v617;
    v1228 &= v1867;
    v202 = v1236 * v362;
    v3954 = v468;
    v2586 = v468 << v2680;
    v3955 = v1862;
    v1226 = v1229 % v1862;
    v3956 = v769;
    v769 <<= v1220;
    --v1232;
    ++v2679;
    v471 *= 4909;
    v961 *= 3378;
    v3957 = v201;
    v1867 /= v201;
    if ( v274 != v1867 )
      --v273;
    if ( v1224 >= v2737 )
      ++v1858;
    v610 ^= 0x4689u;
    v1237 |= 0x3A3Cu;
    v1222 = v104 * v274;
    if ( v759 == v2586 )
      --v768;
    v608 *= 50191;
    v612 = v277 << 29;
    v1227 = v609 ^ v2214;
    v961 += 4072;
    if ( v1224 )
    {
      v3958 = v1224;
      v2215 = v1217 / v1224;
    }
    v3959 = v609;
    v2213 = v609 >> v272;
    v3960 = v201;
    v275 = v1219 / v201;
    v2219 = v272 * v2401;
    v467 &= 0x1A4Bu;
    if ( v106 )
    {
      v3961 = v106;
      v1868 %= v106;
    }
    v201 = v617 - v1221;
    ++v615;
    --v146;
    if ( v274 == v468 )
      --v1237;
    if ( v1221 < v1862 )
      ++v1236;
    v203 += 25729;
    v3962 = v2587;
    v1216 = v1860 / v2587;
    v1233 = v964 ^ v2213;
    v1234 = v1235 - 53954;
    if ( v2681 != v1866 )
      --v103;
    if ( v146 <= v2213 )
      ++v146;
    v276 += 62425;
    if ( v274 < v965 )
      --v616;
    v104 &= 0x10E7u;
    v3963 = v275;
    v611 = v275 >> v273;
    v465 ^= 0xFAE2u;
    v759 *= 20094;
    v1864 <<= 10;
    if ( v276 > v272 )
      ++v361;
    if ( v1223 )
    {
      v3964 = v1223;
      v2404 = v2585 % v1223;
    }
    v2216 += 55901;
    v1224 *= 4;
    if ( v466 <= v1221 )
      --v201;
    v1231 <<= 26;
    v3965 = v2213;
    v2213 <<= v962;
    if ( v2400 >= v104 )
      --v467;
    v1216 |= v1230;
    if ( v103 )
    {
      v3966 = v103;
      v1869 = v1865 % v103;
    }
    v2409 = v1220 / 38356;
    v276 = v234 + 17870;
    v3967 = v2218;
    v1229 = v1225 % v2218;
    if ( v77 > v2214 )
      --v609;
    v359 |= v1225;
    v146 = v470 | 0xBC62;
    if ( v616 > v273 )
      --v272;
    v3968 = v2589;
    v277 %= v2589;
    v3969 = v612;
    v2585 = v612 >> v769;
    if ( v1233 >= v1223 )
      ++v1233;
    if ( v466 > v1226 )
      ++v611;
    v359 = v103 >> 3;
    ++v361;
    v3970 = v614;
    v1865 /= v614;
    v3971 = v1220;
    v202 = v1220 >> v2215;
    v103 = v961 ^ v2677;
    v203 = v201 >> 25;
    v3972 = v273;
    v1236 = v273 << v1866;
    if ( v2407 == v104 )
      --v1218;
    if ( v77 > v359 )
      --v466;
    v468 &= v611;
    if ( v765 != v272 )
      ++v1235;
    v103 ^= v1860;
    v1218 ^= v1219;
    v202 *= v2218;
    if ( v471 )
    {
      v3973 = v471;
      v106 /= v471;
    }
    v78 |= v274;
    v1505 = 17714 * v616;
    v1227 %= 1705;
    v3974 = v1860;
    v275 %= v1860;
    v767 &= 0x6C48u;
    if ( v617 < v2216 )
      ++v766;
    v2407 = v272 | 0xEEA1;
    if ( v759 <= v2217 )
      ++v104;
    if ( v766 >= v1232 )
      ++v274;
    if ( v962 >= v2216 )
      ++v203;
    if ( v1505 )
    {
      v3975 = v1505;
      v77 %= v1505;
    }
    if ( v1224 >= v610 )
      ++v360;
    v277 &= v765;
    v1229 = v1220 * v609;
    if ( v466 != v1505 )
      ++v273;
    v2591 *= 6415;
    v467 = v1221 << 21;
    v1229 /= 57989;
    v466 = v1216 % 54149;
    if ( v2678 >= v106 )
      --v1225;
    if ( v273 != v465 )
      --v611;
    if ( v613 )
    {
      v3976 = v613;
      v468 /= v613;
    }
    if ( v1223 > v274 )
      --v964;
    --v2214;
    v964 &= v465;
    if ( v1868 > v1219 )
      ++v609;
    v1863 = v2682 + v2405;
    if ( v78 )
    {
      v3977 = v78;
      v103 = v1226 % v78;
    }
    v3978 = v2400;
    v272 = v2400 << v273;
    v360 *= v1229;
    v3979 = v2215;
    v1858 = v2215 << v361;
    if ( v106 != v275 )
      ++v469;
    v467 |= v2217;
    v201 = v1868 - 47773;
    v106 /= 52053;
    v1222 &= 0x65DDu;
    v465 = v274 & 0x971E;
    if ( v202 )
    {
      v3980 = v202;
      v469 %= v202;
    }
    v1225 -= 62415;
    v361 &= v1222;
    ++v1236;
    v3981 = v2218;
    v2218 <<= v1235;
    v1222 -= 23027;
    v3982 = v767;
    v767 <<= v468;
    v1865 /= 22049;
    v615 /= 25760;
    v2590 = v2586 & v360;
    if ( v961 <= v359 )
      ++v2220;
    v1219 = v466 - 57554;
    v359 = v467 | 0xDF45;
    if ( v2403 >= v201 )
      --v2400;
    v1238 = v104 * v202;
    if ( v1221 != v613 )
      ++v2215;
    if ( v767 >= v1219 )
      --v962;
    v1505 -= v468;
    v471 = v610 | v2584;
    if ( v1231 != v362 )
      --v276;
    v1219 ^= 0xCECu;
    if ( v360 > v470 )
      ++v276;
    if ( v2410 > v466 )
      --v612;
    if ( v2216 <= v1217 )
      ++v470;
    if ( v965 )
    {
      v3983 = v965;
      v202 = v1226 % v965;
    }
    if ( v2402 < v359 )
      ++v2408;
    if ( v1859 != v766 )
      ++v203;
    v470 += v1222;
    if ( v2406 <= v616 )
      --v1863;
    v78 = v2402 - v617;
    ++v362;
    v3984 = v273;
    v963 = v273 << v1220;
    if ( v1234 <= v471 )
      ++v1218;
    v963 = v470 | v2402;
    if ( v234 >= v466 )
      --v765;
    if ( v1227 )
    {
      v3985 = v1227;
      v201 = v203 % v1227;
    }
    if ( v203 != v2409 )
      ++v1220;
    if ( v1864 > v2403 )
      --v203;
    v1869 = v2680 | v471;
    if ( v612 <= v2406 )
      ++v104;
    if ( v1231 >= v66 )
      --v201;
    v360 = v2217 & 0xDC71;
    v146 &= v1221;
    v1218 = v608 * v1505;
    if ( v2399 < v467 )
      --v1238;
    v468 -= v1216;
    v2585 = v104 << 18;
    v1231 = v613 / 26155;
    v612 = v361 + 11993;
    v277 = 82 * v2591;
    v3986 = v1865;
    v1217 = v1865 << v146;
    if ( v1238 == v359 )
      ++v1858;
    v768 ^= 0x16DDu;
    if ( v469 == v1220 )
      ++v2588;
    if ( v465 < v78 )
      --v1861;
    v272 += 30663;
    v769 = v616 + 125;
    if ( v1238 != v466 )
      ++v1217;
    v1862 = v2399 + v2408;
    v617 %= 16506;
    v1226 >>= 23;
    if ( v203 <= v767 )
      ++v467;
    if ( v146 )
    {
      v3987 = v146;
      v361 = v465 % v146;
    }
    v2677 = v471 + 7529;
    v1858 = v1866 << 12;
    v3998 = v2584
          & (v759 + v2213 - v2399 - v2585 - (v471 + 7529) - v1216)
          ^ (v466 + v2586 - v465 - v2400)
          & v617
          & v1217
          ^ v2401;
    v3997 = v1866 << 12;
    v3996 = v2678 & (v1505 + v359);
    v3995 = v1225 - v1224;
    v3994 = v1226 & (v2679 + v201) ^ v2680 & v1227 ^ (v2587 + v1859) ^ v1218 ^ (v2402 - v360);
    v3993 = (v2588 + v1228 - v2403) & v1219 ^ v1220 ^ v1860 ^ v272 & (v1861 + v106) & v1862 & v2404;
    v3992 = (v2405 - v1863) & v2214 ^ (v2406 + v467 - v2681) ^ v2737;
    v3991 = v1864 ^ (v765 + v104 - v468) & v766 & v1229;
    v3990 = v2407;
    v3989 = v608;
    v3988 = v609 & (v610 - v2215) & (v202 + v2408) & (v2682 + v2216);
    dword_14047A3AC = v3998
                    | (v1866 << 12)
                    | v3996
                    | (v1225 - v1224)
                    | v3994
                    | v3993
                    | v3992
                    | v3991
                    | v2407
                    | v608
                    | v3988
                    | v273
                    | (v274 - v1221) ^ v1222 ^ (v146 + v2217) ^ (v2589 - v1223 - v767) & (v2590 - v611)
                    | (v1865 - v961 - v1230) ^ (v1231 + v768) & v962 ^ (v2409 + v1232)
                    | v1233 ^ v2218 ^ v963 & (v612 + v2219 - v964 - v103)
                    | v1866 ^ v1234 ^ (v469 - v1235)
                    | (v613 + v361 + v1867 + v2410)
                    | v470
                    | v2591
                    & (v2220 + v1236 + v1237)
                    ^ (v1238 + v275)
                    ^ (v965 + v614 - v1868)
                    ^ (v276 + v1869)
                    ^ (v615 + v203)
                    | v362
                    | v77
                    | (v471 + v78)
                    | v769 ^ v234
                    | (v66 + v616) ^ v277;
    memset(buf: &v1521, value: 0, count: sizeof(v1521));
    memset(buf: v1522, value: 0, count: 1u);
    v25 = sub_14012C5B0(&v1521);
    v26 = sub_140265FB0(v25);
    v4055 = std::string::string(v4084, v26);
    v4000 = v4055;
    v27 = sub_14012C550(v1522);
    v28 = sub_140267E70(v27);
    v4056 = std::string::string(v4080, v28);
    v4027 = v4056;
    sub_140054C50(v4056, v4000);
  }
  dword_14047A3AC = -1;
  memset_zero(&v4100.scratch[1], 0x18u);
  v4034 = &v4093;
  memset(buf: &v1513, value: 0, count: sizeof(v1513));
  v4032 = sub_14012C310(&v1513);
  v4033 = sub_140271830(v4032);
  v4035 = std::string::string(v4034, v4033);
  v4036 = json_object_ref(jsonDom: &v4100.size_or_meta, key: v4035);
  v4061 = str_assign_9(v4036, v4074);
  v4062 = sub_140066A60(&v4100.scratch[1], v4074);
  `std::locale::global'::`1'::dtor$2(v4074);
  --v93;
  v1166 = v733 + 38172;
  v3638 = v1156 ^ v920 & v1741 & v1457;
  v3637 = (v1458 - v921) ^ v1459;
  v3636 = v2094 ^ v1460 & v1157;
  v3635 = v2387;
  v3634 = v2529 ^ v2095 & v1158 & (v922 - v1159) & v2530 ^ (v1461 + v2388 - v1742) ^ v1743;
  v3633 = v1744;
  v3632 = v923;
  v3631 = v1745;
  v3630 = v924 + v728 - v1462;
  v3629 = v2096 & (v2097 - v2531 - v2718) ^ (v2389 + v2719 - v925) ^ v2390;
  v3628 = v2391 + v2532;
  v3627 = v2651 ^ v1160 & (v2098 - v2533) ^ v1161 & (v926 - v1162 - v2099);
  v3626 = (v336 + v1746 - v1463) ^ v2100 & v579 ^ v436 & (v927 + (v1163 ^ 0x9DAD));
  v3625 = v2101 & v2392 & v2393;
  v3624 = v580;
  v3623 = (v2394 + v1464) ^ (v729 + v928 + 64559) ^ v1465;
  v3622 = v2395;
  v3621 = (v2102 - v2534) & v437;
  v3620 = (v1466 + v2396 - v1164) ^ v94 & 0x909A ^ v2652 ^ v1165;
  v3619 = (v1467 + v2103) ^ (v733 + 38172 + v1167);
  dword_14047A3AC = v3638
                  | v3637
                  | v3636
                  | v2387
                  | v3634
                  | v1744
                  | v923
                  | v1745
                  | v3630
                  | v3629
                  | (v2391 + v2532)
                  | v3627
                  | v3626
                  | v3625
                  | v580
                  | v3623
                  | v2395
                  | v3621
                  | v3620
                  | v3619
                  | v929 & v730 ^ v930 & v1747 ^ v931 ^ v47
                  | v731 & v1168 ^ (v1169 - v1748)
                  | v932 & v2104
                  | v1170 ^ v933 ^ v1171 ^ v1468 ^ v934 & (v1749 - v935) ^ (v1172 / 38224)
                  | v261 & ((v729 | v93) + v732)
                  | v337
                  | v69 ^ v1173 & (v438 - 1) & (v94 + v338 - v581)
                  | v1750 ^ v1174 ^ v2105 & v1469
                  | (v138 + v936) ^ v1175 ^ v1751 & v439 ^ v582 & (v139 + v733)
                  | v583
                  | v2106;
  v2398[3] = 941530137;
  v2398[2] = -1205310650;
  v2398[5] = -168792;
  HIBYTE(v2398[1]) = 0;
  v2398[4] = -26606;
  strcpy(v2398, "\vF^&-K");
  v3677 = (v2398[0] - 1245350119) ^ 0x91A8C024;
  v3675 = v2398[1] ^ 0x200200;
  dword_14047A3B0 = -1;
  aesKeyForEnc = mov_rax_rcx(v4104);
  aes256_init_ctx(aesCtxOut: &aesCtxForEnc, KeyVect: aesKeyForEnc, FeedbackVect: &aesCbcIV);
  v2398[10] = -555057381;
  v2398[9] = -1801760139;
  v2398[7] = -721173089;
  v2398[6] = 3361;
  v2398[8] = -300548291;
  dword_14047A3B4 = 0;
  aesBufLenFeedback = mov_and_sub_rax_rcx(&v4100.scratch[1]);
  aesBufToEncFeedback = mov_rax_rcx(&v4100.scratch[1]);
  aes256weird_cbc_encrypt(aesContext: &aesCtxForEnc, buf: aesBufToEncFeedback, len: aesBufLenFeedback);
  v2398[21] = -10195397;
  v2398[20] = -1721991181;
  v2398[15] = 1172244338;
  v2398[14] = -1375835074;
  v2398[13] = 1145182272;
  v2398[12] = -1643203827;
  v2398[17] = 142485457;
  v2398[19] = -14907;
  v2398[16] = 102871;
  v2398[11] = 22706870;
  v2398[18] = 47095;
  dword_14047A3AC = -1;
  dword_14047A3B0 = 3224512;
  v4063 = sub_140076F60(&v4107, &v4100.scratch[1]);
  v2398[32] = 2100658529;
  v2398[29] = -1484672706;
  v2398[27] = 8421598;
  v2398[22] = -2128091370;
  v2398[31] = -2776328;
  v2398[25] = -787527286;
  v2398[28] = 536900430;
  v2398[24] = -665159424;
  v2398[30] = -145811966;
  v2398[26] = -916856832;
  v2398[23] = 616176;
  dword_14047A3B4 = 0;
  v4038 = v4097;
  v4039 = sub_1402B3BE0(v4097);
  v4064 = json_parse_into(jsonDomOut: &v4100, in: &v4107, ctx: v4039, allow_comments: 1u, allow_trailing: 0);
  memset(buf: &v1514, value: 0, count: sizeof(v1514));
  v4040 = sub_14012C370(&v1514);
  v4041 = sub_14026F970(v4040);
  v4042 = std::string::string(v4079, v4041);
  v4043 = v4042;
  v190 |= 1u;
  if ( !json_object_contains(jsonDom: &v4100, key: v4042) )
    goto LABEL_13;
  memset(buf: &v1516, value: 0, count: sizeof(v1516));
  v4044 = sub_14012C430(&v1516);
  v4045 = sub_14026DAB0(v4044);
  v4046 = std::string::string(v4078, v4045);
  v4047 = v4046;
  v4058 = sub_140431BD0(v4057, v4046);
  v190 |= 6u;
  v4050 = &v4094;
  memset(buf: &v1517, value: 0, count: sizeof(v1517));
  v4048 = sub_14012C3D0(&v1517);
  v4049 = sub_14026F970(v4048);
  v4051 = std::string::string(v4050, v4049);
  v4052 = json_object_ref(jsonDom: &v4100, key: v4051);
  if ( sub_1402B3BF0(v4052, v4057) )
  else
LABEL_13:
  v1518 = v2725;
  if ( (v190 & 4) != 0 )
  {
    v190 &= ~4u;
    sub_14012C680(v4057);
  }
  if ( (v190 & 2) != 0 )
  {
    v190 &= ~2u;
    `std::locale::global'::`1'::dtor$2(v4078);
  }
  if ( (v190 & 1) != 0 )
  {
    v190 &= ~1u;
    `std::locale::global'::`1'::dtor$2(v4079);
  }
  if ( !v1518 )
  {
    sub_14012C680(&v4100.type);
    `std::locale::global'::`1'::dtor$2(&v4107);
    std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(&v4100.scratch[1]);
    goto LABEL_23;
  }
  v2398[38] = -987623081;
  v2398[34] = -1404424801;
  v2398[33] = -963101684;
  v2398[35] = -268435456;
  v2398[37] = 1913798922;
  v2398[39] = 0;
  v2398[36] = 33793328;
  v2398[45] = -987623081;
  v2398[41] = -1404424801;
  v2398[40] = -963101684;
  v2398[42] = -268435456;
  v2398[44] = 1913798922;
  v2398[46] = 0;
  v2398[43] = 33793328;
  dword_14047A3B4 = -1;
  sub_14012C680(&v4100.type);
  `std::locale::global'::`1'::dtor$2(&v4107);
  std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(&v4100.scratch[1]);
  sub_14012C680(&v4100.size_or_meta);
  sub_140007B70(v4108);
  sub_14012C680(v4101);
  std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(v4099);
  `std::locale::global'::`1'::dtor$2(v4106);
  sub_14012C680(v4102);
  std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(v4104);
  `std::locale::global'::`1'::dtor$2(&v4105);
  return v1519;
}
```

By digging into this, I have discovered an AES-256-CBC encryption routine:
```C++
void __fastcall aes256cbc_encrypt(aes_ctx_t *ctx, unsigned __int8 *buf, __int64 len)
{
  uint8_t *iv; // r9
  unsigned __int64 v6; // rdi
  unsigned __int8 *v7; // rax
  __int64 v8; // r9
  __int64 v9; // rdx

  iv = ctx->iv;
  if ( len )
  {
    v6 = ((len - 1) >> 4) + 1;
    do
    {
      v7 = buf;
      v8 = iv - buf;
      v9 = 16;
      do
      {
        *v7 ^= v7[v8];
        ++v7;
        --v9;
      }
      while ( v9 );
      aes256cbc_encrypt_block(a1: buf, a2: ctx);
      iv = buf;
      buf += 16;
      --v6;
    }
    while ( v6 );
  }
  *ctx->iv = *iv;
}
__int64 __fastcall aes256cbc_encrypt_block(unsigned __int8 *a1, __int64 a2)
{
  unsigned __int8 *v2; // rsi
  __int64 v3; // r12
  __int64 v4; // r9
  __int64 v5; // r8
  __int64 v6; // rbp
  unsigned __int8 *v7; // r8
  __int64 v8; // r9
  unsigned __int8 *v9; // rcx
  __int64 v10; // rdx
  __int64 v11; // rax
  char *v12; // r14
  unsigned __int8 v13; // cl
  __int64 v14; // r15
  unsigned __int8 v15; // al
  unsigned __int8 v16; // cl
  unsigned __int8 v17; // al
  unsigned __int8 v18; // cl
  unsigned __int8 v19; // al
  unsigned __int8 v20; // cl
  char v21; // di
  char v22; // r8
  char v23; // bl
  char v24; // r10
  char v25; // r11
  unsigned __int8 *v26; // rax
  __int64 v27; // r8
  __int64 v28; // rdx
  unsigned __int8 *v29; // r8
  __int64 v30; // r9
  unsigned __int8 *v31; // rcx
  __int64 v32; // rdx
  __int64 v33; // rax
  __int64 v34; // rdx
  unsigned __int8 v35; // cl
  unsigned __int8 v36; // al
  unsigned __int8 v37; // cl
  unsigned __int8 v38; // al
  unsigned __int8 v39; // cl
  unsigned __int8 v40; // al
  unsigned __int8 v41; // cl
  __int64 v42; // rcx
  __int64 result; // rax
  __int64 v44; // [rsp+30h] [rbp+8h]

  v2 = a1;
  v3 = a2 - a1;
  v4 = 4;
  do
  {
    v5 = 4;
    do
    {
      *a1 ^= a1[v3];
      ++a1;
      --v5;
    }
    while ( v5 );
    --v4;
  }
  while ( v4 );
  v6 = v3 + 16;
  v44 = 13;
  do
  {
    v7 = v2;
    v8 = 4;
    do
    {
      v9 = v7;
      v10 = 4;
      do
      {
        v11 = *v9;
        v9 += 4;
        *(v9 - 4) = aesCBCSBOX[v11];
        --v10;
      }
      while ( v10 );
      ++v7;
      --v8;
    }
    while ( v8 );
    v12 = (v2 + 2);
    v13 = v2[1];
    v14 = 4;
    v2[1] = v2[5];
    v2[5] = v2[9];
    v2[9] = v2[13];
    v15 = v2[10];
    v2[13] = v13;
    v16 = v2[2];
    v2[2] = v15;
    v17 = v2[14];
    v2[10] = v16;
    v18 = v2[6];
    v2[6] = v17;
    v19 = v2[15];
    v2[14] = v18;
    v20 = v2[3];
    v2[3] = v19;
    v2[15] = v2[11];
    v2[11] = v2[7];
    v2[7] = v20;
    do
    {
      v21 = *(v12 - 2);
      v22 = *(v12 - 1);
      v23 = v12[1];
      v24 = *v12;
      v12 += 4;
      v25 = v22 ^ v21 ^ v24 ^ v23;
      *(v12 - 6) = v25 ^ v21 ^ (2 * (v22 ^ v21)) ^ (27 * ((v22 ^ v21) >> 7));
      *(v12 - 5) = v25 ^ v22 ^ (2 * (v24 ^ v22)) ^ (27 * ((v24 ^ v22) >> 7));
      *(v12 - 4) = v25 ^ v24 ^ (2 * (v24 ^ v23)) ^ (27 * ((v24 ^ v23) >> 7));
      *(v12 - 3) = v25 ^ v23 ^ (2 * (v23 ^ v21)) ^ (27 * ((v23 ^ v21) >> 7));
      --v14;
    }
    while ( v14 );
    v26 = v2;
    v27 = 4;
    do
    {
      v28 = 4;
      do
      {
        *v26 ^= v26[v6];
        ++v26;
        --v28;
      }
      while ( v28 );
      --v27;
    }
    while ( v27 );
    v6 += 16;
    --v44;
  }
  while ( v44 );
  v29 = v2;
  v30 = 4;
  do
  {
    v31 = v29;
    v32 = 4;
    do
    {
      v33 = *v31;
      v31 += 4;
      *(v31 - 4) = aesCBCSBOX[v33];
      --v32;
    }
    while ( v32 );
    ++v29;
    --v30;
  }
  while ( v30 );
  v34 = 4;
  v35 = v2[1];
  v2[1] = v2[5];
  v2[5] = v2[9];
  v2[9] = v2[13];
  v36 = v2[10];
  v2[13] = v35;
  v37 = v2[2];
  v2[2] = v36;
  v38 = v2[14];
  v2[10] = v37;
  v39 = v2[6];
  v2[6] = v38;
  v40 = v2[15];
  v2[14] = v39;
  v41 = v2[3];
  v2[3] = v40;
  v2[15] = v2[11];
  v2[11] = v2[7];
  v2[7] = v41;
  do
  {
    v42 = 4;
    do
    {
      result = v2[v3 + 224];
      *v2++ ^= result;
      --v42;
    }
    while ( v42 );
    --v34;
  }
  while ( v34 );
  return result;
}
```

and a sha256 one, where it takes 3 inputs and does `SHA256(input1) XOR SHA256(input2 || input3)`:

```C++
__m128 **__fastcall sha256_xor_pair(__m128 **out32, const StrRef *s1, StrRef *extra, const StrRef *s2)
{
  unsigned __int64 v8; // rbx
  __m128i *v9; // rdi
  const u8 *v10; // rdx
  __int64 v11; // r8
  size_t Size; // rcx
  u64 cap_or_tag; // rdx
  __m128i *v14; // rsi
  _QWORD *v15; // rcx
  const u8 *v16; // rdx
  const u8 *v17; // rcx
  unsigned __int64 v18; // rax
  __m128 *v19; // rcx
  char *v20; // rdx
  __m128i *v21; // rax
  __m128i *v22; // rax
  void *Block[2]; // [rsp+50h] [rbp-39h] BYREF
  __int64 v25; // [rsp+60h] [rbp-29h]
  void *v26[2]; // [rsp+68h] [rbp-21h] BYREF
  __int64 v27; // [rsp+78h] [rbp-11h]
  _QWORD v28[3]; // [rsp+80h] [rbp-9h] BYREF
  unsigned __int64 v29; // [rsp+98h] [rbp+Fh]

  v8 = 0;
  *v26 = 0;
  v27 = 0;
  new_mem(a1: v26, a2: 0x20u);
  v9 = v26[0];
  *v26[0] = 0;
  v9[1] = 0;
  v26[1] = &v9[2];
  if ( s1->sso <= 0xF )
  {
    v10 = s1 + s1->cap_or_tag;
  }
  else
  {
    v10 = &s1->data[s1->cap_or_tag];
    s1 = s1->data;
  }
  sha256_update(begin: s1, end: v10, out: v9, out_end: &v9[2]);
  Size = extra->cap_or_tag;
  cap_or_tag = s2->cap_or_tag;
  if ( 0x7FFFFFFFFFFFFFFFLL - Size < cap_or_tag )
    err_0();
  if ( extra->sso > 0xF )
    extra = extra->data;
  if ( s2->sso > 0xF )
    s2 = s2->data;
  memcat(v28, cap_or_tag, v11, extra, Size: Size, Src: s2, cap_or_tag);
  *Block = 0;
  v25 = 0;
  new_mem(a1: Block, a2: 0x20u);
  v14 = Block[0];
  *Block[0] = 0;
  v14[1] = 0;
  Block[1] = &v14[2];
  v15 = v28;
  if ( v29 > 0xF )
    v15 = v28[0];
  v16 = v15 + v28[2];
  v17 = v28;
  if ( v29 > 0xF )
    v17 = v28[0];
  sha256_update(begin: v17, end: v16, out: v14, out_end: &v14[2]);
  *out32 = 0;
  *out32 = 0;
  out32[1] = 0;
  out32[2] = 0;
  new_mem(a1: out32, a2: 0x20u);
  v18 = *out32;
  *v18 = 0;
  *(v18 + 16) = 0;
  out32[1] = (v18 + 32);
  v19 = *out32;
  v20 = &(*out32)[1].m128_i8[15];
  if ( (*out32 > (&v9[1].m128i_u64[1] + 7) || v20 < v9)
    && (v19 > (&v14[1].m128i_u64[1] + 7) || v20 < v14)
    && (v19 > out32 || v20 < out32) )
  {
    *v19 = _mm_xor_ps(_mm_loadu_si128(v14), _mm_loadu_si128(v9));
    v19[1] = _mm_xor_ps(_mm_loadu_si128(v14 + 1), _mm_loadu_si128(v9 + 1));
  }
  else
  {
    do
    {
      (*out32)->m128_i8[v8] = v9->m128i_i8[v8] ^ v14->m128i_i8[v8];
      ++v8;
    }
    while ( v8 < 0x20 );
  }
  if ( v14 )
  {
    v21 = v14;
    if ( (v25 - v14) >= 0x1000 )
    {
      v14 = v14[-1].m128i_i64[1];
      if ( (v21 - v14 - 8) > 0x1F )
        invalid_parameter_noinfo_noreturn();
    }
    j_j_free(Block: v14);
  }
  std::string::~string(this: v28);
  if ( v9 )
  {
    v22 = v9;
    if ( (v27 - v9) >= 0x1000 )
    {
      v9 = v9[-1].m128i_i64[1];
      if ( (v22 - v9 - 8) > 0x1F )
        invalid_parameter_noinfo_noreturn();
    }
    j_j_free(Block: v9);
  }
  return out32;
}
void __fastcall sha256_update(const u8 *begin, const u8 *end, u8 *out, u8 *out_end)
{
  unsigned int v8; // ecx
  unsigned __int64 i; // rdx
  unsigned int v10; // ecx
  u8 *j; // r14
  u8 v12; // al
  __int64 v13; // r15
  char *v14; // rsi
  char *v15; // rdx
  size_t v16; // r14
  char *v17; // r9
  unsigned __int64 k; // rdx
  u8 *v19; // rax
  void *v20; // rcx
  char v21[4]; // [rsp+20h] [rbp-39h] BYREF
  int v22[3]; // [rsp+24h] [rbp-35h] BYREF
  void *Block[2]; // [rsp+30h] [rbp-29h] BYREF
  _BYTE v24[56]; // [rsp+40h] [rbp-19h] BYREF
  char v25; // [rsp+78h] [rbp+1Fh] BYREF

  Block[0] = 0;
  Block[1] = 0;
  memset(v24, 0, sizeof(v24));
  v22[0] = 0;
  fill_u32_pattern(&v24[8], &v24[24], v22);
  *&v24[24] = xmmword_14046A640;
  *&v24[40] = xmmword_14046A650;
  v8 = 0;
  *&v24[8] += end - begin;
  for ( i = 0; i < 4; ++i )
  {
    v10 = *&v24[4 * i + 8] + v8;
    *&v24[4 * i + 8] = v10;
    if ( v10 < 0x10000 )
      break;
    v8 = HIWORD(v10);
    *&v24[4 * i + 10] = 0;
  }
  for ( j = Block[1]; begin != end; ++begin )
  {
    v12 = *begin;
    v21[0] = *begin;
    if ( j == *v24 )
    {
      sub_14043A050(Block, j, v21);
      j = Block[1];
    }
    else
    {
      *j = v12;
      j = ++Block[1];
    }
  }
  v13 = 0;
  v14 = Block[0];
  if ( (j - Block[0]) >= 0x40 )
  {
    do
    {
      sha256_compress_2blocks(&v24[24], &v14[v13]);
      v13 += 64;
      j = Block[1];
      v14 = Block[0];
    }
    while ( (v13 + 64) <= (Block[1] - Block[0]) );
  }
  v15 = &v14[v13];
  if ( v14 != &v14[v13] )
  {
    v16 = j - v15;
    memmove(v14, Src: v15, Size: v16);
    Block[1] = &v14[v16];
  }
  sha256_finalize_buf(Block);
  v17 = &v24[24];
  do
  {
    for ( k = 0; k < 4; ++k )
    {
      if ( out == out_end )
        break;
      v19 = out++;
      *v19 = *v17 >> (8 * (3 - k));
    }
    v17 += 4;
  }
  while ( v17 != &v25 );
  v20 = Block[0];
  if ( Block[0] )
  {
    if ( *v24 - Block[0] >= 0x1000 )
    {
      v20 = *(Block[0] - 1);
      if ( (Block[0] - v20 - 8) > 0x1F )
        invalid_parameter_noinfo_noreturn();
    }
    j_j_free(Block: v20);
  }
}
```
By inspecting the code more, we can see that the IV is just the byte range [00, 0F], and that the result of the previous hashing+XOR procedure is used as key for AES-CBC. I presumed at this point that this is how the server communicates with us, so I went on to search for where the inputs came from.

We find that the first input is at offset 160 in the config given to this function, the second one is at offset 192, and the third one is the hour of the current GMT time (use dynamic analysis to retrieve the format or just compute it from the operations there):

```C++
// write access to const memory has been detected, the output may be wrong!
__int64 __fastcall sub_140037090(__int64 a1, __int64 a2)
{
  dword_14047A3AC = 1;
  dword_14047A3B4 = 0;
  memcpy_wrap_1(a2, a1 + 192);
  return a2;
}
__int64 __fastcall sub_140037060(__int64 a1, __int64 a2)
{
  memcpy_wrap_1(a2, a1 + 160);
  return a2;
}
```

So, from here, I went back to main and traced where that config was built from.

```C++
// write access to const memory has been detected, the output may be wrong!
int __fastcall main(int argc, const char **argv, const char **envp)
{
  dword_14047A3B0 = 0;
  v39[0] = -883863319;
  v32[1] = -2071170243;
  v39[1] = -166556534;
  v32[0] = -621766678;
  dword_14047A3B4 = 0;
  (memset_wrapper)(v106, 320);
  (setCfg)(v106, &unk_1404780A0);
  if ( !doAuth(v106) )
  {
    v39[0] = -1197171932;
    v32[0] = 0;
    v32[1] = -401639781;
    v39[1] = -764834860;
    dword_14047A3B0 = 38531;
    dword_14047A3B4 = -45170;
    dword_14047A3AC = -2;
    v95[0] = 0;
    v3 = sub_140226560(v95);
    v4 = sub_14022E3D0(v3);
    v5 = std::string::string(v99, v4);
    v6 = sub_1402264D0(&v94);
    v7 = sub_140230290(v6);
    v8 = std::string::string(v98, v7);
    sub_140054C50(v8, v5);
  }
  v39[1] = -538005833;
  v32[0] = -155323700;
  v39[0] = 0;
  v32[1] = -1;
  dword_14047A3B0 = 1;
  dword_14047A3B4 = 5709;
  dword_14047A3AC = 0;
  sub_140036CF0(v106, Buf1);
  v9 = sub_140226640(&v93);
  v10 = sub_14022C510(v9);
  v11 = std::string::string(v100, v10);
  v12 = sub_14042F6E0(Buf1: Buf1, Buf2: v11);
  `std::locale::global'::`1'::dtor$2(v100);
  if ( v12 )
  {
    v39[0] = -1808693765;
    v39[1] = 525596399;
    v32[0] = -1366461928;
    dword_14047A3B0 = 1;
    dword_14047A3B4 = 5709;
    dword_14047A3AC = 0;
    v13 = sub_140226700(&v92);
    v14 = sub_140228790(v13);
    v15 = std::string::string(v102, v14);
    v16 = sub_1402266A0(&v91);
    v17 = sub_14022A650(v16);
    v18 = std::string::string(v101, v17);
    sub_140054C50(v18, v15);
  }
  dword_14047A3AC = -1;
  memset_zero(&v104, 8u);
  if ( __eh34_try(-1, 0) )
  {
    __eh34_scope_strut(0);
    sub_14000CF30(&v104, Buf1);
    if ( talk_to_c2(&v104, v106) )
    {
      v32[0] = 205069;
      v39[1] = 1079814197;
      v32[1] = 0;
      dword_14047A3B4 = 0;
      http_handler(&v104, v106);
    }
    sub_14000D630(&v104);
  }
  if ( __eh34_catch(0) )
  {
    if ( __eh34_catch_type(0, &std::exception `RTTI Type Descriptor', &v96) )
    {
      strcpy(v32, "p 4D@D");
      strcpy(v39, "PKBS2c");
      HIBYTE(v39[1]) = 0;
      v39[1] -= 39496;
      v32[1] = -1143874688;
      v31 = -1791311861 - v32[0];
      v32[0] = -16778247;
      v39[0] = -16787280;
      if ( v31 < 1744794077 )
        v26 = v53 + 2080373751;
      v49 = v34 % 53011;
      v59 &= 0xFB61u;
      v30 = v44 | 0x8B7F4070;
      ++v43;
      v58 >>= 31;
      v39[0] = v83 % 61336;
      if ( v39[1] < -782683929 >> v43 )
      v42 &= v45;
      v24 = v74 >> 31;
      v46 = v26 * v43;
      v49 ^= v32[1];
      v28 = -362819354 * v79;
      v48 += v88;
      v74 *= 34834;
      v56 = v88 | 0x6577;
      if ( -362819354 * v79 == v34 )
        ++v62;
      if ( v69 != v25 )
        ++v39[0];
      v27 = v26 | 0xDE3D;
      v69 = v28 & 0x9AD7;
      if ( v31 == v58 )
        ++v30;
      if ( v58 >= -620962865 )
        ++v39[0];
      if ( v50 != v39[0] )
        --v53;
      v52 += v80;
      v71 %= 887157008;
      if ( v27 < v82 )
        ++v61;
      v49 /= 3917;
      if ( v24 <= 0 )
      dword_14047A3B4 = (v49 + v39[0] + v89)
                      & (v66 + v39[1])
                      & 0xB14197F9
                      & v64
                      & 0x9F298650
                      ^ (v62 - 30796 + 10312)
                      & (v33 + v55)
                      & v32[1]
                      | (v48 - v32[0] - 973091072 + 174548579)
                      & (-295962076 - (v74 + 9678) + 1268661469)
                      & 0x8100572F
                      & v56
                      & 0x6DBB4B64
                      ^ v25
                      & v73
                      | (v47 - v30 - v83 - v46 - 1941496678)
                      ^ (-107334730 - v57 - v58)
                      ^ 0x4BF97DEF
                      ^ (-16811296 * v66 + 1810)
                      | v82 & 0xAEA13199 ^ ((v36 >> 31) - v78 + 12692213 + 9555 * v34) ^ v81 ^ v77 ^ v87 ^ v80
                      | ((-782683929 >> v43) + v76 + 49720374) ^ (v31 - v79 + 8945561) ^ (v41 + 1651) ^ 0xB5AC04CD
                      | (v85 + v45)
                      & 0x2CFB0FEB
                      & v72
                      & 0x47AF0004
                      & (v32[1] / -2130705919)
                      ^ v59
                      & 0xA575AB82
                      ^ (v44 + 1791302203)
                      | (v60 + 1) & (1557782271 - v38) & v65 ^ (-2046916866 - v24) & v75 ^ 0x200
                      | (v63 + v38 - 1954594704) & v37 ^ (v29 - v43) & v34 ^ 0xFC776BBD
                      | (v74 + v86) ^ v84 & v62 ^ v51 ^ 0x200
                      | (v42 - v68) & v61 & v36
                      | (v67 - v52) ^ v28
                      | (v27 - v70) ^ v69
                      | (v53 - 1 + v40)
                      | v88 & v54
                      | v71 & 0xA7BEB1D9
                      | v50 & v35
                      | (-1954594704 % v57 - 1);
      v20 = (*(*v96 + 8LL))(v96);
      std::string::string(v97, v20);
      v21 = sub_140226790(&v90);
      v22 = sub_1402268D0(v21);
      v23 = std::string::string(v103, v22);
      sub_140054C50(v23, v97);
    }
  }
  dword_14047A3AC = -1;
  v32[0] = -1635048422;
  dword_14047A3B4 = -1;
  `std::locale::global'::`1'::dtor$2(Buf1);
  cleanup(v106);
  return 0;
}
```

We can see a memset on that config variable and then a function calling into it, after which it is used in other big functions.

```C++
// write access to const memory has been detected, the output may be wrong!
__int64 __fastcall sub_14002E020(__int64 a1)
{
  __m128i si128; // xmm0
  __int64 *ThreadLocalStoragePointer; // rax
  __int64 v4; // r15
  int v5; // eax
  __m128i *v6; // rdi
  _BYTE *v7; // rax
  size_t v8; // rsi
  size_t v9; // r8
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // rax
  __int64 v15; // rax
  int v16; // eax
  __int64 v17; // rdi
  _BYTE *v18; // rax
  size_t v19; // r8
  int v20; // eax
  _BYTE *v21; // rax
  __int128 v23; // [rsp+1F8h] [rbp+F8h] BYREF
  __int128 v24; // [rsp+208h] [rbp+108h]
  char v25; // [rsp+218h] [rbp+118h] BYREF
  int v26; // [rsp+228h] [rbp+128h] BYREF

  *a1 = 0;
  *(a1 + 16) = 0;
  *(a1 + 24) = 15;
  *a1 = 0;
  *(a1 + 32) = 0;
  *(a1 + 48) = 0;
  *(a1 + 56) = 15;
  *(a1 + 32) = 0;
  *(a1 + 64) = 0;
  *(a1 + 80) = 0;
  *(a1 + 88) = 15;
  *(a1 + 64) = 0;
  *(a1 + 96) = 0;
  *(a1 + 112) = 0;
  *(a1 + 120) = 15;
  *(a1 + 96) = 0;
  *(a1 + 128) = 0;
  *(a1 + 144) = 0;
  *(a1 + 152) = 15;
  *(a1 + 128) = 0;
  *(a1 + 160) = 0;
  *(a1 + 176) = 0;
  *(a1 + 184) = 15;
  *(a1 + 160) = 0;
  *(a1 + 192) = 0;
  *(a1 + 208) = 0;
  *(a1 + 216) = 15;
  *(a1 + 192) = 0;
  *(a1 + 224) = 0;
  *(a1 + 240) = 0;
  *(a1 + 248) = 15;
  *(a1 + 224) = 0;
  *(a1 + 256) = 0;
  *(a1 + 264) = 0;
  *(a1 + 272) = 0;
  si128 = _mm_load_si128(&xmmword_14046BEA0);
  v26 = -543545100;
  ThreadLocalStoragePointer = NtCurrentTeb()->ThreadLocalStoragePointer;
  v4 = *ThreadLocalStoragePointer;
  v5 = *(*ThreadLocalStoragePointer + 428);
  if ( (v5 & 1) != 0 )
  {
    v6 = (v4 + 904);
  }
  else
  {
    *(v4 + 428) = v5 | 1;
    v6 = (v4 + 904);
    *(v4 + 924) = 1;
    if ( v4 + 904 > &v26 + 3 || v4 + 923 < &v25 )
    {
      *v6 = si128;
      *(v4 + 920) = v26;
    }
    else
    {
      *v6 = si128;
      *(v4 + 920) = v26;
    }
    _tlregdtor(qword_140466D50);
  }
  v7 = sub_1402B1060(v6);
  *(a1 + 280) = 0;
  *(a1 + 296) = 0;
  *(a1 + 304) = 0;
  v8 = -1;
  v9 = -1;
  do
    ++v9;
  while ( v7[v9] );
  memcpy_wrap((a1 + 280), v7, v9);
  *(a1 + 312) = 8000;
  dword_14047A3B0 = 1;
  dword_14047A3B4 = 5709;
  dword_14047A3AC = 0;
  v10 = GetUsername(&unk_1404780A0, &v23);
  move_to_off(a1, v10);
  std::string::~string(this: &v23);
  v11 = GetComputername(&unk_1404780A0, &v23);
  move_to_off(a1 + 32, v11);
  std::string::~string(this: &v23);
  dword_14047A3B4 = -1;
  v12 = GetVersion(&unk_1404780A0, &v23);
  move_to_off(a1 + 64, v12);
  std::string::~string(this: &v23);
  v13 = buildSysInfoString(&unk_1404780A0, &v23);
  move_to_off(a1 + 96, v13);
  std::string::~string(this: &v23);
  dword_14047A3B4 = -1;
  v14 = GetMemory(&unk_1404780A0, &v23);
  move_to_off(a1 + 128, v14);
  std::string::~string(this: &v23);
  v15 = joinUsernameAndCompName(&unk_1404780A0, &v23);
  move_to_off(a1 + 160, v15);
  std::string::~string(this: &v23);
  v16 = *(v4 + 1104);
  if ( (v16 & 1) != 0 )
  {
    v17 = v4 + 1500;
  }
  else
  {
    *(v4 + 1104) = v16 | 1;
    v17 = v4 + 1500;
    *(v4 + 1503) = 411;
    *(v4 + 1500) = -27951;
    *(v4 + 1502) = 12;
    _tlregdtor(qword_140466D30);
  }
  v18 = build192Off(v17);
  v23 = 0;
  v24 = 0;
  v19 = -1;
  do
    ++v19;
  while ( v18[v19] );
  memcpy_wrap(&v23, v18, v19);
  move_to_off(a1 + 192, &v23);
  std::string::~string(this: &v23);
  v20 = *(v4 + 516);
  if ( (v20 & 1) == 0 )
  {
    *(v4 + 516) = v20 | 1;
    *(v4 + 1223) = 265;
    *(v4 + 1220) = 27775;
    *(v4 + 1222) = 122;
    _tlregdtor(qword_140466D10);
  }
  v21 = sub_1402AD2E0(v4 + 1220);
  v23 = 0;
  v24 = 0;
  do
    ++v8;
  while ( v21[v8] );
  memcpy_wrap(&v23, v21, v8);
  move_to_off(a1 + 224, &v23);
  std::string::~string(this: &v23);
  return a1;
}
```

We can see that it saves some computer info at various offsets. Especially, at offset 160 it joins the username and computername by "@". At offset 192, it builds the string `N/A` via SIMD operations and saves it there. So, we have 1/3 pieces for trying to decrypt the communications. We just need the hour and the joined string. The hour we can luckily get from the PCAP as `06`, so that leaves us with only the "username@computername" string.

Investigating the other big function before our previous but after the config mapping, we get this one:
```C++
__int64 __fastcall doAuth(__int64 a1)
{
  dword_14047A3B4 = -1;
  dword_14047A3AC = -1;
  Time = time64(Time: 0);
  dword_14047A3AC = -1;
  dword_14047A3B4 = 0;
  strcpy(v439, "Jb4YC`");
  HIBYTE(v439[1]) = 0;
  v117 = 4 * v439[0];
  if ( 4 * v439[0] == -1832869221 )
  v431 ^= 0xC6C2B72E;
  --v1148;
  v45 = 1072348177 - v122;
  ++v986;
  v1438 = 1065332607 * v741;
  v740 = -33554432 * v741;
  ++v428;
  v36 = (v117 - 1945) & 0x9AF0;
  --v433;
  v47 = (v435 & 0x10E | 0x2261) ^ 0x17E2;
  if ( v430 > v47 )
  if ( v120 != v45 )
  v123 /= 22808;
  v438 = v1143 % 56573;
  v117 ^= 0xD08Au;
  v434 += v121;
  v1445 = v432;
  v1457 = v115 & 0x7FCCB631;
  v1456 = v1142 & v425;
  v1455 = (1 >> v435)
        & 0xFFFF10D4
        ^ v426
        & 0xCFCAFAAB
        ^ (v739 + v45 + v117 + 1905459926)
        ^ (v427 + 25383480)
        & ((v427 & 0x7DD00322 | 0x820D2019) + v118 - v1143 - 15075714 + 881844592)
        ^ 0xA53392BD;
  v1454 = v428 ^ v429;
  v1453 = (-699587521 - v984) & v430 & v740 ^ v119;
  v1451 = (1065332607 * v741 + v53) & v120 & 0xA5090188 ^ v1144;
  v1450 = (v46 + v985 + v431) & (v986 - 1936692736);
  v1449 = (v1145 + -1456230411 - v987 + 64495)
        & v121
        ^ (v1446 + v741 - 1941457965 - v433 - v432 - v63 - 624407790 + 1)
        ^ (v434 + v435)
        ^ 0xFFFFF867;
  v1448 = v1235
        ^ ((-763618556 >> v435 << 26) - v1146 - v122)
        ^ (v436 + v123 - 2097066622)
        & (1351966412 - v1147)
        ^ 0xA3D7B6F1;
  v1447 = v742;
  dword_14047A3B4 = v115 & 0x7FCCB631
                  | v1142 & v425
                  | v1455
                  | v428 ^ v429
                  | v1453
                  | v1451
                  | v1450
                  | v1449
                  | v1448
                  | v742
                  | v437 & v36 ^ (((v743 / 465043456) & 0xFEBC) - 1945) & 0x7FEABE1A ^ 0xCF936E14
                  | (v1143 % 56573) ^ (v47 + v1148) ^ (8203 - v1149)
                  | v743 ^ 0x5BC80AA3
                  | (v739 - 1615207937 - v439[0]) & v439[1] & 0x767B1C53
                  | v124
                  & 0x2A30C
                  ^ (v435 & 0x10E | 0x7CFEFEEF)
                  ^ (v125 - 1387747831)
                  & 0xA
                  ^ (v440 - v744)
                  ^ 0x393D4C16
                  | v1150 & 0x49048FDD ^ 0xC10A364D
                  | v441 ^ 0xEB4E6F2F
                  | (v426 % v432 * (v426 % v432) - 347213796) ^ 0x35CFE3D8
                  | 0x81000008
                  | 0x7D1A56EF
                  | 0x23916592;
  gmtime64_s(Tm: &Tm, Time: &Time);
  dword_14047A3AC = -1;
  memset(buf: &v82, value: 0, count: sizeof(v82));
  v1 = sub_1400D3850(&v82);
  v2 = sub_140299E30(v1);
  strftime(Buffer: Buffer, SizeInBytes: 0xBu, Format: v2, Tm: &Tm);
  dword_14047A3AC = -1;
  std::string::string(v2570, Buffer);
  dword_14047A3B0 = 38531;
  dword_14047A3B4 = -45170;
  dword_14047A3AC = -2;
  sub_140037060(a1, v2569);
  dword_14047A3B4 = -1022967541;
  sub_14042F520(v2568);
  dword_14047A3AC = -1;
  jumpbuf_sp = _except_get_jumpbuf_sp(v2568);
  dword_14047A3B4 = -1;
  memset_zero(v2565, 0x18u);
  v3 = sub_1402B4AF0(v1128);
  sub_1402B4A90(v2565, jumpbuf_sp, v3);
  dword_14047A3B4 = -1;
  v4 = mov_rax_rcx(v2565);
  SBOXXor(data: v2568, v4, jumpbuf_sp);
  dword_14047A3AC = 1;
  dword_14047A3B4 = 620756399;
  memset_zero(v2573, 0x40u);
  memset(buf: v83, value: 0, count: 1u);
  v5 = sub_1400D38C0(v83);
  v6 = sub_140297F70(v5);
  v2469 = std::string::string(v2548, v6);
  v2470 = v2469;
  v2474 = v2469;
  memset(buf: &v64, value: 0, count: sizeof(v64));
  v7 = sub_1400D3930(&v64);
  v8 = sub_1402960B0(v7);
  v2471 = std::string::string(v2542, v8);
  v2472 = v2471;
  v2473 = v2471;
  sub_140431970(v2554, v2474, v2471);
  memset(buf: &v65, value: 0, count: sizeof(v65));
  v9 = sub_1400D3A20(&v65);
  v10 = sub_1402941F0(v9);
  v2475 = std::string::string(v2543, v10);
  v2476 = v2475;
  v2484 = v2475;
  memset(buf: &v66, value: 0, count: sizeof(v66));
  v11 = mov_rax_rcx(v2565);
  v2477 = format_hex(v2544, v11, jumpbuf_sp);
  v2479 = v2477;
  v12 = sub_1400D3A90(&v66);
  v13 = sub_140292330(v12);
  v2478 = std::string::string(v2546, v13);
  v2480 = v2478;
  v2481 = sub_14042F5F0(v2547, v2478, v2479);
  v2468 = v2481;
  v2483 = v2481;
  sub_140431970(v2555, v2484, v2481);
  qmemcpy(dst: v2534, src: unknown_libname_29(v2541, v2554, v2556), count: sizeof(v2534));
  sub_1402CE7B0(v2573, v2534);
  `eh vector destructor iterator'(v2554, 0x40u, 2u, sub_140004B50);
  `std::locale::global'::`1'::dtor$2(v2547);
  `std::locale::global'::`1'::dtor$2(v2546);
  `std::locale::global'::`1'::dtor$2(v2544);
  `std::locale::global'::`1'::dtor$2(v2543);
  `std::locale::global'::`1'::dtor$2(v2542);
  `std::locale::global'::`1'::dtor$2(v2548);
  dword_14047A3B4 = 0;
  memset_zero(v2561, 8u);
  v2485 = sub_140036CB0(a1, v2540);
  v2486 = v2485;
  v1897 = sub_140036CE0(a1);
  v2530 = sub_14000D5D0(v2561, v2486, v1897);
  `std::locale::global'::`1'::dtor$2(v2540);
  dword_14047A3AC = -1;
  memset_zero(v2572, 0x50u);
  v2487 = v2558;
  memset(buf: &v67, value: 0, count: sizeof(v67));
  v2488 = sub_1402B3BE0(v2558, 0);
  v2492 = v2488;
  v2489 = sub_1400D3B00(&v67);
  v2490 = sub_140290470(v2489);
  v2491 = std::string::string(v2539, v2490);
  v2493 = v2491;
  v2531 = sub_14000D790(v2561, v2572, v2491, v2573, v2492);
  `std::locale::global'::`1'::dtor$2(v2539);
  HasCapturedContext = Concurrency::details::_ContextCallback::_HasCapturedContext(this: v2572);
  if ( !HasCapturedContext || (v2494 = mov_rax_rcx(v2572), *(v2494 + 32) != 200) )
  {
    dword_14047A3B4 = -1;
    memset(buf: v79, value: 0, count: 1u);
    v2525 = sub_1400D3DA0(v79);
    v2526 = sub_140282D30(v2525);
    v2527 = std::string::string(v2553, v2526);
    v2528 = v2527;
    v2422 = sub_140001F70(v2572);
    sub_140050E60(v2528, v2422);
  }
  dword_14047A3B4 = -1022967541;
  v2495 = v2559;
  v2496 = sub_1402B3BE0(v2559, 0);
  v2497 = v2496;
  v2482 = mov_rax_rcx(v2572);
  LOBYTE(v14) = 1;
  v2532 = json_parse_into(v2563, v2482 + 200, v2497, v14, 0);
  memset(buf: &v69, value: 0, count: sizeof(v69));
  v2498 = sub_1400D3B60(&v69);
  v2499 = sub_14028E5B0(v2498);
  v2500 = std::string::string(v2549, v2499);
  v2501 = v2500;
  v70 = json_object_contains(v2563, v2500);
  v71 = v70;
  `std::locale::global'::`1'::dtor$2(v2549);
  if ( v71 )
  {
    dword_14047A3B4 = 0;
    memset_zero(v2566, 0x18u);
    v2504 = v2556;
    memset(buf: &v72, value: 0, count: sizeof(v72));
    v2502 = sub_1400D3BC0(&v72);
    v2503 = sub_14028C6F0(v2502);
    v2505 = std::string::string(v2504, v2503);
    v2506 = json_object_ref(v2563, v2505);
    v2533 = str_assign_0(v2506, v2538);
    v2529 = sub_140066A60(v2566, v2538);
    `std::locale::global'::`1'::dtor$2(v2538);
    dword_14047A3AC = -1;
    v2535 = decrypt_first_buf(v2571, v2566, v2569);
    dword_14047A3B4 = 0;
    v2507 = v2560;
    v2508 = sub_1402B3BE0(v2560, 0);
    LOBYTE(v15) = 1;
    v2536 = json_parse_into(v2562, v2571, v2508, v15, 0);
    memset(buf: &v73, value: 0, count: sizeof(v73));
    v2509 = sub_1400D3C20(&v73);
    v2510 = sub_14028A830(v2509);
    v2511 = std::string::string(v2545, v2510);
    v2512 = v2511;
    v74 = json_object_contains(v2562, v2511);
    v75 = v74;
    `std::locale::global'::`1'::dtor$2(v2545);
    if ( v75 )
    {
      dword_14047A3B4 = 0;
      v2515 = &v2557;
      memset(buf: &v76, value: 0, count: sizeof(v76));
      v2513 = sub_1400D3C80(&v76);
      v2514 = sub_140288970(v2513);
      v2516 = std::string::string(v2515, v2514);
      v2517 = json_object_ref(v2562, v2516);
      v2537 = str_assign_9(v2517, Str);
      dword_14047A3B4 = -1;
      memset(buf: &v77, value: 0, count: sizeof(v77));
      v2518 = sub_1400D3CE0(&v77);
      v2519 = sub_140286AB0(v2518);
      v2520 = std::string::string(v2550, v2519);
      v16 = sub_1402CEE40(v2520, 0);
      v2467 = strstr(Str, *v16, 0);
      `std::locale::global'::`1'::dtor$2(v2550);
      if ( v2467 != -1 )
      {
        dword_14047A3AC = -1;
        v2521 = str_substr(Str, v2551, 0, v2467);
        v2522 = v2521;
        str_assign_at_192(a1, v2521);
        `std::locale::global'::`1'::dtor$2(v2551);
        dword_14047A3B4 = 0;
        v2523 = str_substr(Str, v2552, v2467 + 1, -1);
        v2524 = v2523;
        sub_1400349D0(a1, v2523);
        `std::locale::global'::`1'::dtor$2(v2552);
        dword_14047A3B4 = -1;
        `std::locale::global'::`1'::dtor$2(Str);
        sub_14012C680(v2562);
        `std::locale::global'::`1'::dtor$2(v2571);
        std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(v2566);
        sub_14012C680(v2563);
        sub_140007B70(v2572);
        sub_14000D630(v2561);
        FSimpleLinkNavModifier::~FSimpleLinkNavModifier(this: v2573);
        std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(v2565);
        `std::locale::global'::`1'::dtor$2(v2568);
        `std::locale::global'::`1'::dtor$2(v2569);
        `std::locale::global'::`1'::dtor$2(v2570);
        return v78;
      }
      `std::locale::global'::`1'::dtor$2(Str);
    }
    sub_14012C680(v2562);
    `std::locale::global'::`1'::dtor$2(v2571);
    std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(v2566);
  }
  sub_14012C680(v2563);
  sub_140007B70(v2572);
  sub_14000D630(v2561);
  v962 |= 0x60E9u;
  v42 = v382 - v382 / 63125;
  v956 %= 1446956993;
  v38 = v382 & 0xBD88;
  if ( v698 == v954 - 385205013 )
  v1127 /= 14326;
  if ( v42 )
  {
    v2428 = v382 - v382 / 63125;
    v57 = 1544777775 % v42;
  }
  if ( v1126 != (v961 ^ 0x5A04) )
    --v956;
  v952 <<= 21;
  v383 = 117444656 * v700;
  --v387;
  v37 = v28 / 60722;
  v61 = v386 ^ 0x40B50CD0;
  v31 = v38 - v700 - 1;
  v24 = 926534581 << v385;
  v39 = v38 % 26468;
  v955 = v389 >> 31;
  v58 = v57 % 52313;
  v389 += 1073612027;
  v2432 = 117444656 * v700;
  v52 = (117444656 * v700) >> v698;
  if ( (v386 ^ 0x40B50CD0) == 0xE6B7885B )
  v959 = v948 - 58649;
  v953 ^= 0x977Bu;
  v27 = -33298 * v382;
  v699 <<= 10;
  v386 = -1635048422 << v952;
  if ( v383 != 1020110045 )
  v391 *= 27336;
  v44 = (-1857319767 >> v958) | 0x2DA1;
  v32 = 5597 >> v1224;
  if ( v31 != v960 )
    --v384;
  v1224 = v704 % 8924;
  v390 += 273678337;
  v59 = 27336 << v44;
  if ( v44 < 1073741825 )
    --v37;
  v700 -= 1085607120;
  if ( v59 != v385 )
  v387 &= 0xDFB7u;
  v33 = v32 % 1766542948;
  --v1125;
  if ( v27 < 0x20000000 )
  if ( v390 == 62251 )
  if ( v31 > v961 )
  v703 ^= 0x802D282u;
  if ( v58 < v958 )
  --v381;
  ++v387;
  v2441 = v958;
  v2442 = v56 | 0xFDDFFDCC;
  v954 += v27;
  v2443 = v962;
  v703 |= v37;
  v49 = (v384 ^ 0xFB6DE402) - 1981794809;
  v390 = v954 ^ 0x17E6;
  if ( v1127 != 441974767 )
  v35 = v34 / 31648;
  v1223 += 15878;
  v55 = 29530 >> v697;
  v948 /= 11640;
  v30 = -424179621 - v40;
  v18 = (v962 << (v958 >> 9)) - 1;
  v1225 /= -1824375549;
  v2446 = v385;
  v697 = v385 << 17;
  if ( v18 >= v383 )
    ++v59;
  v22 = v21 | 0x323A;
  if ( v959 < v31 )
    --v28;
  v2447 = v382 - v382 / 63125;
  v43 = v42 >> 14;
  v29 = v383 + 738197504;
  v54 = 33875138 - v39 - 1;
  if ( v59 >= 27336 )
    ++v28;
  if ( !v381 )
    ++v31;
  v41 = v54 + v40;
  v952 = v699 * v27;
  if ( v699 < -757798979 )
    --v385;
  v960 >>= 18;
  if ( v955 >= -1921843607 )
  v25 = v24 - 1;
  v20 = v19 + 1;
  v60 = v59 << 21;
  if ( v384 )
  {
    v2448 = v384;
    v55 /= v384;
  }
  if ( v382 >= v703 )
  if ( v39 == -1981794809 )
    v29 = v383 + 738197505;
  if ( v49 >= 33816576 )
  v81 = v54 & 0xA5BA;
  if ( v391 > 2112392003 )
    ++v23;
  v2449 = -33298 * v382;
  v2450 = v388;
  v702 = v698 / v388;
  if ( v381 > v52 )
    ++v51;
  v2465 = v48 & (-8524288 * v382 + v1124);
  v2464 = v2451
        & (v952 + v54 + 5597 - 27336)
        ^ (v381 - 25315)
        ^ (v954 - v953)
        & (334567554 - v697 + 1073741825 - v1125)
        ^ v955;
  v2463 = v1223 ^ v382 & (v956 - v384 - v383) ^ (v28 + v55) ^ (v49 - v2452) ^ (v385 + v386);
  v2462 = v698
        ^ v26
        ^ (v957 + (v48 | 0x2353))
        & (v699 - 12858)
        ^ v700
        & ((v58 >> 7) - v1126)
        & (v1268 + v58 - v1127)
        & v958;
  v2461 = v387;
  v2460 = v2453 & v959 & 0xFFFEC548;
  v2458 = v60 & v29 ^ 0x47DA;
  v2457 = (33816576 - v37) & v701 & (v960 - v39);
  v2456 = (v702 - (v28 & 0xB8EF)) & v1224 ^ ((v43 & (v698 | 0x93423D03)) - 134402690 - v61);
  v2454 = (v22 + v50 + v1225 + v703) ^ (1073612027 - v62) ^ (v51 + v23 - 15878) & (v1269 + v704 + 2112392003);
  dword_14047A3B4 = v2465
                  | v2464
                  | v2463
                  | v2462
                  | v387
                  | v2460
                  | v2458
                  | v2457
                  | v2456
                  | v2454
                  | (v388 + v41) & v962
                  | (v391 + 1940873108)
                  ^ (v961 + v43 - v389 - ((v56 | 0xFDDFFDCC) >> v957))
                  & (v390 + v52)
                  ^ (v18 + 891253037 - v31 - (v958 >> 9))
                  | v33
                  | (-35343 - (v41 | 0x7C1F)) ^ v35
                  | (v1270 + v44 - 1635048422) & 0xF6BDCACD ^ (616663559 - v81) ^ 0xFFFFDAFC ^ 0x93423D03
                  | v30 ^ 0x9AA96A2E
                  | v25 & (v948 + v61 % 5597 - v20 + 268435458) & 0xEFFFFFFF ^ 0xFFFFFFF3
                  | 0x20000000
                  | 0x1A57FFEF
                  | 0xFFFF43CC;
  FSimpleLinkNavModifier::~FSimpleLinkNavModifier(this: v2573);
  std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(v2565);
  `std::locale::global'::`1'::dtor$2(v2568);
  `std::locale::global'::`1'::dtor$2(v2569);
  `std::locale::global'::`1'::dtor$2(v2570);
  return v80;
}
```
Analyzing it, we can see it building a string with the current date (YEARMONTHDAYHOUR) and concatenating it with the value at offset 160.
```C++
  strftime(Buffer: Buffer, SizeInBytes: 0xBu, Format: v2, Tm: &Tm);
  std::string::string(v2570, Buffer);
  sub_140037060(a1, v2569);
  sub_14042F520(v2568);

__int64 __fastcall sub_140037060(__int64 a1, __int64 a2)
{
  memcpy_wrap_1(a2, a1 + 160);
  return a2;
}
_QWORD *__fastcall sub_14042F520(_QWORD *a1, _QWORD *a2, _QWORD *Src)
{
  size_t v3; // r9
  size_t Size; // rcx

  v3 = Src[2];
  Size = a2[2];
  if ( 0x7FFFFFFFFFFFFFFFLL - Size < v3 )
    err_0();
  if ( a2[3] > 0xFu )
    a2 = *a2;
  if ( Src[3] > 0xFu )
    Src = *Src;
  memcat(a1, a2, Src, a2, Size: Size, Src: Src, v3);
  return a1;
}
```

It then puts that value into another function, which does seems to implement a substitution cipher via a table lookup and encryption with XOR with key 0x5A.

```C++
// write access to const memory has been detected, the output may be wrong!
void __fastcall SBOXXor(std_string *data, __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 i; // rbx
  char v7; // r11

  if ( a3 )
  {
    for ( i = 0; i < a3; ++i )
    {
      dword_14047A3B4 = -1;
      v7 = *(sub_1402CEDD0(data) + i) ^ 0x5A;
      dword_14047A3B0 = 1071644672;
      dword_14047A3B4 = -1;
      *(a2 + i) = byte_14046A540[(i + 1 + v7)];
    }
  }
}
```

Looking downwards from it and inspecting functions, we can see that it eventually calls a function related to http, which seems to do an HTTP GET request.


```C++
 memset(buf: &v67, value: 0, count: sizeof(v67));
  v2488 = sub_1402B3BE0(v2558, 0);
  v2492 = v2488;
  v2489 = sub_1400D3B00(&v67);
  v2490 = sub_140290470(v2489);
  v2491 = std::string::string(v2539, v2490);
  v2493 = v2491;
  v2531 = sub_14000D790(v2561, v2572, v2491, v2573, v2492);
  `std::locale::global'::`1'::dtor$2(v2539);
  HasCapturedContext = Concurrency::details::_ContextCallback::_HasCapturedContext(this: v2572);

 __int64 __fastcall sub_14000D790(__int64 *a1, __int64 a2, size_t *a3, int *a4, __int64 a5)
{
  __int64 v9; // rdx
  __int64 v10; // rcx
  _BYTE v12[56]; // [rsp+38h] [rbp-60h] BYREF
  __int64 v13; // [rsp+70h] [rbp-28h]

  v13 = 0;
  std::_Func_class<void,SQEX::Ebony::Steering::Behaviors::InputBehavior *>::_Reset_move(this: v12, _Right: a5);
  sub_14000CB90(*a1, a2, a3, a4, v12);
  v10 = *(a5 + 56);
  if ( v10 )
  {
    LOBYTE(v9) = v10 != a5;
    (*(*v10 + 32LL))(v10, v9);
    *(a5 + 56) = 0;
  }
  return a2;
}

__int64 __fastcall sub_14000CB90(__int64 a1, __int64 a2, size_t *a3, int *a4, __int64 a5)
{
  void *v9; // rdx
  unsigned __int64 v10; // rax
  _BYTE *v11; // rdx
  __int64 v12; // rdx
  __int64 v13; // rdx
  __int64 v14; // rcx
  int *v16; // [rsp+30h] [rbp-498h] BYREF
  void *v17[4]; // [rsp+40h] [rbp-488h] BYREF
  void *v18[10]; // [rsp+60h] [rbp-468h] BYREF
  int v19; // [rsp+B0h] [rbp-418h] BYREF
  _BYTE v20[8]; // [rsp+B8h] [rbp-410h] BYREF
  unsigned __int64 v21; // [rsp+C0h] [rbp-408h]
  _BYTE v22[56]; // [rsp+3A0h] [rbp-128h] BYREF
  _BYTE *v23; // [rsp+3D8h] [rbp-F0h]
  __int64 v24; // [rsp+480h] [rbp-48h]

  sub_140005A10(v17);
  memmove_wrap_0(v17, Src: "GET", Size: 3u);
  if ( v18 != a3 )
  {
    v9 = a3;
    if ( a3[3] > 0xF )
      v9 = *a3;
    memmove_wrap_0(v18, Src: v9, Size: a3[2]);
  }
  if ( &v19 != a4 )
  {
    v16 = &v19;
    v19 = *a4;
    sub_140433580(v20, **(a4 + 1), *(a4 + 1));
    v10 = std::_Hash<std::_Umap_traits<std::wstring,std::wstring,std::_Uhash_compare<std::wstring,std::hash<std::wstring>,std::equal_to<std::wstring>>,std::allocator<std::pair<std::wstring const,std::wstring>>,0>>::_Desired_grow_bucket_count(
            this: &v19,
            _For_size: v21);
    sub_14042E590(&v19, v10);
  }
  if ( v22 != a5 )
  {
    if ( v23 )
    {
      v11 = v22;
      LOBYTE(v11) = v23 != v22;
      (*(*v23 + 32LL))(v23, v11);
      v23 = 0;
    }
    std::_Func_class<void,SQEX::Ebony::Steering::Behaviors::InputBehavior *>::_Reset_move(this: v22, _Right: a5);
  }
  if ( *(a1 + 520) > 0 )
    v24 = *sub_140001490(&v16);
  sub_140007BC0(a1, a2, v17);
  sub_140005D20(v17, v12);
  v14 = *(a5 + 56);
  if ( v14 )
  {
    LOBYTE(v13) = v14 != a5;
    (*(*v14 + 32LL))(v14, v13);
    *(a5 + 56) = 0;
  }
  return a2;
}
``` 
By creating my own server and mapping it to the required address locally, I was able to debug the program and see that this is the first request made to `/good`, which seems to implement some sort of authentication, as it is the only one having an `Authorization` header. Thinking that maybe the `Bearer` token is encrypted as shown above, I write a simple Python script for inverting the S-BOX and then decrypting by XORing with 0x5A. This works and yields us the following string: `2025082006TheBoss@THUNDERNODE`. So we know now the computer name as well, and we can get to decrypting the packets. Creating the key as the program shows (sha256("TheBoss@THUNDERNODE") XOR sha256("N/A06")) and then trying AES-256-CBC decryption on the data, yields nothing, so our key must be wrong somewhere. The "username@computername" and the hour seem to be correct (hour confirmed by the decoded bearer token), so that means that our "N/A" is wrong and something else modifies offset 192.

By checking for in IDA for "C0" (192 in hex), we get few references to it, but one shows some memory moving involving that offset, inside our `doAuth` function:

```C++
// write access to const memory has been detected, the output may be wrong!
void **__fastcall str_assign_at_192(__int64 a1, _QWORD *a2)
{
  _QWORD *v2; // r11
  void **result; // rax

  v2 = a2;
  dword_14047A3B0 = 1;
  dword_14047A3B4 = 5709;
  result = 0;
  dword_14047A3AC = 0;
  if ( (a1 + 192) != a2 )
  {
    if ( a2[3] > 0xFu )
      a2 = *a2;
    return memmove_wrap_0((a1 + 192), Src: a2, Size: v2[2]);
  }
  return result;
}
```

Tracing back the source variable, we get into some functions parsing JSONs and we eventually find that the buffer passed into those came from a decryption function, by using another S-BOX and XOR with a rolling key.

```C++
// write access to const memory has been detected, the output may be wrong!
__int64 __fastcall decrypt_first_buf(__int64 a1, _QWORD *a2, __int64 a3)
{
  v132 = a1;
  strcpy(v55, "p 4D@D");
  strcpy(v100, "\b\"(H\"08");
  v117[0] = 327044371;
  v117[1] = -603667322;
  HIBYTE(v55[1]) = -92;
  if ( v100[1] == 1494657834 )
  v72 = v98 | 0xF47B220F;
  ++v94;
  v97 -= 39496;
  v77 = v82 + 28845;
  if ( v100[0] >= -1321086845 )
    --v90;
  v92 = v89 * v84;
  v75 /= 44463;
  v61 ^= 0x3A003100u;
  v87 -= v98;
  v17 = v27 + 41231;
  v28 = 17464 * v27;
  v116 <<= 22;
  --v93;
  v42 = v121 + 2080373751;
  v73 = v57 >> 1;
  ++v59;
  v100[0] >>= 31;
  ++v99;
  if ( ++v89 == v58 )
  ++v66;
  v56 = v88 % 1744794077;
  v71 -= 11804;
  v13 = v119 % v84;
  v59 |= 0x10000938u;
  --v117[1];
  v69 /= v62;
  v78 ^= v113;
  v19 = 1202651139 * v101;
  v55[1] = v28 << v108;
  v20 = v66 | 1;
  if ( v65 == v71 )
    --v128;
  if ( v114 < v30 )
    ++v13;
  if ( v95 != v13 )
    ++v72;
  v31 = v30 + 60212;
  v53 = v110 / 27670;
  v50 = v31 + 65451;
  v62 *= -474259989;
  if ( v100[1] < v69 )
    ++v17;
  if ( v66 <= v95 )
    v42 = v121 + 2080373750;
  v16 = v17 ^ 0x3B881F8F;
  v57 -= 39450;
  v66 -= v55[0];
  v126 = v103 / v80;
  v75 *= 21971;
  v100[0] = 0;
  v33 = (v17 ^ 0x3B881F8F) >> 31;
  v55[0] = v72 | 0xE199;
  v73 >>= v98;
  v101 = v13 ^ 0x2CC4;
  if ( v53 > v79 )
  v85 = 64539 * v56;
  v40 = -782683929 << v63;
  v59 *= v67;
  v48 = v112 >> SLOBYTE(v55[1]);
  if ( v75 > 0 )
    ++v56;
  v58 += v79;
  if ( v55[1] == 795511444 )
  if ( v55[1] < v53 )
  v88 >>= 31;
  v36 = v35 >> 31;
  if ( v42 <= 0 )
  if ( v20 <= v50 )
  v90 ^= 0xF47B220F;
  v72 *= v89;
  if ( v104 > v71 )
    ++v59;
  v56 = 5803 * v64;
  --v123;
  v70 = v55[0] - 9033;
  v24 = (v62 + v49) | v82;
  if ( v66 < 1744794077 )
    ++v42;
  v76 = v83 % 53011;
  if ( v65 >= v62 )
    ++v112;
  v91 &= 0xFB61u;
  v81 = v63 >> v64;
  v46 = v45 >> 3;
  v67 = v55[1] / v25;
  if ( v50 >= v96 )
    --v13;
  if ( v100[1] >= 998776719 )
  v73 = v77 | 0x8B7F4070;
  ++v86;
  v92 >>= 31;
  if ( v19 == v114 )
    --v87;
  v102 = v61 << v68;
  v69 = v40 >> v86;
  v38 = v46 % v64;
  if ( v48 == v100[0] )
    ++v73;
  v32 = v31 - 1;
  v70 = v117[1] % 61336;
  if ( v97 < v69 )
  if ( v61 <= v80 )
    --v40;
  v57 = 9555 * v83;
  v87 &= v78;
  if ( v50 == v49 )
  v29 = v111 >> 31;
  if ( v24 != v15 )
  v94 = v13 ^ v84;
  v79 = v86 * v42;
  if ( v75 == -754651116 )
    --v32;
  v76 ^= v55[1];
  if ( v105 >= v78 )
    --v124;
  v64 = v48 * v116;
  if ( v16 != v36 )
  v81 += v127;
  v51 = v47 - 193256945;
  v71 = v19 - (v47 - 193256945);
  v65 >>= v74;
  if ( v37 <= v46 )
    ++v38;
  if ( v33 != 973091072 )
    --v40;
  v14 = v13 >> 31;
  v111 *= 34834;
  v94 = v127 | 0x6577;
  v58 >>= 31;
  v88 = v52 | v58;
  if ( v64 == v83 )
    ++v101;
  v54 = v16 % 38497;
  if ( v56 == v63 )
    --v47;
  if ( v98 != v15 )
    ++v70;
  v43 = v42 | 0xDE3D;
  v39 = -754651116 * v40;
  v72 += 1810;
  v98 = v64 & 0x9AD7;
  if ( v66 == v92 )
    ++v73;
  if ( v24 <= v92 )
    ++v70;
  v34 = v33 << v95;
  if ( v114 != v70 )
    --v121;
  v120 += v118;
  if ( v25 == v62 )
    --v96;
  if ( v77 < v47 )
    --v99;
  v26 = v25 | 0x572E;
  if ( v71 )
    v113 %= v71;
  if ( v43 < v117[0] )
    ++v102;
  if ( v19 == 7966828 )
    --v110;
  v76 /= 3917;
  v21 = v54 ^ v20;
  v96 = (v50 >> v38) + 25951;
  if ( v34 >= v29 )
  if ( v99 > v105 )
    --v58;
  if ( v93 )
    v39 = v47 % v93;
  dword_14047A3B4 = (v76 + v70 + v129)
                  & (v89 + v97)
                  & 0xB14197F9
                  & v96
                  & v32
                  ^ (v101 - 30796 + v53)
                  & (v56 + v95)
                  & v55[1]
                  | (v81 - v55[0] - 973091072 + 795511444 + v24)
                  & (v74 - (v54 + v111) - v19 + 7966828)
                  & v26
                  & v94
                  & (v17
                   ^ 0x3B88F537)
                  ^ v15
                  & v108
                  | (v80 - v73 - v117[1] - v79 + v49) ^ (v71 - v50) & v34 ^ (v41 - v93 - v92) ^ v62 ^ v72
                  | (v51 - v40 + v58) & v117[0] ^ ((v84 >> 31) - v110 - (v50 >> v38) + v57) ^ v119 ^ v109 ^ v125 ^ v118
                  | (v37 + 754651116) & (v115 + v78) & v107 & v52 & v67 ^ v68 & v91 ^ (v77 - v21)
                  | (v69 + v106 + v65) ^ (v66 - v116 - v38) ^ (v90 + 1651) ^ v59
                  | (v104 - v60 + v18) & (1557782271 - v85) & v100[0] ^ (v61 - v29) & v105 ^ 0x200
                  | (v100[1] + v85 + v47) & v82 ^ (v44 - v86) & v83 ^ v46
                  | (v111 + v126) ^ v124 & v101 ^ v123 ^ v63
                  | (v87 - v112) & v84 & v102
                  | (v43 - v103) ^ v98
                  | (v99 - v120) ^ v64
                  | (v14 + v121 + v88)
                  | v127 & v122
                  | v128 & v113
                  | v114 & v75
                  | (((v68 % 26737) >> v46) + v39);
  sub_1402CF340(a1);
  v117[1] = -2107705108;
  v100[1] = 18941200;
  v117[0] = -341973258;
  v55[1] = -76684286;
  v100[0] = -1;
  v55[0] = 0;
  dword_14047A3B4 = 93318681;
  dword_14047A3B0 = 1071644672;
  v6 = std::string::end(a3, v133);
  v7 = sub_1402CEEA0(a3, v134);
  sub_140431900(&v135, *v7, *v6, v130);
  v117[1] = 1610004619;
  v100[0] = -536872065;
  v55[0] = 644544255;
  v55[1] = 0x80000000;
  v117[0] = -1787662320;
  v100[1] = -1245;
  dword_14047A3B4 = -1;
  dword_14047A3AC = 0;
  dword_14047A3B0 = -721166;
  v9 = *(&v135 + 1) - v135;
  if ( a2[1] != *a2 )
  {
    do
    {
      v100[1] = -2137557681;
      qmemcpy(v117, "M{\"v*jdO", sizeof(v117));
      v96 = v117[0] >> 15;
      v55[1] = -272763241;
      v100[0] = -531039137;
      v55[0] = 0;
      if ( v117[1] <= 0 )
      v108 = v103 | 0xA96AAFD;
      v90 ^= 0x85C6u;
      v70 |= 0x5564u;
      v72 *= v83;
      v23 = v22 + 1;
      v100[1] = 0;
      if ( v23 )
        v118 %= v23;
      v116 *= v87;
      v94 |= 0x26C7u;
      v67 &= 0xEE37u;
      dword_14047A3B4 = -1;
      v10 = *(Block + *(*a2 + v8));
      v117[0] = -439871480;
      v100[0] = 16810024;
      v117[1] = -1523306433;
      v100[1] = 429953389;
      v55[1] = -272763241;
      v55[0] = 0;
      v111 %= -1097337376;
      dword_14047A3B4 = -1;
      v100[0] = -1924098806;
      v55[1] = -952037770;
      v100[1] = -447504320;
      v117[0] = 142485457;
      v117[1] = -14907;
      v55[0] = -169869441;
      dword_14047A3AC = -1;
      v11 = *(v8 % v9 + v135) ^ (-1 - v8 + v10);
      v117[1] = -1801760139;
      v100[1] = 0;
      v100[0] = 0;
      v55[1] = 134901619;
      v117[0] = -300548291;
      v55[0] = 0;
      dword_14047A3B4 = 0;
      sub_1402CEE00(a1, v11);
      ++v8;
    }
    while ( v8 < a2[1] - *a2 );
  }
  v100[0] = -545649123;
  v100[1] = 270566146;
  v117[1] = 2103594208;
  v117[0] = -1;
  v55[0] = -545669824;
  v55[1] = 2147483640;
  dword_14047A3B4 = -1;
  dword_14047A3B0 = 0;
  std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(&v135);
  return a1;
}

int prepare_Sbox()
{
  int v0; // ebx
  char *v1; // rdi
  unsigned __int8 *v2; // rdx
  __int64 v3; // rcx

  v0 = 0;
  new_mem(&Block, 0x100u);
  v1 = Block;
  memset(Block, Val: 0, Size: 0x100u);
  *&xmmword_14047A398 = v1 + 256;
  v2 = byte_14046A540;
  do
  {
    v3 = *v2++;
    *(Block + v3) = v0++;
  }
  while ( v0 < 256 );
  return atexit(CompoundTag::getByteArray_::_2_::_dynamic_atexit_destructor_for__dummy__);
}
```

Tracing back the values used there, we get that the decrypted buffer came from the request, so it is the JSON response for "GET /good", and that the rolling key is our "username@computername" string. Using a simple Python script to invert this S-BOX (same as before) and then decrypt it as they do there, we get the following JSON: `{"sta": "excellent", "ack": "peanut@theannualtraditionofstaringatdisassemblyforweeks.torealizetheflagwasjustxoredwiththefilenamethewholetime.com:8080"}`. Great, so now we have to analyze further to see what is extracted from this line, even though we can already guess it is `peanut`.
We can see that it builds the `@` symbol again, and does `strstr` for it, followed some time after by a `substr`, and the actual assign, confirming that our previous hunch was correct:
```C++
      memset(buf: &v77, value: 0, count: sizeof(v77));
      v2518 = sub_1400D3CE0(&v77);
      v2519 = sub_140286AB0(v2518);
      v2520 = std::string::string(v2550, v2519);
      v16 = sub_1402CEE40(v2520, 0);
      v2467 = strstr(Str, *v16, 0);
      ...
      v2521 = str_substr(Str, v2551, 0, v2467);
      v2522 = v2521;
      str_assign_at_192(a1, v2521);
```

So now, we have all the 3 required pieces to construct our AES key: `sha256("TheBoss@THUNDERNODE") XOR sha256("peanut06")`. This yields a working key and we now can decrypt all communications. Trying a few from various places by hand, I quickly learned that while decryption works for some buffers, it fails at others. By trying them sequentially, I eventually end up at a response after which no communications are decryptable, specifically: `{"msg": "cmd", "d": {"cid": 6, "dt": 20, "np": "TheBoss@THUNDERNODE"}}`. So that means we need to find the command handler and see what happens for that value. Looking in the calls after the call to `talk_to_c2` succeeds, we reach what seems to be a HTTP handler routine, where continuously parses requests, decrypts them, and eventually leads into the command handler:

```C++
// write access to const memory has been detected, the output may be wrong!
void __fastcall cmd_handler(__int64 **a1, __int64 a2, __int64 a3)
{
  *&v10792 = 0x706050403020100LL;
  *(&v10792 + 1) = 0xF0E0D0C0B0A0908LL;
  dword_14047A3B4 = 0;
  memset_zero(v10775, 0x18u);
  memset(buf: &v85, value: 0, count: sizeof(v85));
  v3 = sub_1401FE490(&v85);
  v4 = sub_140260370(v3);
  v10610 = std::string::string(a1: v10726, a2: v4);
  v10611 = v10610;
  v5 = sub_1402B3F50(a3, v10610);
  str_assign_0(a1: v5, a2: &v10727);
  sub_140066A60(a1: v10775, a2: &v10727);
  `std::locale::global'::`1'::dtor$2(&v10727);
  `std::locale::global'::`1'::dtor$2(v10726);
  dword_14047A3AC = -1;
  Time = time64(Time: 0);
  dword_14047A3AC = 0;
  dword_14047A3B0 = 1096810496;
  gmtime64_s(Tm: &Tm, Time: &Time);
  dword_14047A3AC = 0;
  dword_14047A3B0 = -721166;
  dword_14047A3B4 = -1;
  memset(buf: &v86, value: 0, count: sizeof(v86));
  v6 = sub_1401FE4F0(&v86);
  v7 = sub_14025E4B0(v6);
  strftime(Buffer: Buffer, SizeInBytes: 3u, Format: v7, Tm: &Tm);
  dword_14047A3B4 = -1;
  std::string::string(a1: &v10776, a2: Buffer);
  dword_14047A3B4 = -1;
  memset_zero(v10774, 0x18u);
  v10613 = sub_140037090(a2, v10729);
  v10614 = v10613;
  v10615 = sub_140037060(a2, v10730);
  v10616 = v10615;
  sha256_xor_pair(out32: v10774, s1: v10615, extra: v10614, s2: &v10776);
  `std::locale::global'::`1'::dtor$2(v10730);
  `std::locale::global'::`1'::dtor$2(v10729);
  dword_14047A3B0 = 3224512;
  dword_14047A3AC = -1;
  dword_14047A3B4 = -1;
  v8 = mov_rax_rcx(v10774);
  aes256_init_ctx(aesCtxOut: &v10789, KeyVect: v8, FeedbackVect: &v10792);
  dword_14047A3AC = -1;
  v10617 = mov_and_sub_rax_rcx(v10775);
  v9 = mov_rax_rcx(v10775);
  aes256weird_cbc_encrypt(aesContext: &v10789, buf: v9, len: v10617);
  dword_14047A3B4 = 0;
  sub_140076F60(&v10783, v10775);
  dword_14047A3B0 = 38531;
  dword_14047A3B4 = -45170;
  dword_14047A3AC = -2;
  nlohmann::basic_json<std::map,std::vector,std::string,bool,__int64,unsigned __int64,double,std::allocator,nlohmann::adl_serializer,std::vector<unsigned char>>::basic_json<std::map,std::vector,std::string,bool,__int64,unsigned __int64,double,std::allocator,nlohmann::adl_serializer,std::vector<unsigned char>>(
    this: &v10772.size_or_meta,
    __formal: 0);
  if ( __eh34_try(-1, 0) )
  {
    __eh34_scope_strut(0);
    dword_14047A3B4 = 0;
    dword_14047A3B0 = 0;
    v10618 = &v10694;
    v10619 = v10760;
    v10620 = sub_1402B3BE0(v10760);
    v10621 = json_parse_into(jsonDomOut: v10618, in: &v10783, ctx: v10620, allow_comments: 1u, allow_trailing: 0);
    v10622 = v10621;
    sub_1402B43A0(&v10772.size_or_meta, v10621);
  }
  if ( __eh34_catch(0) )
  {
    if ( __eh34_catch_type(0, &nlohmann::json_abi_v3_12_0::detail::parse_error `RTTI Type Descriptor', &v10793) )
    {
      dword_14047A3B0 = 38531;
      dword_14047A3B4 = -45170;
      dword_14047A3AC = -2;
      __eh34_try_continuation(
        0,
        &nlohmann::json_abi_v3_12_0::detail::parse_error `RTTI Type Descriptor',
        &loc_14016C95B);
      goto LABEL_129;
    }
  }
  memset(buf: &v87, value: 0, count: sizeof(v87));
  v10 = sub_1401FE550(&v87);
  v11 = sub_14025C5F0(v10);
  v10623 = std::string::string(a1: v10732, a2: v11);
  v10624 = v10623;
  v116 |= 1u;
  if ( !json_object_contains(jsonDom: &v10772.size_or_meta, key: v10623) )
    goto LABEL_5;
  memset(buf: &v88, value: 0, count: sizeof(v88));
  v12 = sub_1401FE610(&v88);
  v13 = sub_14025C5F0(v12);
  v10625 = std::string::string(a1: v10733, a2: v13);
  v10626 = v10625;
  v116 |= 2u;
  sub_140431BD0(v10695, v10625);
  v116 |= 4u;
  v10627 = &v10734;
  memset(buf: &v89, value: 0, count: sizeof(v89));
  v14 = sub_1401FE5B0(&v89);
  v15 = sub_14025C5F0(v14);
  v10628 = std::string::string(a1: v10627, a2: v15);
  v16 = json_object_ref(jsonDom: &v10772.size_or_meta, key: v10628);
  if ( sub_1402B3BF0(v16, v10695) )
  else
LABEL_5:
  v90 = v3160;
  if ( (v116 & 4) != 0 )
  {
    v116 &= ~4u;
    sub_14012C680(v10695);
  }
  if ( (v116 & 2) != 0 )
  {
    v116 &= ~2u;
    `std::locale::global'::`1'::dtor$2(v10733);
  }
  if ( (v116 & 1) != 0 )
  {
    v116 &= ~1u;
    `std::locale::global'::`1'::dtor$2(v10732);
  }
  if ( v90 )
  {
    dword_14047A3B0 = 1;
    dword_14047A3B4 = 5709;
    dword_14047A3AC = 0;
    v10629 = &v10735;
    memset(buf: &v91, value: 0, count: sizeof(v91));
    v17 = sub_1401FE670(&v91, 0);
    v18 = sub_14025A730(v17);
    v10630 = std::string::string(a1: v10629, a2: v18);
    v19 = json_object_ref(jsonDom: &v10772.size_or_meta, key: v10630);
    sub_1402B43E0(&v10772, v19);
    dword_14047A3B4 = 0;
    v10609 = &v10736;
    memset(buf: &v92, value: 0, count: sizeof(v92));
    v20 = sub_1401FE6D0(&v92);
    v21 = sub_140258870(v20);
    v10632 = std::string::string(a1: v10609, a2: v21);
    v22 = json_object_ref(jsonDom: &v10772, key: v10632);
    v3500 = sub_140431C80(v22);
    v3501 = v3500;
    switch ( v3500 )
    {
      case 2:
        memset(buf: &v93, value: 0, count: sizeof(v93));
        v23 = sub_1401FE730(&v93);
        v24 = sub_1402569B0(v23);
        v10633 = std::string::string(a1: v10737, a2: v24);
        v10634 = v10633;
        v116 |= 8u;
        v3502 = json_object_contains(jsonDom: &v10772, key: v10633)
             && (v10635 = &v10738,
                 memset(buf: &v94, value: 0, count: sizeof(v94)),
                 v25 = sub_1401FE790(&v94),
                 v26 = sub_1402569B0(v25),
                 v10636 = std::string::string(a1: v10635, a2: v26),
                 v27 = json_object_ref(jsonDom: &v10772, key: v10636),
                 !sub_1402B40D0(v27));
        v95 = v3502;
        if ( (v116 & 8) != 0 )
        {
          v116 &= ~8u;
          `std::locale::global'::`1'::dtor$2(v10737);
        }
        if ( v95 )
        {
          dword_14047A3B4 = -1;
          v10637 = &v10739;
          memset(buf: &v96, value: 0, count: sizeof(v96));
          v28 = sub_1401FE7F0(&v96);
          v29 = sub_140254AF0(v28);
          v10638 = std::string::string(a1: v10637, a2: v29);
          v30 = json_object_ref(jsonDom: &v10772, key: v10638);
          str_assign_0(a1: v30, a2: v10777);
          dword_14047A3B4 = -1;
          memset(buf: &v97, value: 0, count: sizeof(v97));
          v31 = sub_1401FE850(&v97);
          v32 = sub_140252C30(v31);
          v10639 = std::string::string(a1: v10741, a2: v32);
          v10640 = v10639;
          std::operator+<char>(result: v10782, _Left: v10639, _Right: v10777);
          `std::locale::global'::`1'::dtor$2(v10741);
          dword_14047A3B4 = -1;
          v33 = sub_1402CEDD0(v10782);
          sub_1401FEFB0(v10781, v33);
          memset(buf: &v98, value: 0, count: sizeof(v98));
          v34 = sub_1401FE8C0(&v98);
          v35 = sub_140250D70(v34);
          v10641 = std::string::string(a1: v10744, a2: v35);
          v10642 = v10641;
          sub_140431C60(v10748, v10641);
          sub_140431D80(v10749, v10781);
          qmemcpy(dst: v10698, src: unknown_libname_29(v10697, v10748, v10750), count: sizeof(v10698));
          sub_140279330(v10712, v10698);
          qmemcpy(dst: v10700, src: unknown_libname_29(v10699, v10712, v10713), count: sizeof(v10700));
          LOBYTE(v36) = 2;
          LOBYTE(v37) = 1;
          sub_1402B4740(v10769, v10700, v37, v36);
          `eh vector destructor iterator'(v10712, 0x18u, 1u, sub_14012C680);
          `eh vector destructor iterator'(v10748, 0x18u, 2u, sub_14012C680);
          `std::locale::global'::`1'::dtor$2(v10744);
          dword_14047A3B0 = 1;
          dword_14047A3B4 = 5709;
          dword_14047A3AC = 0;
          sub_1402B40E0(v10769, v10780, -1, 32, 0, 0);
          dword_14047A3AC = -1;
          dword_14047A3B4 = 93318681;
          dword_14047A3B0 = 1071644672;
          memset_zero(v10773, 0x18u);
          sub_140076E40(v10773, v10780);
          dword_14047A3AC = -1;
          dword_14047A3B0 = -1;
          dword_14047A3B4 = -1;
          v38 = mov_rax_rcx(v10774);
          aes256_init_ctx(aesCtxOut: &v10790, KeyVect: v38, FeedbackVect: &v10792);
          dword_14047A3B4 = -1;
          v10643 = mov_and_sub_rax_rcx(v10773);
          v39 = mov_rax_rcx(v10773);
          aes256cbc_encrypt(ctx: &v10790, buf: v39, len: v10643);
          memset(buf: &v99, value: 0, count: sizeof(v99));
          v40 = sub_1401FE920(&v99);
          v41 = sub_14024EEB0(v40);
          v10644 = std::string::string(a1: v10746, a2: v41);
          v10645 = v10644;
          sub_140431C60(v10750, v10644);
          v10646 = mov_and_sub_rax_rcx(v10773);
          v42 = mov_rax_rcx(v10773);
          v10647 = format_hex(a1: v10747, a2: v42, a3: v10646);
          v10648 = v10647;
          sub_140431C60(v10751, v10647);
          qmemcpy(dst: v10702, src: unknown_libname_29(v10701, v10750, v10752), count: sizeof(v10702));
          sub_140279330(v10711, v10702);
          qmemcpy(dst: v10704, src: unknown_libname_29(v10703, v10711, v10712), count: sizeof(v10704));
          LOBYTE(v43) = 2;
          LOBYTE(v44) = 1;
          sub_1402B4740(v10771, v10704, v44, v43);
          `eh vector destructor iterator'(v10711, 0x18u, 1u, sub_14012C680);
          `eh vector destructor iterator'(v10750, 0x18u, 2u, sub_14012C680);
          `std::locale::global'::`1'::dtor$2(v10747);
          `std::locale::global'::`1'::dtor$2(v10746);
          dword_14047A3B0 = -1;
          v10649 = v10761;
          memset(buf: &v100, value: 0, count: sizeof(v100));
          memset(buf: &v101, value: 0, count: sizeof(v101));
          v10650 = sub_1402B3BE0(v10761);
          v10651 = v10650;
          v45 = sub_1401FE9E0(&v100);
          v46 = sub_14024B130(v45);
          v10652 = std::string::string(a1: v10723, a2: v46);
          v10631 = v10652;
          v10654 = sub_1402B40E0(v10771, v10740, -1, 32, 0, 0);
          v10655 = v10654;
          v47 = sub_1401FE980(&v101);
          v48 = sub_14024CFF0(v47);
          v10656 = std::string::string(a1: v10745, a2: v48);
          v10657 = v10656;
          sub_14000D820(a1, v10763, v10656, v10655, v10631, v10651);
          sub_140007B70(v10763);
          `std::locale::global'::`1'::dtor$2(v10745);
          `std::locale::global'::`1'::dtor$2(v10740);
          `std::locale::global'::`1'::dtor$2(v10723);
          sub_14012C680(v10771);
          std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(v10773);
          `std::locale::global'::`1'::dtor$2(v10780);
          sub_14012C680(v10769);
          `std::locale::global'::`1'::dtor$2(v10781);
          `std::locale::global'::`1'::dtor$2(v10782);
          `std::locale::global'::`1'::dtor$2(v10777);
        }
        dword_14047A3B4 = -1;
        break;
      case 3:
        dword_14047A3B4 = -1;
        dword_14047A3AC = -1;
        exit(Code: 0);
      case 5:
        memset(buf: &v102, value: 0, count: sizeof(v102));
        v49 = sub_1401FEA70(&v102);
        v50 = sub_140249270(v49);
        v10658 = std::string::string(a1: v10743, a2: v50);
        v10659 = v10658;
        v116 |= 0x10u;
        v5524 = json_object_contains(jsonDom: &v10772, key: v10658)
             && (v10660 = &v10742,
                 memset(buf: &v103, value: 0, count: sizeof(v103)),
                 v51 = sub_1401FEAD0(&v103),
                 v52 = sub_140249270(v51),
                 v10661 = std::string::string(a1: v10660, a2: v52),
                 v53 = json_object_ref(jsonDom: &v10772, key: v10661),
                 !sub_1402B40D0(v53));
        v104 = v5524;
        if ( (v116 & 0x10) != 0 )
        {
          v116 &= ~0x10u;
          `std::locale::global'::`1'::dtor$2(v10743);
        }
        if ( v104 )
        {
          dword_14047A3B0 = -1;
          v10662 = &v10731;
          memset(buf: &v105, value: 0, count: sizeof(v105));
          v54 = sub_1401FEB30(&v105);
          v55 = sub_1402473B0(v54);
          v10663 = std::string::string(a1: v10662, a2: v55);
          v56 = json_object_ref(jsonDom: &v10772, key: v10663);
          str_assign_0(a1: v56, a2: v10784);
          dword_14047A3B4 = -1;
          dword_14047A3AC = 0;
          dword_14047A3B0 = -721166;
          memset_zero(v10765, 0x110u);
          sub_1402B3B90(v10765, v10784, 32, 64, 1);
          dword_14047A3B4 = -1;
          sub_1402CF340(a1: v10785);
          dword_14047A3AC = -1;
          dword_14047A3B0 = 0;
          sub_1402CF340(a1: v10786);
          if ( std::ios_base::operator bool(v10765 + *(v10765[0] + 4LL)) )
          {
            dword_14047A3B4 = -1;
            memset_zero(v10788, 0xE8u);
            std::ostringstream::ostringstream(this: v10788, 1);
            dword_14047A3B4 = -1;
            srw_lock = get_srw_lock(v10765);
            std::ostream::operator<<(v10788, srw_lock);
            dword_14047A3B4 = -1;
            v10664 = sub_1402CE1B0(v10788, v10728);
            move_to_off(v10785, v10664);
            `std::locale::global'::`1'::dtor$2(v10728);
            dword_14047A3B4 = 93318681;
            dword_14047A3B0 = 1071644672;
            memset(buf: &v106, value: 0, count: sizeof(v106));
            v58 = sub_1401FEB90(&v106);
            v59 = sub_1402454F0(v58);
            v10665 = std::string::string(a1: v10722, a2: v59);
            move_to_off(v10786, v10665);
            `std::locale::global'::`1'::dtor$2(v10722);
            std::ostringstream::`vbase destructor'(v10788);
          }
          else
          {
            dword_14047A3AC = -1;
            memset(buf: &v107, value: 0, count: sizeof(v107));
            v60 = sub_1401FEC00(&v107);
            v61 = sub_140243630(v60);
            v10666 = std::string::string(a1: v10725, a2: v61);
            move_to_off(v10786, v10666);
            `std::locale::global'::`1'::dtor$2(v10725);
          }
          dword_14047A3B4 = -1;
          sub_1402B3B40(v10765);
          memset(buf: &v108, value: 0, count: sizeof(v108));
          v62 = sub_1401FEC70(&v108);
          v63 = sub_140241770(v62);
          v10667 = std::string::string(a1: v10724, a2: v63);
          v10668 = v10667;
          sub_140431C60(v10752, v10667);
          sub_140431D80(v10753, v10786);
          qmemcpy(dst: v10706, src: unknown_libname_29(v10705, v10752, v10754), count: sizeof(v10706));
          sub_140279330(v10754, v10706);
          memset(buf: &v109, value: 0, count: sizeof(v109));
          v64 = sub_1401FECD0(&v109);
          v65 = sub_14023F8B0(v64);
          v10669 = std::string::string(a1: v10718, a2: v65);
          v10670 = v10669;
          sub_140431C60(v10756, v10669);
          v10671 = sub_14003D5A0(v10721, v10785);
          v10672 = v10671;
          sub_140431C60(v10757, v10671);
          qmemcpy(dst: v10708, src: unknown_libname_29(v10707, v10756, v10758), count: sizeof(v10708));
          sub_140279330(v10755, v10708);
          qmemcpy(dst: v10690, src: unknown_libname_29(v10709, v10754, v10756), count: sizeof(v10690));
          LOBYTE(v66) = 2;
          LOBYTE(v67) = 1;
          sub_1402B4740(v10770, v10690, v67, v66);
          `eh vector destructor iterator'(v10754, 0x18u, 2u, sub_14012C680);
          `eh vector destructor iterator'(v10756, 0x18u, 2u, sub_14012C680);
          `std::locale::global'::`1'::dtor$2(v10721);
          `std::locale::global'::`1'::dtor$2(v10718);
          `eh vector destructor iterator'(v10752, 0x18u, 2u, sub_14012C680);
          `std::locale::global'::`1'::dtor$2(v10724);
          dword_14047A3B4 = -1;
          dword_14047A3AC = 0;
          dword_14047A3B0 = -721166;
          sub_1402B40E0(v10770, v10778, -1, 32, 0, 0);
          dword_14047A3B4 = -1;
          memset_zero(&v10772.scratch[1], 0x18u);
          sub_140076E40(&v10772.scratch[1], v10778);
          dword_14047A3AC = -1;
          dword_14047A3B4 = 0;
          dword_14047A3B0 = 0;
          v68 = mov_rax_rcx(v10774);
          aes256_init_ctx(aesCtxOut: &v10791, KeyVect: v68, FeedbackVect: &v10792);
          dword_14047A3AC = -1;
          v10673 = mov_and_sub_rax_rcx(&v10772.scratch[1]);
          v69 = mov_rax_rcx(&v10772.scratch[1]);
          aes256cbc_encrypt(ctx: &v10791, buf: v69, len: v10673);
          memset(buf: &v110, value: 0, count: sizeof(v110));
          v70 = sub_1401FED30(&v110);
          v71 = sub_14023D9F0(v70);
          v10674 = std::string::string(a1: v10720, a2: v71);
          v10675 = v10674;
          sub_140431C60(v10758, v10674);
          v10676 = mov_and_sub_rax_rcx(&v10772.scratch[1]);
          v72 = mov_rax_rcx(&v10772.scratch[1]);
          v10677 = format_hex(a1: v10719, a2: v72, a3: v10676);
          v10678 = v10677;
          sub_140431C60(v10759, v10677);
          qmemcpy(dst: v10692, src: unknown_libname_29(v10691, v10758, v10760), count: sizeof(v10692));
          sub_140279330(v10710, v10692);
          qmemcpy(dst: v10696, src: unknown_libname_29(v10693, v10710, v10711), count: sizeof(v10696));
          LOBYTE(v73) = 2;
          LOBYTE(v74) = 1;
          sub_1402B4740(v10768, v10696, v74, v73);
          `eh vector destructor iterator'(v10710, 0x18u, 1u, sub_14012C680);
          `eh vector destructor iterator'(v10758, 0x18u, 2u, sub_14012C680);
          `std::locale::global'::`1'::dtor$2(v10719);
          `std::locale::global'::`1'::dtor$2(v10720);
          dword_14047A3B0 = 38531;
          dword_14047A3B4 = -45170;
          dword_14047A3AC = -2;
          v10679 = v10762;
          memset(buf: &v111, value: 0, count: sizeof(v111));
          memset(buf: &v112, value: 0, count: sizeof(v112));
          v10680 = sub_1402B3BE0(v10762);
          v10681 = v10680;
          v75 = sub_1401FEDF0(&v111);
          v76 = sub_140239C70(v75);
          v10682 = std::string::string(a1: v10713, a2: v76);
          v10683 = v10682;
          v10684 = sub_1402B40E0(v10768, v10717, -1, 32, 0, 0);
          v10685 = v10684;
          v77 = sub_1401FED90(&v112);
          v78 = sub_14023BB30(v77);
          v10686 = std::string::string(a1: v10716, a2: v78);
          v10687 = v10686;
          sub_14000D820(a1, v10764, v10686, v10685, v10683, v10681);
          sub_140007B70(v10764);
          `std::locale::global'::`1'::dtor$2(v10716);
          `std::locale::global'::`1'::dtor$2(v10717);
          `std::locale::global'::`1'::dtor$2(v10713);
          sub_14012C680(v10768);
          std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(&v10772.scratch[1]);
          `std::locale::global'::`1'::dtor$2(v10778);
          sub_14012C680(v10770);
          `std::locale::global'::`1'::dtor$2(v10786);
          `std::locale::global'::`1'::dtor$2(v10785);
          std::ifstream::`vbase destructor'(this: v10765);
          `std::locale::global'::`1'::dtor$2(v10784);
        }
        dword_14047A3B4 = -1;
        break;
      case 6:
        dword_14047A3B4 = 0;
        v10688 = &v10715;
        memset(buf: &v113, value: 0, count: sizeof(v113));
        v79 = sub_1401FEE80(&v113);
        v80 = sub_140237DB0(v79);
        v10689 = std::string::string(a1: v10688, a2: v80);
        v81 = json_object_ref(jsonDom: &v10772, key: v10689);
        v9247 = sub_140431C80(v81);
        dword_14047A3B4 = -1;
        Sleep(dwMilliseconds: 1000 * v9247);
        dword_14047A3AC = -1;
        v10612 = &v10714;
        memset(buf: v114, value: 0, count: 1u);
        v82 = sub_1401FEEE0(v114);
        v83 = sub_140235EF0(v82);               // np
        v10653 = std::string::string(a1: v10612, a2: v83);
        v84 = json_object_ref(jsonDom: &v10772, key: v10653);
        str_assign_0(a1: v84, a2: v10779);
        dword_14047A3AC = -1;
        str_assign_at_192(a1: a2, a2: v10779);
        dword_14047A3B4 = -1;
        dword_14047A3B0 = 3224512;
        `std::locale::global'::`1'::dtor$2(v10779);
        break;
      default:
        v10288 = v10292 | v10345;
        if ( (v10292 | v10345) <= v10396 )
          --v10297;
        v10376 = v10340 & v10352;
        --v10333;
        v10313 = v10375 / 9503;
        ++v10338;
        v10364 |= v10315;
        v10338 |= 0xE904u;
        ++v10297;
        --v10331;
        v10360 = v10324 ^ v10359;
        v10354 = v10323 + v10369;
        v10382 = v10308 + 49638;
        v10413 = v10390;
        v10332 = v10350 % v10390;
        v10400 -= 6706;
        v10414 = v10371;
        v10381 = v10371 >> v10304;
        if ( v10331 < v10336 )
          ++v10322;
        v10415 = v10395;
        v10395 <<= v10292;
        if ( v10338 < v10332 )
          --v10355;
        if ( v10288 <= v10337 )
          ++v10387;
        if ( v10394 < v10360 )
          ++v10333;
        if ( v10355 < v10351 )
          ++v10293;
        v10298 = v10392 & v10386;
        v10317 = v10346 + v10390;
        if ( v10359 != v10387 )
          ++v10301;
        --v10343;
        v10349 = 31588 * v10385;
        v10380 += v10326;
        v10416 = v10296;
        v10321 = v10287 / v10296;
        v10417 = v10296;
        v10360 = v10296 % v10296;
        v10335 = v10393 % 53498;
        v10287 &= v10337;
        v10293 ^= v10312;
        v10418 = v10342;
        v10398 /= v10342;
        v10379 = v10353 + 26151;
        v10366 -= 38275;
        v10330 = v10354 / 5357;
        v10341 = v10336 ^ v10334++;
        v10332 = v10320 - v10343;
        if ( v10344 > v10354 )
          --v10285;
        v10399 *= 53045;
        if ( v10348 == v10332 )
          --v10317;
        if ( v10362 < v10395 )
          ++v10305;
        v10376 = v10288 + 4315;
        --v10303;
        v10366 &= 0xF37Du;
        v10403 *= v10389;
        v10381 += v10356;
        if ( v10360 >= v10287 )
          ++v10339;
        v10419 = v10299;
        v10393 = v10299 >> v10307;
        v10313 /= 3100;
        v10420 = v10329;
        v10329 >>= v10330;
        if ( v10362 > v10354 )
          --v10306;
        if ( v10338 < v10335 )
          ++v10288;
        v10381 = v10298 << 21;
        v10403 -= v10347;
        if ( v10382 )
        {
          v10421 = v10382;
          v10355 %= v10382;
        }
        v10329 -= 41816;
        v10422 = v10286;
        v10352 = v10286 >> v10403;
        v10334 += v10319;
        v10305 = v10339 & 0x1EB;
        v10348 = v10292 + 34183;
        v10302 = v10370 & 0x8DFE;
        v10390 += v10302;
        v10423 = v10321;
        v10321 <<= v10287;
        if ( v10347 <= v10292 + 34183 )
          --v10324;
        v10365 += 23285;
        if ( v10348 > v10378 )
          --v10339;
        v10396 |= v10365;
        v10367 = v10381 ^ v10334;
        v10318 = 59734 * v10300;
        v10327 = v10298 % 58382;
        if ( 59734 * v10300 < v10336 )
          ++v10320;
        v10382 *= 10513;
        v10303 = v10321 - v10330;
        if ( v10375 >= v10298 )
          --v10375;
        if ( v10322 )
        {
          v10424 = v10322;
          v10351 = v10318 % v10322;
        }
        v10321 ^= v10377;
        if ( v10285 )
        {
          v10425 = v10285;
          v10311 %= v10285;
        }
        v10403 &= 0xE2F1u;
        v10322 = 32475 * v10350;
        --v10292;
        if ( v10399 >= v10374 )
          --v10287;
        if ( v10333 <= v10367 )
          --v10373;
        if ( v10339 )
        {
          v10426 = v10339;
          v10321 %= v10339;
        }
        v10301 = v10364 / 59881;
        ++v10320;
        if ( v10385 == v10399 )
          ++v10373;
        v10384 = v10309 / 10824;
        if ( v10306 >= v10378 )
          ++v10352;
        if ( v10312 >= v10293 )
          --v10367;
        if ( v10355 )
        {
          v10427 = v10355;
          v10338 = v10302 / v10355;
        }
        --v10290;
        v10388 = v10395 & v10399;
        v10384 = v10379 / 43239;
        v10368 = 42816 * v10371;
        v10305 >>= 6;
        v10286 |= 0x3700u;
        v10374 = v10292 | v10319;
        if ( v10400 < v10345 )
          --v10339;
        if ( v10365 > v10339 )
          ++v10297;
        v10374 = v10326 + v10347;
        --v10311;
        if ( v10322 >= v10382 )
          ++v10319;
        v10400 |= 0xE439u;
        v10303 = v10331 - v10302;
        v10314 |= 0x1356u;
        if ( v10337 == v10293 )
          ++v10352;
        v10428 = v10340;
        v10348 /= v10340;
        v10403 >>= 17;
        v10361 = v10360 % 25852;
        if ( v10301 < v10324 )
          --v10379;
        v10389 = v10378 % 53171;
        if ( v10348 )
        {
          v10429 = v10348;
          v10325 = v10329 % v10348;
        }
        v10383 &= 0x7C2Du;
        v10430 = v10285;
        v10367 = v10285 << v10311;
        ++v10312;
        --v10322;
        if ( v10383 != v10318 )
          --v10308;
        if ( v10390 <= v10286 )
          --v10403;
        if ( v10348 >= v10347 )
          --v10388;
        if ( v10393 > v10288 )
          --v10377;
        v10382 /= 52075;
        v10324 -= v10361;
        v10431 = v10383;
        v10432 = v10383 << v10383;
        v10367 = v10383 << v10383 >> v10340;
        v10393 += v10341;
        v10361 <<= 30;
        if ( v10363 <= v10312 )
          ++v10311;
        if ( v10333 != v10384 )
          ++v10298;
        v10356 = v10357 | 0x85EB;
        v10358 = v10318 / 35938;
        if ( v10339 )
        {
          v10433 = v10339;
          v10338 %= v10339;
        }
        if ( v10365 >= v10349 )
          --v10350;
        v10366 = v10353 & 0xAAF6;
        v10376 ^= 0xDD7Bu;
        v10337 = v10317 & 0xD211;
        v10339 |= 0xD3CDu;
        if ( v10285 > v10307 )
          --v10331;
        if ( v10349 != v10374 )
          --v10319;
        v10349 += v10370;
        v10318 = v10383 >> 6;
        v10347 = v10338 + 3389;
        v10380 /= 43155;
        v10342 |= v10312;
        v10434 = v10403 ^ (v10401 - v10402) ^ (v10399 - v10400) & (v10397 - v10398);
        v10435 = (v10396 + v10395) ^ v10394 ^ v10393;
        v10436 = v10392 ^ v10391;
        v10437 = v10390 + v10389;
        v10438 = v10388 & (v10387 + v10386 + v10384 - v10385) & v10383 ^ v10382;
        v10439 = v10381 & v10380;
        v10440 = v10379 ^ v10378 ^ v10377 ^ (v10376 + v10375 + v10374);
        v10441 = v10373 ^ v10372;
        v10442 = v10371 ^ v10370;
        v10443 = (v10369 + v10368) & v10367 & v10366 & (v10365 + v10364 + v10363 + v10362);
        v10444 = v10361 + v10360 + v10359 + v10358 + v10357;
        v10445 = v10356
               & v10355
               ^ v10354
               ^ v10353
               & v10352
               & (v10351 + v10349 + v10348 + v10338 + 3389 - v10350)
               & v10346
               & v10345
               ^ v10344
               & v10343
               ^ v10342
               & v10341;
        v10446 = v10340 ^ v10339 ^ (v10338 + v10337) ^ (v10336 + v10335) & v10334;
        v10447 = v10333
               ^ (v10332 + v10331)
               & (v10328 - v10329 - v10330)
               & v10327
               ^ v10326
               & v10325
               & v10324
               & (v10322 - v10323)
               ^ v10321
               & v10320
               & (v10319 + (v10383 >> 6) + v10317);
        dword_14047A3B0 = v10434
                        | v10435
                        | v10392 ^ v10391
                        | (v10390 + v10389)
                        | v10438
                        | v10381 & v10380
                        | v10440
                        | v10373 ^ v10372
                        | v10371 ^ v10370
                        | v10443
                        | v10444
                        | v10445
                        | v10446
                        | v10447
                        | v10316 & (v10315 + v10314) & v10313 ^ v10312
                        | v10311 & v10310 ^ v10309
                        | (v10308 + v10307)
                        | v10306 & v10305
                        | v10304
                        | (v10303 + v10302)
                        | (v10300 - v10301)
                        | (v10298 - v10299)
                        | v10297
                        | (v10296 + v10295) ^ v10294 & (v10292 + v10291 - v10293)
                        | v10290 & v10289 ^ v10288 & v10287
                        | v10286 ^ v10285 & v10284;
        dword_14047A3B4 = -1;
        break;
    }
    sub_14012C680(&v10772.type);
  }
LABEL_129:
  sub_14012C680(&v10772.size_or_meta);
  `std::locale::global'::`1'::dtor$2(&v10783);
  std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(v10774);
  `std::locale::global'::`1'::dtor$2(&v10776);
  std::vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>::~vector<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition,std::allocator<enum ScriptModuleMinecraft::IScriptConditionalEventSignal<ScriptModuleMinecraft::ScriptActorDieAfterEvent,0>::ClosureCondition>>(v10775);
}
```

If we skim through the deobufscation, we can see that it gets the "np" key from the decoded JSON and sets it at offset 192, so that's our now second part of the key. Updating the script to look for new parts to the key and rebuild it every time, yields a working script which decrypts all communications.

```Python
from dpkt.tcp import TCP
from Crypto.Cipher import AES
from hashlib import sha256
import dpkt, json, sys

at_first = False
aes_key = b""
part1 = ""
part2 = ""
INV_SBOX = bytes([
0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
])

SBOX = [0]*256 # invert sbox
for i, v in enumerate(INV_SBOX):
    SBOX[v] = i

def decode_bearer(bearer_hex):
    bearer = bytes.fromhex(bearer_hex)
    out = []
    sbox = SBOX
    sbox_len = len(sbox)
    for i, b in enumerate(bearer):
        k = SBOX[b]
        raw = (k - (i + 1)) & 0xFF
        src_byte = raw ^ 0x5A
        out.append(src_byte)
    return bytes(out)

def decode_first_packet(cipher_hex, key_ascii):
    c = bytes.fromhex(cipher_hex)
    k = key_ascii.encode()
    out = bytearray()
    for i, b in enumerate(c):
        t  = SBOX[b]
        bb = (t - (i+1)) & 0xFF
        pt = bb ^ k[i % len(k)]
        out.append(pt)
    return bytes(out)


def derive_key(key_part1, key_part2, key_part3 = "06"):
    p1 = sha256()
    p1.update(key_part1.encode())
    h1 = bytes.fromhex(p1.hexdigest())
    p2 = sha256()
    p2.update((key_part2 + key_part3).encode())
    h2 = bytes.fromhex(p2.hexdigest())
    return bytes([h1[i] ^ h2[i] for i in range(len(h1))])


def aes_cbc_decrypt_hex(ct_hex, key):
    iv = bytes(range(16))  # 00..0f
    ct = bytes.fromhex(ct_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and all(x == pad for x in pt[-pad:]):
        pt = pt[:-pad]
    return pt

def process_pcap(path):
    global part1, part2, aes_key, at_first
    with open(path, "rb") as f:
        pcap = dpkt.pcapng.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip.data, TCP):
                    continue
                tcp: TCP = ip.data
                if not tcp.data:
                    continue
                data = tcp.data.decode()
                if "GET /good" in data:
                    at_first = True
                    bearer = data.split("Bearer ")[1].split("\r\n")[0].strip()
                    part1 = decode_bearer(bearer).decode().split("06")[1].strip()
                    continue
                if at_first:
                    d = json.loads(data)["d"]
                    part2 = json.loads(decode_first_packet(d, part1).decode())["ack"].split("@")[0].strip()
                    aes_key = derive_key(part1, part2)
                    at_first = False
                    continue
                d = json.loads(data)["d"] # will err for normal requests and only get the json ones
                msg = aes_cbc_decrypt_hex(d, aes_key)
                print(msg.decode())
                j = json.loads(msg)
                if j["msg"] == "cmd":
                    if j["d"]["cid"] == 6:
                        part2 = j["d"]["np"]
                        aes_key = derive_key(part1, part2)
                        continue
            except Exception as e:
                #print(e)
                continue

if __name__ == "__main__":
    process_pcap(sys.argv[1])

```

However, looking through the responses, we see that there's no flag. There are 2 base-64 encoded files, one with a short story, and one with some passwords, and the rest are just system recon commands. At this point I grew a bit desperate and tried a few options based on the 2 files, but none worked. However, going back to analyzing the decoded output properly, I noticed a series of commands which included a command for sending over a file which didn't return anything.

```
{"msg": "no_op"}
{"msg": "no_op"}
{"msg": "cmd", "d": {"cid": 5, "lp": "C:\\Users\\TheBoss\\Documents\\Studio_Masters_Vault\\The_Vault\\rocknroll.zip"}}
{"msg": "no_op"}
{"msg": "no_op"}
```

Looking through the PCAP, I have identified the request and saw that it has never reached my script, probably because `dpkt` didn't see it properly or idk. So I decrypted the ZIP (part2 = "TheBoss@THUNDERNODE") file manually from the PCAP using CyberChef, and opened it with the password given for `Other` in the passwords file, and it contained a `.jpg` file. I tried opening it, but that didn't work, so I opened it up in HxD and the flag was there.

FLAG: `c4n7_st4r7_a_flar3_w1th0ut_4_$park@flare-on.com`
