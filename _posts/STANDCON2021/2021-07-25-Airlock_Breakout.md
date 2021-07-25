---
title : "Airlock Breakout [RE]"
categories: STANDCON2021
---

JavaScript flag checking functions solved using z3-solver. First RE challenge from STANDCON 2021.

# Challenge Description

I've stolen the Nova Core, but it seems like I've been locked in within these 3 airlock doors. I'm not sure how much longer I can hold them off Please help me crack the password so that I can be on my merry way!

`http://20.198.209.142:55030O`

# Solution

Navigating to the webpage, and immediately looking at the source tab, there's only one JS file, non-obfuscated, clearly containing the flag checking functions.

*You can get the script [here]({{ sites.url }}/files/Airlock_Breakout-flag.js)*

The first function is pretty self-explanatory. The second one is system of equations, I'll be using z3 in python to solve for it. Get a quickstart [here](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)

Considering each character as an 8-bit vector, we can construct these quite straightforward.

```python
s = Solver()
part = [BitVec(str(i), 8) for i in range(4)]
s.add(part[0] + 2*part[1] - 3*part[2] + 4*part[3] == 354)
s.add(2*part[0] + 2*part[1] - 2*part[2] + 3*part[3] == 383)
s.add(3*part[0] - 2*part[1] - 4*part[2] + part[3] == -106)
s.add(2*part[0]*part[0]*part[0] + 3*part[1]*part[1] - 2*part[2]*part[2]*part[2] - 4*part[3]*part[3] == 59284)
if s.check() == sat:
    result = s.model()
    return ''.join([chr(int(str(result[p]))) for p in part])
```

The third function was also quite easy (you just construct everything as it is checked, and throw it into z3's solver). Only thing interesting is the magic value and the length of the final part of the flag. We can fully utilize the power of z3 and just construct `magic` as it is, as for the length, I tested 6, which gave `unsat`, which I then tried 7 and it worked.

```python
s = Solver()
str3 = [BitVec("3-%d" % i, 32) for i in range(3)]
str4 = [BitVec("4-%d" % i, 32) for i in range(2)]
str5 = [BitVec("5-%d" % i, 32) for i in range(3)]
str6 = [BitVec("6-%d" % i, 32) for i in range(7)]

magic = BitVecVal(0, 32) # constant number
for strs in [str3, str4, str5, str6]:
    s.add(And([\
        Or([ strs[i] == ord(ch) for ch in "01347CFHKLNRUX" ]) for i in range(len(strs))\
    ]))

    for char in strs:
        magic = (magic << 3) + char - magic

s.add(str3[0] == ord("0"))
s.add(str5[0] == ord("7"))
s.add(str3[0] + str5[0] - str6[0] == 51)
s.add(str3[0] == str4[0])
s.add(str3[2] - str3[1] == -30)
s.add((str4[1] / 7) * str5[1] == 720)
s.add(str5[0] + str5[2] == 106)
s.add(str6[3] - str6[2] == -6)
s.add(str6[2] * str6[4] == 3936)
s.add(magic == (-859895409 & 0xffffffff))

if s.check() == sat:
    result = s.model()
    return '_'.join([''.join([ chr(int(str(result[p]))) for p in strs]) for strs in [str3, str4, str5, str6]])

else:
    print("unsat")
```

Then we just piece everything together and get the flag.

# Final Script

```python
def part1():
    return ''.join(map(chr, [51, 74, 51, 67, 55]))

from z3 import *

def part2():
    s = Solver()
    part = [BitVec(str(i), 8) for i in range(4)]
    s.add(part[0] + 2*part[1] - 3*part[2] + 4*part[3] == 354)
    s.add(2*part[0] + 2*part[1] - 2*part[2] + 3*part[3] == 383)
    s.add(3*part[0] - 2*part[1] - 4*part[2] + part[3] == -106)
    s.add(2*part[0]*part[0]*part[0] + 3*part[1]*part[1] - 2*part[2]*part[2]*part[2] - 4*part[3]*part[3] == 59284)
    if s.check() == sat:
        result = s.model()
        return ''.join([chr(int(str(result[p]))) for p in part])


def part3():
    s = Solver()
    str3 = [BitVec("3-%d" % i, 32) for i in range(3)]
    str4 = [BitVec("4-%d" % i, 32) for i in range(2)]
    str5 = [BitVec("5-%d" % i, 32) for i in range(3)]
    str6 = [BitVec("6-%d" % i, 32) for i in range(7)]

    magic = BitVecVal(0, 32) # constant number
    for strs in [str3, str4, str5, str6]:
        s.add(And([\
            Or([ strs[i] == ord(ch) for ch in "01347CFHKLNRUX" ]) for i in range(len(strs))\
        ]))

        for char in strs:
            magic = (magic << 3) + char - magic

    s.add(str3[0] == ord("0"))
    s.add(str5[0] == ord("7"))
    s.add(str3[0] + str5[0] - str6[0] == 51)
    s.add(str3[0] == str4[0])
    s.add(str3[2] - str3[1] == -30)
    s.add((str4[1] / 7) * str5[1] == 720)
    s.add(str5[0] + str5[2] == 106)
    s.add(str6[3] - str6[2] == -6)
    s.add(str6[2] * str6[4] == 3936)
    s.add(magic == (-859895409 & 0xffffffff))

    if s.check() == sat:
        result = s.model()
        return '_'.join([''.join([ chr(int(str(result[p]))) for p in strs]) for strs in [str3, str4, str5, str6]])
    else:
        print("unsat")

print("STC{% raw %}{%s_%s_%s}{% endraw %}" % (part1(), part2(), part3()))
```

Flag: `STC{3J3C7_7H3M_0U7_0F_7H3_41RL0CK}`
