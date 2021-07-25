---
title : "Ancient Computing [Forensics]"
categories: STANDCON2021
---

Study and understand a very old file spreadsheet format (WK1 for Lotus 1-2-3), then retrieve data stored in a cell. First forensics challenge from STANDCON2021.

# Challenge Description

What is the value contained in the cell D9? Specify your answer up to 14 decimal places.

The flag is the answer to the question enclosed with the flag format: `STC{0.12345678901234}`

[book1.wk1]({{ sites.url }}/files/book1.wk1){: .btn .btn--info}

# Solution

I started with some heavy googling, but found nothing regarding the file specifications of `.wk1`. I tried using convertors to convert it to a modern file format that Excel can open, but upon doing that, I find that the data has been truncated to 8 decimal places only.

So I ended up studying the file format myself...

Doing `hexdump -C book1.wk1 | less`,

```
00000070  00 01 24 00 01 00 00 26  00 04 00 7c 26 41 00 25  |..$....&...|&A.%|
00000080  00 08 00 7c 50 61 67 65  20 23 00 2a 00 10 00 ff  |...|Page #.*....|
00000090  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff 0e  |................|
000000a0  00 0d 00 f1 00 00 00 00  00 80 58 1e ed e8 c4 3f  |..........X....?|
000000b0  0e 00 0d 00 f1 01 00 00  00 00 00 63 25 ef 3f ef  |...........c%.?.|
000000c0  3f 0e 00 0d 00 f1 02 00  00 00 00 80 2f 1e 9e 7c  |?.........../..||
000000d0  ee 3f 0e 00 0d 00 f1 03  00 00 00 00 00 7a db 1c  |.?...........z..|
000000e0  81 e9 3f 0e 00 0d 00 f1  04 00 00 00 00 60 8a ae  |..?..........`..|
000000f0  40 f3 e4 3f 0e 00 0d 00  f1 05 00 00 00 00 40 bd  |@..?..........@.|
00000100  c9 98 bb ee 3f 0e 00 0d  00 f1 06 00 00 00 00 80  |....?...........|
00000110  f1 70 48 2f d3 3f 0e 00  0d 00 f1 00 00 01 00 00  |.pH/.?..........|
00000120  80 0b a5 0d 27 d8 3f 0e  00 0d 00 f1 01 00 01 00  |....'.?.........|
00000130  00 40 9e 58 d6 bc df 3f  0e 00 0d 00 f1 02 00 01  |.@.X...?........|
00000140  00 00 00 6e 5d 67 f1 dc  3f 0e 00 0d 00 f1 03 00  |...n]g..?.......|
00000150  01 00 00 60 b3 79 66 48  e3 3f 0e 00 0d 00 f1 04  |...`.yfH.?......|
00000160  00 01 00 00 00 89 b6 ee  19 cd 3f 0e 00 0d 00 f1  |..........?.....|
00000170  05 00 01 00 00 00 9a 0a  50 9e ab 3f 0e 00 0d 00  |........P..?....|
00000180  f1 06 00 01 00 00 80 97  42 7b 49 ef 3f 0e 00 0d  |........B{I.?...|
00000190  00 f1 00 00 02 00 00 00  84 0a b5 81 d9 3f 0e 00  |.............?..|
```

My eyes were immediately caught to the repeating patterns, which should represent each cell. We can generalize it to this format:

`3f 0e 00 0d 00 f1 XX XX YY YY 00 DD DD DD DD DD DD`

The 2 bytes of `X` and 2 bytes of `Y` were concluded by noticing that they iterate from 0 to 6 and from 0 to 13 respectively, which matches the number of columns and rows of the spreadsheet.

The goal is to understand how the bytes labelled as `D` relate to the actual values in that cell. I got my hands dirty here and modified the values, then converted the file to csv to see how it changes.

I'll be showing the values I tested and the thoughts I had in mind at each step.

```
00 00 00 00 00 00   =>   0.00003052     [= 2^-15]
00 00 00 00 00 01   =>   0.00003242     [= 2^-15 + 2^-19]
00 00 00 00 00 02   =>   0.00003433     [= 2^-15 + 2^-18]
```

This hints me that the lower nibble of the last byte has a value of `2^-19`.

```
00 00 00 00 00 10   =>   0.00006104     [= 2^-14]
00 00 00 00 00 F0   =>   1
```

So the higher nibble of the last byte controls the exponent, a value `k` means multiplied by `2^(k-15)`.

```
00 00 00 00 01 F0   =>   1.00024414     [= 1 + 2^-12]
00 00 00 00 10 F0   =>   1.00390625     [= 1 + 2^-8]
```

At this point, I have a rough idea of what's going on. If we arrange the bytes in little endian form:

```
F0 10 00 00 00 00
=> 2^(15 - 15) * 1.(0x01000000000)_2
   = (1.00000001)_2
   = 1.00390625
```

We can verify this concept with other cells

```
80 E4 19 90 F2 DA   =>   0.42105486

Little endian: DA F2 90 19 E4 80
0xAF29019E480 = 0b10101111001010010000000110011110010010000000

2^(0xD - 15) * 1.1010111100101001000000011001111....
= 0.011010111100101000000011001111....
= 0.42105486418586224
```

So it's correct! I wrote a quick script to help do the calculations for me.

# Final Script

{%raw%}
```python
cells = [[0 for i in range(7)] for j in range(15)]

with open("book1.wk1", "rb") as f:
    f.seek(0x9e)
    byte = f.read(6)
    while byte:
        col = int.from_bytes(f.read(2), byteorder='little');
        row = int.from_bytes(f.read(2), byteorder='little');
        sequence = f.read(7)
        cells[row][col] = int.from_bytes(sequence, byteorder='little')
        byte = f.read(6)
        if row == 14 and col == 6: break

def parse(packet):
    exponent = int(packet[0], 16) - 15
    mantissa = 1 + int(packet[1:], 16) / (2**(4 * len(packet[1:])))
    return mantissa * (2**exponent)

print("STC{%.14f}" % parse(hex(cells[8][3])[2:]))
```
{%endraw%}

Flag: `STC{0.25241301339338}`


