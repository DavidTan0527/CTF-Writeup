---
title : "Decrypt Message 1 [RE]"
categories: HacktheonSejong2024
---

Reversing C++ program given source code.

# Challenge Description

Decrypt `188d1f2f13cd5b601bd6047f4496ff74496ff74496ff7`

[decrypt_message_1.zip]({{ site.url }}/files/hacktheonsejong2024/decrypt_message_1.zip){: .btn .btn--info}

# Solution

The program is essentially taking the user input (byte-by-byte), then reading every 2 bytes as a short, and performing the following operation.

```c
        eax = data[byte_address];
        ecx = eax + 0x11;
        eax = eax + 0xB;
        ecx = eax * ecx;
        edx = ecx;
        edx = edx >> 8;
        eax = edx;
        eax = eax ^ ecx;
        eax = eax >> 0x10;
        eax = eax ^ edx;
        eax = eax ^ ecx;
        data[byte_address] = eax;
```

Since each element is a `short` which is only 16 bits = 2 bytes, we can bruteforce it.

Note: the result is printed as a hex string of each elements in `data`, but since it isn't padded to a fixed length, we have to try out different lengths.

# Final Script
```python
def test(x: str) -> (int, bool):
    n = int(x, 16)
    
    for a in range(0x101, 0x10000):
        if a & 0xff == 0:
            continue
        
        eax = (a) & 0xffffffffffffffff
        ecx = (eax + 0x11) & 0xffffffffffffffff
        eax = (eax + 0xB) & 0xffffffffffffffff
        ecx = (eax * ecx) & 0xffffffffffffffff
        edx = (ecx) & 0xffffffffffffffff
        edx = (edx >> 8) & 0xffffffffffffffff
        eax = (edx) & 0xffffffffffffffff
        eax = (eax ^ ecx) & 0xffffffffffffffff
        eax = (eax >> 0x10) & 0xffffffffffffffff
        eax = (eax ^ edx) & 0xffffffffffffffff
        eax = (eax ^ ecx) & 0xffffffffffffffff
        
        if eax == n:
            return a, True
        
    return 0, False
    

c = "188d1f2f13cd5b601bd6047f4496ff74496ff74496ff7"

flag = b""

i = 0
while i < len(c):
    l = 1
    while i + l <= len(c):
        chunk = c[i:i+l]
        x, ok = test(chunk)
        
        if ok:
            part = x.to_bytes(2, 'little')
            flag += part
            break
        
        assert(i + l < len(c))
        
        l += 1
        
    i += l
    
print(flag)
```
Flag: `GODGPT!!!!!!`