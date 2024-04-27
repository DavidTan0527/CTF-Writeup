---
title : "Decrypt Message 2 [RE]"
categories: HacktheonSejong2024
---

Reversing an encryption program with bruteforce.

# Challenge Description

Decrypt "446709213550020f3b28696533183206631e030743394d4531"

Decrypted message is start with "BrU7e"

[decrypt_message_2.zip]({{ site.url }}/files/hacktheonsejong2024/decrypt_message_2.zip){: .btn .btn--info}

# Solution

We are given a binary called `encryptor`. If we decompile it in Ghidra, we see that it encrypts the "flag" and prints the ciphertext in hex (what we're given in the description).

The encryption algorithm, after renaming the methods, looks like this:

```c
char *enc(char *flag, int len) // len == 5
{
    ...
    len = strlen(flag);
    len_00 = (int)len;
    if (len_00 % 5 == 0) {
        s = (char *)rand_hexstr(5);
        printf("key @ %s\n",s);
        flag_str = expand_char_to_int(flag,len_00);
        hex_str = expand_char_to_int(s,5);
        xor_enc(flag_str,hex_str,len_00,5);
        huh(flag_str,hex_str,len_00,5);
        local_18 = to_hex(flag_str,len_00);
        free(flag_str);
        free(hex_str);
        free(s);
    }
    ...
}
```

`expand_char_to_int`, `rand_hexstr` (it's actually base64 character), and `xor_enc` are pretty straightforward to figure out, but the `huh` function is more complicated at first sight. Initially, I thought it was doing RC4, but it turns out it's something simpler. Here's the decompiled code after renaming:

```c
void huh(int *msg, int *key, int len_msg, int len_key)
{
    ...
    key_idx = (int *)malloc((long)len_key << 2);
    for (num = 0; num < len_key; num = num + 1) {
        key_idx[num] = num;
    }
    for (i = 0; j = i, i < len_key; i = i + 1) {
        while (j = j + 1, j < len_key) {
        if (key[j] < key[i]) {
            iVar1 = key[i];
            key[i] = key[j];
            key[j] = iVar1;
            iVar1 = key_idx[i];
            key_idx[i] = key_idx[j];
            key_idx[j] = iVar1;
        }
        }
    }
    res = (int *)malloc((long)len_msg << 2);
    for (ri = 0; ri < len_msg; ri = len_key + ri) {
        for (rj = 0; rj < len_key; rj = rj + 1) {
        res[ri + rj] = msg[ri + key_idx[rj]];
        }
    }
    for (local_54 = 0; local_54 < len_msg; local_54 = local_54 + 1) {
        msg[local_54] = res[local_54];
    }
    ...
}
```

Essentially, it is sorting the bytes in the key to determine its rank (smallest is rank 0, largest is rank 4 in our case), then shuffling each blocks of 5 in the message by the key rank (I called it `key_idx`).

Therefore, to do the decryption, since we don't know the key, we can guess the key by bruteforcing since it's only 5 base64 characters. I used pwntools' multithreaded bruteforce utility function `pwnlib.util.iters.mbruteforce` to solve. For each guess, we reverse the process by doing: first `huh` decrypt, then `xor` decrypt (same as encrypt), and check if the result starts with "BrU7e".

# Final Script
```python
from Crypto.Cipher import ARC4
from pwnlib.util.iters import *

c = bytes.fromhex("446709213550020f3b28696533183206631e030743394d4531")
print("Length:", len(c))

# starts with "BrU7e"
flag = ""

chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

def xor(x, k):
    m = []
    for i in range(len(x)):
        m.append(x[i] ^ k[i % len(k)])
    return bytes(bytearray(m))

def dec(x, k):
    idx = [i for i in range(len(k))]
    key = list(k)
    for i in range(len(k)):
        for j in range(i+1, len(k)):
            if key[j] < key[i]:
                key[i], key[j] = key[j], key[i]
                idx[i], idx[j] = idx[j], idx[i]
                
    res = [0] * len(x)
    for i in range(0, len(res), len(k)):
        for j in range(len(k)):
            res[i + idx[j]] = x[i + j]
    return res
            
            

def solve(k: str):
    k = k.encode()
    t = dec(c, k)
    m = xor(t, k)
    
    if m[:5] == b"BrU7e":
        print(m)
        return True
    return False
        
print("Max # of tries:", len(chars)**5)
mbruteforce(solve, chars, 5, method="fixed")
```
The script takes very long to finish...

Flag: `BrU7e_fORcE_l5_p0w3rFu1i!`