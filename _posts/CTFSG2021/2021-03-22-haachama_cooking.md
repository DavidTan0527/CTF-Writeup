---
title : "Haachama cooking [RE]"
categories: CTFSG2021
---

A simple Golang binary reversing challenge with some AES. Second RE challenge from CTF.SG 2021.

# Challenge Description
*I lost the description, but it didn't contain any useful information anyway.*

We are given a [binary]({{ sites.url }}/files/haachama)

# Solution
I couldn't get this binary to run, so I gave up eventually and went straight to static analysis.

Opening this binary in Ghidra, we find no `entry` as we normally would with a `C` binary. We can see hints of Golang from the `fmt` functions, so the main is actually at `main.main`.

One skill you need to have when analyzing Golang binaries is to ignore certain part of code, for instance:

```c
void main.main(void)
{
  pppuVar1 = (undefined ***)(*(int *)(*in_GS_OFFSET + -4) + 8);
  ppiVar2 = (int **)register0x00000010;
  if (*pppuVar1 <= &local_2c && &local_2c != (undefined ***)*pppuVar1) {
    ...
    while (true) {
      ...
      if (next_index_x16 < (uint)((int)index * 0x10)) {
LAB_080dac9c:
        runtime.panicSliceB();
        break;
      }
      ...
      if ((int *)0x3 < local_6c) {
        runtime.panicIndex();
        goto LAB_080dac9c;
      }
      result[(int)local_6c] = local_84;
      index = local_70;
    }
    runtime.panicSliceAlen();
  }
  *(undefined4 *)((undefined *)ppiVar2 + -4) = 0x80dacb2;
  runtime.morestack_noctxt();
  main.main();
  return;
}
```

These code do nothing related to the main logic of the program, it just allocates stack space for the executable. We'll jump straight into the important parts.

{% include image.html url="/assets/images/haachama/2.png" description="The input length is 64 bytes long as seen from here" %}

After the input, there is a while loop that, upon closer inspection, each iteration seems to operate on 16 bytes of our input.

{% include image.html url="/assets/images/haachama/1.png" description="This is done for the 4 16 byte segments" %}

Looking at this, we are given `iv` and `key`, and if we trace the `main.encryptPart()` call, we end up in `main.encryptPart.func1()` and see that it calls `main.aesEncrypt()`. From this, I just blindly assumed that it takes the given `iv` and `key` to encrypt our 16 byte segments.

Going back to `main.main`, we can look into the code that runs after we encrypt the 4 segments. I'll be excluding the parameters and only look at the function calls (this is sufficient in understanding the program, and this is what I did to solve it).

```cpp
main.merge();
runtime.makeslice();
encoding/hex.Encode();
runtime.slicebytetostring();
fmt.Fprintln();
runtime.convTstring();
fmt.Fprintln();
if (local_74 == (undefined **)&DAT_00000080) {
  runtime.memequal();
  if ((char)local_a0 != '\0') {
    fmt.Fprintln();
    return;
  }
}
fmt.Fprintln();
return;
```

If we look into `main.merge()`, it takes the 4 segments (after encryption) and merges them back into 64 bytes (converting them to a literal string, i.e. `0x2a03` -> "2a03"), then compares it to some string using `runtime.memequal()`.

{% include image.html url="/assets/images/haachama/3.png" description="The target ciphertext that is compared to" %}

So the final solution is to take 128 characters of this string, because AES outputs in 128 bit = 16 byte = 32 characters, 4 such outputs concat to 128 characters. Then we use that string and decrypt using AES with the given `iv` and `key`.

# Final Script
```python
from Crypto.Cipher import AES

iv = b'mysupersecureiv\x00'
key = b'mysupersecurekey'

def decrypt_flag(key: str, iv: str, ciphertext: str):
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

ct = ['20d91f642406ce17432107a0f61a5405', 'c3b45ec744d07c2d3a19649f5ed2c5ba', 'ff4d15473b92c1d00916790dd14deec7', '7a9d413a1e2fe83f0775bd7d3c984c4c']

for text in ct:
    print(decrypt_flag(key, iv, text), end='')
print()
```

Flag: `CTFSG{t0d@y_1_1E@rnT_hum@ns_c@nt_multit@sk_BUT_c0mput3rs_c@n_d0}`
