---
title: "FlashyLighty [Mobile]"
categories: DSO-NUS2021
gallery:
 - url: /assets/images/flashylighty/2.png
   image_path: /assets/images/flashylighty/2.png
   title: "specialK"
 - url: /assets/images/flashylighty/3.png
   image_path: /assets/images/flashylighty/3.png
   title: "gimmie"
---

Mobile reversing challenge that uses time of execution to check for conditions. Third mobile challenge from DSO-NUS 2021.

# Problem Statement
```
Bling bling flashlight by day, diary by night

Files (Any of the links are fine):
https://nusdsoctf2.s3-ap-southeast-1.amazonaws.com/S3/FlashyLighty/flashylighty.apk
https://nusdsoctf.s3-ap-southeast-1.amazonaws.com/S3/FlashyLighty/flashylighty.apk

 >> Flag format conversion may have to be done for this challenge (Refer to notifications)
```

# Solution

I started off by using `apktool` on `flashylighty.apk`, then in the project directory, convert the `.smali` files in `/smali/com/dso/flashylighty` to `.jar` using [dex2jar tool](https://github.com/pxb1988/dex2jar). Then, we can decompile the `.jar` back to `java` using JD-GUI, you can find a decompiler of your liking [here](https://java-decompiler.github.io/).

The 3 files that we just decompiled doesn't seem to do anything other than hinting the native methods. So the next thing I did is to find where these methods are used (the main driver function).

I went back to the `flashylighty.apk` and ran `d2j-dex2jar` on the apk itself, and throwing the output jar file to JD-GUI. Now, we can use the search function of this tool to search for the string `MainActivity`, and we find that it is used in the classes in `b.b.a`.

{% include image.html url="/assets/images/flashylighty/1.png" description="" %}

Supposedly, we need to reach the part of "Check logcat!". There are two interesting functions: `specialK` and `gimmie` -- both native methods. One thing to notice before we switch gears, the number that satisfies the if statement is the same for both native methods.

## Analyzing the native methods

We go to `/lib/x86` (my choice of architecture), and import that `.so` into ghidra. Here are the decompilations of the two native methods:

{% include gallery %}

I realized that these two methods take in 3 and 4 arguments respectively, but in Java they are passed 1 and 2 arguments. The extra 2 arguments are `JNIEnv *` and `jobject` respectively, as shown [here](https://www3.ntu.edu.sg/home/ehchua/programming/java/javanativeinterface.html). So when we see `**(code **)(*param_1 + ...)(...)`, this is in fact calling a JNI function, the offsets represent the index of the function being called, you can refer to this [specification](https://docs.oracle.com/en/java/javase/13/docs/specs/jni/functions.html).

But I found it quite painful to keep looking up indices on the specification, and I found [this](https://www.ragingrock.com/AndroidAppRE/reversing_native_libs.html) that talks about changing the data type of `param_1` to `JNIEnv *`, then ghidra will be able to show the function name instead of just the offsets.

{% include image.html url="/assets/images/flashylighty/4.png" description="gimmie function when the type is changed" %}

So it's just copying the string that we passed in into a local variable. The code seems to take the least significant byte of `param_3` and xor with the last 6 characters of `param_4`. After reading it for a bit longer, it seemed to me that it doesn't make sense for it to xor with the last 6 characters only, so my intuition leads me to just xor the whole string in my later solution.

The value of `param_4` is fixed (hardcoded). Whereas the value of `param_3` depends on what value will make `specialK() == 10101`, recall that the numbers passed into the two method calls are the same.

So the only thing left to do is to reverse `specialK`:

```c
iVar3 = 100;
do {
  clock_gettime(0,&local_1c);
  dVar4 = (double)local_1c.tv_sec;
  dVar5 = (double)local_1c.tv_nsec;
  __android_log_print(4,0x10820,"I can dance all day");
  clock_gettime(0,&local_1c);
  param_3 = param_3 + (int)(((double)local_1c.tv_nsec / 1000000.00000000 +
                            (double)local_1c.tv_sec * 1000.00000000) -
                           (dVar5 / 1000000.00000000 + dVar4 * 1000.00000000));
  iVar3 = iVar3 + -1;
} while (iVar3 != 0);
uVar1 = 0xefe;
if (param_3 * param_3 == 0x7a69) {
  uVar2 = 0x29c;
  uVar1 = 0x2775;
  if (param_3 == 0xadf) goto LAB_00010714;
}
uVar2 = uVar1;
LAB_00010714:
if (*(int *)(in_GS_OFFSET + 0x14) == local_14) {
  return uVar2;
}
```

The do-while loop is incrementing our input number by the duration of one iteration, for a total of 100 iterations, then the resulting value squared must be equal to `0x7a69`. If you do the math out, `0x7a69 = 31337` which is not a perfect square, so we need to exploit the fact that `imul` instruction in assembly only takes the lowest 32 bits of the result into `eax`, so we can write a brute force to find a number such that its square is of the form `0x...00007a69`.

But how do we deal with the time? I had no idea at that moment in time so I played a lot with `adb` and tried to see if `logcat` can give me precise timings of each iteration, but eventually I realised that each iteration would never take more than 2ms, and since the division will take the floor, each iteration either adds 1 or 0.

So I just need to try for increments of 0 to 100, and take those respective inputs into `gimmie`.

# Final Script
Because python is too slow, I turned to C instead.
```c
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
  char s[] = "zjMl+G^(j{}Gz+kLG~Wj{+";
  int found[256];
  memset(found, 0, 256 * sizeof(int));

  for (long long i = 0; i < (1ll<<32); i++) {
    if (((i*i)&0xffffffffll) == 0x7a69ll) {
      found[i&0xff] = 1;
    }
  }

  for (int i = 0; i < 256; i++) {
    if (found[i]) {
      for (int j = 0; j <= 100; j++) {
        for (int k = 0; k < strlen(s); k++) {
          int c = s[k];
          int ch = c^((i-j)&0xff);
          printf("%c", ch);
        }
        printf("\n");
      }
    }
  }

  return 0;
}
```

## Output
```
...
fvQp7[B4vga[f7wP[bKvg7
aqVw0\E3q`f\a0pW\eLq`0
`pWv1]D2pag]`1qV]dMpa1
csTu2^G1sbd^c2rU^gNsb2
brUt3_F0rce_b3sT_fOrc3
m}Z{<PI?}ljPm<|[Pi@}l<
l|[z=QH>|mkQl=}ZQhA|m=
oXy>RK=nhRo>~YRkBn>
...
```

Put `brUt3_F0rce_b3sT_fOrc3` in SHA256, and we get the flag.

Flag: `DSO-NUS{1dcd6f93316353bd99336eb7cfe7bfb146ba59e7b03a4ab7afd47020c08dc677}`
