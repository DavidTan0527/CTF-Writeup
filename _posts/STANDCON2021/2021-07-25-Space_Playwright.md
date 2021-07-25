---
title : "Space Playwright [RE]"
categories: STANDCON2021
---

Reverse a program written in Shakespeare Programming Language (SPL). Second RE challenge in STANDCON2021.

# Challenge Description

I hath found this script.

What couldst this beest?

Is't hiding something from me?

t hast given me this phrase `664-81258-81750-82199-82668-83044-83428-83794-84071-84362-84652-84845-85082-85233-85428-85591-85691-85842-85990-86073-86166-86253-8`

[tobeornottobe]({{ sites.url }}/files/tobeornottobe){: .btn .btn--info}

# Solution

If you've seen this esoteric language, you would be able to recognize it almost instantly. First thing I did was to read up on the language [here](http://shakespearelang.sourceforge.net/report/shakespeare/shakespeare.html) to get a feel of how the language works.

I'll do a bit of step by step walkthrough since the program isn't that long anyway.

The program starts with declaring 4 variables, and starts with Scene II.

```
Scene II: i has't been traumatis'd.

Egeus:
Open Your mind! Remember yourself!

Dogberry:
You are as amazing as the sum of yourself and a king. Am I as smelly as the sum of my happy warm rich hair and my trustworthy cat?

Egeus:
if not, let us return to Scene II! recall your unhappy childhood!
```

We can translate this into a sort of psuedocode.

```
Scene II:

Read character into Dogberry. Push the value onto his stack.

Egeus = Egeus + 1
Dogberry == 10 ?

If not, goto Scene II.
Pop Dogberry's stack into himself.
```

Ahh, much easier to read. This just reads input until it hits a `\n` character (value = 10), and stores all the characters by pushing them onto Dogberry's stack. In the end, Egeus will have the value of the length of the input.

```
Scene III: we square anon.

[Enter Benedick]

Egeus:
Thou art as sweet as the sum of the square of me and Dogberry.

[Exit Benedick]
[Enter Dogberry]

Dogberry:
You are as smelly as the sum of yourself and a hog! Are you better than the sum of a pig and a king?

Egeus:
if not, let us proceed to scene IV.
Recall your betrayal!
You are as stupid as the sum of Benedick and you. Open thy heart!

[Exit Dogberry]
///// Ignore /////
[Enter Ford]

Egeus:
You are as bad as the evil snotty cowardly microsoft.
Open your heart!

[Exit Ford]
//////////////////

Egeus:
we must proceed to scene III.
```

There seems to be a lot of going on. But one step at a time, we again write it in pseudocode.

But before we do, notice that I have two lines of comments denoting the section I'll be ignoring. Spoiler alert: Scene III is a loop, and the section I'm ignoring just prints a single `8`, which doesn't make sense as the ciphertext we have from the challenge description has only one `8` in the end.

```
// Dogberry's value is 10 ('\n') from last part

Scene III:

Benedick = Egeus**2 + Dogberry // Recall that Egeus is the length of the input from the last part

Egeus = Egeus - 1
Egeus > 0 ?

If not, goto Scene IV
Pop Dogberry's stack
Dogberry = Benedick + Dogberry
print Dogberry's value

Goto Scene III
```

We can run through a few iterations by hand, writing down what it prints out. Assuming the input is the flag, and has length `n`.

```
output[0]  :     n**2 +     10      + flag[n-1]
output[1]  : (n-1)**2 + output[0]   + flag[n-2]
output[2]  : (n-2)**2 + output[1]   + flag[n-3]
...
output[n-1]:     1**2 + output[n-2] + flag[0]
```

Remember that the data structure used is a stack (LIFO), so the first value we pop is the last character of the flag. Finally, we can just reverse this process and get our flag.

# Final Script

```python
code = "664-81258-81750-82199-82668-83044-83428-83794-84071-84362-84652-84845-85082-85233-85428-85591-85691-85842-85990-86073-86166-86253-8"

txt = list(map(int, code.split("-")))[:-1]
result = "\n"
last = ord(result[0])

for j in range(len(txt)):
    e = len(txt) - j + 1
    result += chr(txt[j] - last - e**2)
    last = txt[j]

print(result[::-1])

```

If we run this script, we get something weird.

```bash
$ py trans.py
STC{s3cr3t1y_4n_4l13𓣮}
```

That's ok, we can just guess the final character.

Flag: `STC{s3cr3t1y_4n_4l13n}`
