---
layout: categories
title : "Dice Is You [RE]"
categories: DiceCTF2021
---

A wasm reversing challenge.

# Challenge Description
```
DICE IS YOU

Controls:
- wasd/arrows: movement
- space: advance a tick without moving
- q: quit to main menu
- r: restart current level
- z: undo a move (only works for past 256 moves and super buggy)

Play: dice-is-you.dicec.tf
```

# Solution
## Level 1-4
This challenge was quite well made as you get to play through a game before the real challenge comes. The first four levels were all quite trivial after you understand the game mechanics through some trial and error.

*It's not really required for you to play through but I found that it helped me understand the game's lifecycle a bit, I'll save you the hassle though: Change the value of the cookie to 5 to unlock level 5.*

## Level 5
This level is basically unsolvable by just playing the game, so let's finally do some RE.

{% include image.html url="/assets/images/dice_is_you_1.png" description="What?????" %}

Opening the network tab in the developer's tools, we can copy the url (https://dice-is-you.dicec.tf/app.wasm) to the wasm binary and download that.

Then, we can use a [wasm decompiler](https://github.com/WebAssembly/wabt) to decompile the binary to, what is known as, dcmp (which is syntactically very similar to JavaScript).

```bash
wasm-decompile app.wasm -o app.js
cat app.js | grep function | grep -v "emscripten" | grep -v "SDL" > functions.txt
```

Since decompiled code is usually very big, it's also useful to extract the lines which contain function names, just to find out the more important functions easier.

Looking inside the txt file, notice some important functions:
```javascript
function level1() {
function level2() {
function level3() {
function level4() {
function level_flag_fin() {
function flag_rules(a:int, b:int) {
...
function check_code(a, b, c, d) {
function get_code_value(a:int):int {
function code(a, b, c, d, e) {
function reset(a:int) {
function check_rule(a:int, b:int, c:int, d:int, e:int, f:int, g:int, h:int):int {
function check_win_condition(a:int, b:int, c:int):int {
```
The function names were pretty self explanatory -- at least that's what I hoped for, since the code was basically unreadable. So we have the functions for the respective levels, and the last level is called `level_flag_fin`, which implies that the flag will be given after we solve it (?) 

### What are the blocks?
Looking at the function,

```javascript
function level_flag_fin() {
  ...
  var j:int = 198;
  var k:int = 324;
  var l:int = 330;
  var m:int = 2;
  var n:int = 8;
  var o:int = -2;
  var p:int = 7;
  var q:int = 6;
  var r:int = 342;
  spawn_entity(m, m, r);
  spawn_entity(d, d, o);
  spawn_entity(m, d, o);
  spawn_entity(e, d, o);
  spawn_entity(h, d, o);
  spawn_entity(f, d, o);
  spawn_entity(q, d, o);
  spawn_entity(p, d, o);
  ...
}
```

It seems like this level functions spawns the blocks (entities), we can tidy the code using a [closure compiler](https://developers.google.com/closure/compiler) after cleaning it into proper JavaScript, which wasn't really hard to do.

```javascript
function level_flag_fin() {
  var a = g_a - 16;
  a < g_c && handle_stack_overflow();
  g_a = a;
  spawn_entity(2, 2, 342);
  spawn_entity(1, 1, -2);
  spawn_entity(2, 1, -2);
  ...
  spawn_entity(3, 4, 264);
  spawn_entity(3, 5, 138);
  for (c[3] = 1; c[3] <= 12; c[3]++) {
    spawn_entity(c[3], 13, -2);
    spawn_entity(c[3], 17, -2);
    if (c[3] <= 8) spawn_entity(c[3], 15, -2);
    if (c[3] <= 5) spawn_entity(c[3], 19, -2);
  }
  spawn_entity(1, 14, -2);
  spawn_entity(1, 16, -2);
  spawn_entity(1, 18, -2);
  spawn_entity(8, 14, -2);
  ...
  a = c + 16;
  a < g_c && handle_stack_overflow();
  g_a = a;
}
```

Much more readable! After staring at this for probably half an hour, a reasonable hypothesis I made was that `spawn_entity` takes in `x_coords`, `y_coords`, `entity_id` as its arguments. So, I added some comments to identify which lines corresponded to what block.

```javascript
  ...
  spawn_entity(3, 3, 330); // y 
  spawn_entity(4, 3, 324); // x
  spawn_entity(5, 3, 198); // o+
  spawn_entity(3, 4, 264); // E
  spawn_entity(3, 5, 138); // ∆
  ...
  spawn_entity(16, 3, 240); //O.
  spawn_entity(18, 3, 252); //D
  spawn_entity(10, 3, 294); //I
  spawn_entity(12, 3, 276); //|_
  spawn_entity(14, 3, 288); //L mirror
  spawn_entity(16, 5, 300); //∆filled
  spawn_entity(18, 5, 312); //J
  spawn_entity(10, 5, 306); //K
  spawn_entity(12, 5, 318); //F
  spawn_entity(14, 5, 348); //G
  spawn_entity(16, 7, 336); //N
  spawn_entity(18, 7, 150); //square half fill
  spawn_entity(10, 7, 162); //Z
  spawn_entity(12, 7, 174); //+
  spawn_entity(14, 7, 186); //square
  spawn_entity(16, 9, 258); // /
  spawn_entity(18, 9, 210); // o-
  spawn_entity(10, 9, 222); // R mirror
  spawn_entity(12, 9, 234); // T
  spawn_entity(14, 9, 246); // π
  ...
```

### How do you win?
After poking around for a really long time, I figured `check_win_condition` wasn't really the function that I should be looking at, instead there was this mysterious function above it called `code` which takes in 5 arguments...

*Same as the number of blocks in a row/column of the grid. Coincidence? I think not*

Doing the same thing: clean up, closure compile...

```javascript
function code(b, c, d, e, f) {
  var a = g_a - 16;
  a[15] = b;
  a[14] = c;
  a[13] = d;
  a[12] = e;
  a[11] = f;
  return 42 * (a[15] & 255) + 1337 * (a[14] & 255) + (a[13] & 255) + (a[13] & 255 ^ a[12] & 255) + ((a[11] & 255) << 1) & 255;
}
```

This looks promising! So I searched what function called it, and found myself in `check_code` (oddly enough, this function was never actually called anywhere else). Here's the simplified code:

```javascript
function check_code(c, g, h, k) {
  ...
  c = get_code_value(a[4][0]);
  a[11] = c;
  c = get_code_value(a[4][1]);
  a[10] = c;
  c = get_code_value(a[4][2]);
  a[9] = c;
  c = get_code_value(a[4][3]);
  a[8] = c;
  c = get_code_value(a[4][4]);
  a[7] = c;
  ...
  b = code(a[11] & 255, a[10] & 255, a[9] & 255, a[8] & 255, a[7] & 255);
  a[6] = b;
  if (!(a[6] & 255)) {
    // returns 1
    return ..., a[31] = 1, b = a[31], b &= 1, ..., b;
  }
  a[31] = 0;
  b = a[31];
  b &= 1;
  ...
  // returns 0
  return b;
}
```

Intuitively, we expect `check_code` to return 1. The result of `code` is masked with 255, so `code` must return 0 in order to satisfy the if-statement. We can test this out using the example in the level (the one that is highlighted)

{% include image.html url="/assets/images/dice_is_you_2.png" description="Their entity_id is 210, 174, 324, 330, 198 respectively" %}

Firing up python, we can verify that our concept is corr...
```python
>>> 42*(210&255)+1337*(174&255)+(324&255)+((324&255)^(330&255))+((198&255)<<1)&255
16
```

Wait, what? Maybe I got it revers...
```python
>>> 42*(198&255)+1337*(330&255)+(324&255)+((324&255)^(174&255))+((210&255)<<1)&255
200
```

So... It seems like `code` doesn't take in `entity_id`s to compute the result. But luckily I noticed that what's being passed is the result of `get_code_value`, and its argument is hopefully the `entity_id`.

In summary, `get_code_value` takes in an argument, minus 138 from it, then puts it through a switch statement (210 cases O.o). Each case will return a different value, so I plugged in the `entity_id`s and gathered their respective "code_value".

```
y, 212
x, 194
o+, 189
E, 48
∆, 192
O., 18
D, 25
I, 120
|_, 55
L mirror, 1
∆filled, 61
J, 135
K, 138
F, 49
G, 96
N, 148
square half fill, 119
Z, 247
+, 160
square, 179
 /, 163
 o-, 171
 R mirror, 5
 T, 183
 π, 150
```

Am I finally on the right track? Well...

```python
>>> 42*(171&255)+1337*(160&255)+(194&255)+((194&255)^(212&255))+((189&255)<<1)&255
0
```

YES! So what's left to do is to write a z3 solver to solve for the correct configuration, then push the blocks accordingly and get the flag!

# Final Script
```python
from z3 import *
s = Solver()
ans = [BitVec(str(i), 9) for i in range(25)]
cond = "42*(ans[%s]&255)+1337*(ans[%s]&255)+(ans[%s]&255)+(ans[%s]&255^ans[%s]&255)+((ans[%s]&255)<<1)&255 == 0"

values = [212, 194, 189, 48, 192, 18, 25, 120, 55, 1, 61, 135, 138, 49, 96, 148, 119, 247, 160, 179, 163, 171, 5, 183, 150]

for i in range(len(ans)):
    scond = "ans[%d] == %d" % (i, values[0])
    for j in values[1:]:
        scond = "Or(%s, ans[%d] == %d)" % (scond, i, j)
    s.add(eval(scond))

s.add(ans[0] == values[0])
s.add(ans[1] == values[1])
s.add(ans[2] == values[2])
s.add(ans[5] == values[3])
s.add(ans[10] == values[4])
for i in range(5):
    # row
    x = 5*i
    s.add(eval(cond % (str(x),str(x+1),str(x+2),str(x+2),str(x+3),str(x+4))))
    # col
    s.add(eval(cond % (str(i),str(i+5),str(i+10),str(i+10),str(i+15),str(i+20))))

for i in range(24):
    for j in range(i+1, 25):
        s.add(eval("ans[%s] != ans[%s]" % (str(i), str(j))))

values.sort()
while s.check() == sat:
    model = s.model()
    result = str(s.model())
    result = list(map(lambda x: int((x.split(' = ')[1]).replace(']', '')), ''.join(result.split("\n")).split(',')))
    result.sort()
    ok = True
    for i in range(len(result)):
        if values[i] != result[i]:
            ok = False
            break
    if ok:
        print(model)
        break
```

*There's definitely a better way to script this but oh well ¯\\_(ツ)_/¯*

{% include image.html url="/assets/images/dice_is_you_3.png" description="dice{d1ce_1s_y0u_is_th0nk_73da6}" %}