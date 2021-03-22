---
title : "What do the numbas mean? [RE]"
categories: CTFSG2021
---

Analyze python Intermediate Representation and recover the flag. First RE challenge from CTF.SG 2021.

# Challenge Description
Agent: “Only you can tell us what the codes mean. We have the broadcast, we have been playing to you over and over again for hours but we haven’t been able to break through your programming yet. This is our last shot.”

We are given a [text file]({{ site.url }}/files/whatdothenumbasmean.txt)

# Solution
First thing I did was to change the extension of the file to `.py` to get some syntax highlighting in vscode (even though it isn't actually python, the highlighting still worked okay).

```python
---------------------------IR DUMP: what_do_they_mean---------------------------
label 0:
    flag = arg(0, name=flag)                 ['flag']
    $const4.1 = const(int, 0)                ['$const4.1']
    $6binary_subscr.2 = static_getitem(value=flag, index=0, index_var=$const4.1, fn=<built-in function getitem>) ['$6binary_subscr.2', '$const4.1', 'flag']
    $const8.3 = const(str, C)                ['$const8.3']
    $10compare_op.4 = $6binary_subscr.2 != $const8.3 ['$10compare_op.4', '$6binary_subscr.2', '$const8.3']
    bool12 = global(bool: <class 'bool'>)    ['bool12']
    $12pred = call bool12($10compare_op.4, func=bool12, args=(Var($10compare_op.4, whatdothenumbasmean.py:26),), kws=(), vararg=None) ['$10compare_op.4', '$12pred', 'bool12']
    branch $12pred, 86, 14                   ['$12pred']
label 14:
    $const16.1 = const(int, 1)               ['$const16.1']
    $18binary_subscr.2 = static_getitem(value=flag, index=1, index_var=$const16.1, fn=<built-in function getitem>) ['$18binary_subscr.2', '$const16.1', 'flag']
    $const20.3 = const(str, T)               ['$const20.3']
...
```

If we take a look at the first few lines, without knowing much of python IR syntax, one can deduce that it is checking whether `flag[0] == 'C'`. This is after seeing that `label 86` is a destination of failing the check. Seen below:

```python
label 86:
    $const86.0 = const(bool, False)          ['$const86.0']
    $88return_value.1 = cast(value=$const86.0) ['$88return_value.1', '$const86.0']
    return $88return_value.1                 ['$88return_value.1']
```

Applying this same logic and understanding, we can quickly disect the following few blocks of code. We get these:

```python
flag = "CTFSG{...}"
```

---

```python
label 90:
    $const92.1 = const(int, 6)               ['$const92.1']
    $const94.2 = const(int, -1)              ['$const94.2']
    $96build_slice.3 = global(slice: <class 'slice'>) ['$96build_slice.3']
    $96build_slice.4 = call $96build_slice.3($const92.1, $const94.2, func=$96build_slice.3, args=(Var($const92.1, whatdothenumbasmean.py:35), Var($const94.2, whatdothenumbasmean.py:35)), kws=(), vararg=None) ['$96build_slice.3', '$96build_slice.4', '$const92.1', '$const94.2']
    $98binary_subscr.5 = static_getitem(value=flag, index=slice(6, -1, None), index_var=$96build_slice.4, fn=<built-in function getitem>) ['$96build_slice.4', '$98binary_subscr.5', 'flag']
    buf = $98binary_subscr.5                 ['$98binary_subscr.5', 'buf']
    $102load_global.6 = global(len: <built-in function len>) ['$102load_global.6']
    $106call_function.8 = call $102load_global.6(buf, func=$102load_global.6, args=[Var(buf, whatdothenumbasmean.py:35)], kws=(), vararg=None) ['$102load_global.6', '$106call_function.8', 'buf']
    $const108.9 = const(int, 16)             ['$const108.9']
    $110compare_op.10 = $106call_function.8 != $const108.9 ['$106call_function.8', '$110compare_op.10', '$const108.9']
    bool112 = global(bool: <class 'bool'>)   ['bool112']
    $112pred = call bool112($110compare_op.10, func=bool112, args=(Var($110compare_op.10, whatdothenumbasmean.py:36),), kws=(), vararg=None) ['$110compare_op.10', '$112pred', 'bool112']
    branch $112pred, 114, 118                ['$112pred']
...
```

It should be quite easy to see that this takes a slice (or substring) from index 6 to -1 (exclusive), and checking whether it is of length 16. At this point, we know that the flag looks like

`CTFSG{<string of length 16>}`

---

```python
label 118:
    $120load_method.1 = getattr(value=buf, attr=startswith) ['$120load_method.1', 'buf']
    $const122.2 = const(str, th3)            ['$const122.2']
    $124call_method.3 = call $120load_method.1($const122.2, func=$120load_method.1, args=[Var($const122.2, whatdothenumbasmean.py:40)], kws=(), vararg=None) ['$120load_method.1', '$124call_method.3', '$const122.2']
    bool126 = global(bool: <class 'bool'>)   ['bool126']
    $126pred = call bool126($124call_method.3, func=bool126, args=(Var($124call_method.3, whatdothenumbasmean.py:40),), kws=(), vararg=None) ['$124call_method.3', '$126pred', 'bool126']
    branch $126pred, 132, 128                ['$126pred']
...
label 132:
    $const132.0 = const(str, numb)           ['$const132.0']
    $136compare_op.2 = $const132.0 in buf    ['$136compare_op.2', '$const132.0', 'buf']
    $136compare_op.2 = unary(fn=<built-in function not_>, value=$136compare_op.2) ['$136compare_op.2', '$136compare_op.2']
    bool138 = global(bool: <class 'bool'>)   ['bool138']
    $138pred = call bool138($136compare_op.2, func=bool138, args=(Var($136compare_op.2, whatdothenumbasmean.py:44),), kws=(), vararg=None) ['$136compare_op.2', '$138pred', 'bool138']
    branch $138pred, 140, 144                ['$138pred']
...
```

This tells us that the string startswith "th3" and "numb" is a substring of the flag.

---

```python
label 152:
    $152for_iter.1 = iternext(value=$phi152.0) ['$152for_iter.1', '$phi152.0']
    $152for_iter.2 = pair_first(value=$152for_iter.1) ['$152for_iter.1', '$152for_iter.2']
    $152for_iter.3 = pair_second(value=$152for_iter.1) ['$152for_iter.1', '$152for_iter.3']
    $phi154.1 = $152for_iter.2               ['$152for_iter.2', '$phi154.1']
    branch $152for_iter.3, 154, 194          ['$152for_iter.3']
label 154:
    ch = $phi154.1                           ['$phi154.1', 'ch']
    $const156.2 = const(int, 97)             ['$const156.2']
    $158load_global.3 = global(ord: <built-in function ord>) ['$158load_global.3']
    $162call_function.5 = call $158load_global.3(ch, func=$158load_global.3, args=[Var(ch, whatdothenumbasmean.py:48)], kws=(), vararg=None) ['$158load_global.3', '$162call_function.5', 'ch']
    $168compare_op.7 = $const156.2 <= $162call_function.5 ['$162call_function.5', '$168compare_op.7', '$const156.2']
    bool170 = global(bool: <class 'bool'>)   ['bool170']
    $170pred = call bool170($168compare_op.7, func=bool170, args=(Var($168compare_op.7, whatdothenumbasmean.py:49),), kws=(), vararg=None) ['$168compare_op.7', '$170pred', 'bool170']
    $phi172.1 = $162call_function.5          ['$162call_function.5', '$phi172.1']
    branch $170pred, 172, 180                ['$170pred']
label 172:
    $const172.2 = const(int, 122)            ['$const172.2']
    $174compare_op.3 = $phi172.1 <= $const172.2 ['$174compare_op.3', '$const172.2', '$phi172.1']
    bool176 = global(bool: <class 'bool'>)   ['bool176']
    $176pred = call bool176($174compare_op.3, func=bool176, args=(Var($174compare_op.3, whatdothenumbasmean.py:49),), kws=(), vararg=None) ['$174compare_op.3', '$176pred', 'bool176']
    branch $176pred, 178, 297                ['$176pred']
label 178:
    jump 184                                 []
label 180:
    jump 297 
label 184:
    $const186.2 = const(int, 1)              ['$const186.2']
    $188inplace_add.3 = inplace_binop(fn=<built-in function iadd>, immutable_fn=<built-in function add>, lhs=letters, rhs=$const186.2, static_lhs=Undefined, static_rhs=Undefined) ['$188inplace_add.3', '$const186.2', 'letters']
    letters = $188inplace_add.3              ['$188inplace_add.3', 'letters']
    jump 297                                 []
label 194:
    $const196.1 = const(int, 10)             ['$const196.1']
    $198compare_op.2 = letters != $const196.1 ['$198compare_op.2', '$const196.1', 'letters']
    bool200 = global(bool: <class 'bool'>)   ['bool200']
    $200pred = call bool200($198compare_op.2, func=bool200, args=(Var($198compare_op.2, whatdothenumbasmean.py:51),), kws=(), vararg=None) ['$198compare_op.2', '$200pred', 'bool200']
    branch $200pred, 202, 206                ['$200pred']
...
label 297:
    jump 152                                 []
```

This iterates through the string and counts how many lowercase letters are there (decimal value between 97 and 122), the number should be 10.

---

```python
label 206:
    $const208.1 = const(int, 3)              ['$const208.1']
    $210binary_subscr.2 = static_getitem(value=buf, index=3, index_var=$const208.1, fn=<built-in function getitem>) ['$210binary_subscr.2', '$const208.1', 'buf']
    $const214.4 = const(int, 10)             ['$const214.4']
    $216binary_subscr.5 = static_getitem(value=buf, index=10, index_var=$const214.4, fn=<built-in function getitem>) ['$216binary_subscr.5', '$const214.4', 'buf']
    $218compare_op.6 = $210binary_subscr.2 != $216binary_subscr.5 ['$210binary_subscr.2', '$216binary_subscr.5', '$218compare_op.6']
    bool220 = global(bool: <class 'bool'>)   ['bool220']
    $220pred = call bool220($218compare_op.6, func=bool220, args=(Var($218compare_op.6, whatdothenumbasmean.py:55),), kws=(), vararg=None) ['$218compare_op.6', '$220pred', 'bool220']
    branch $220pred, 234, 222                ['$220pred']
label 222:
    $const224.1 = const(int, 3)              ['$const224.1']
    $226binary_subscr.2 = static_getitem(value=buf, index=3, index_var=$const224.1, fn=<built-in function getitem>) ['$226binary_subscr.2', '$const224.1', 'buf']
    $const228.3 = const(str, _)              ['$const228.3']
    $230compare_op.4 = $226binary_subscr.2 != $const228.3 ['$226binary_subscr.2', '$230compare_op.4', '$const228.3']
    bool232 = global(bool: <class 'bool'>)   ['bool232']
    $232pred = call bool232($230compare_op.4, func=bool232, args=(Var($230compare_op.4, whatdothenumbasmean.py:55),), kws=(), vararg=None) ['$230compare_op.4', '$232pred', 'bool232']
    branch $232pred, 234, 238                ['$232pred']
```

This says index 3 and 10 are both the character `_`. And the later parts are similar, it says index 8 and 12 are both `@`, index 14 is has ASCII value 48 which is `0`.

If we put our conditions together we get

`CTFSG{th3_####@#_#@#0#}`

where "numb" is a substring, and there's only one possible position for it.

`CTFSG{th3_numb@#_#@#0#}`

Since there are 10 lowercase letters in the string, we can see that all the unknown characters are lowercase letters. At this point I just guessed that the flag to be 

`CTFSG{th3_numb@s_m@s0n}`

and it turned out to be correct!

*Note: the intended solution (or at least what I think is) is to brute force the remaining characters by using the final part of the IR, which does a CRC checksum on the string and compares it to a desired value. But hey why do bruteforce when you can guess the flag ;)*
