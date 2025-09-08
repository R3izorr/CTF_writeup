# nimrod
**Category:** Reversing
**Difficulty:** Easy
**Author:** Eth007

## Description

And Cush begat Nimrod: he began to be a mighty one in the earth.

## Distribution

- `nimrod`

## Solution
### 1 Try to run the program
We’re given a stripped binary compiled from Nim. Running it shows:

$ ./nimrod

Enter the flag:

Entering random input prints: Incorrect..
### 2 Reversing the file
$ file nimrod
```
nimrod: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d2214d1703d64f0f7620e8d86f2790ebc1f0b861, for GNU/Linux 3.2.0, not stripped
```
Load the binary into Ghidra (or your favorite disassembler). In main (or Nim’s generated entry), the essential check looks like:
```
uVar1 = xorEncrypt__nimrod_46(userInput, 0x13371337);
cVar2 = eqeq___nimrod_69(uVar1, encryptedFlag__nimrod_10);
if (cVar2 == '\0') {
    echoBinSafe(..., "Incorrect.");
} else {
    echoBinSafe(..., "Correct!");
}

```
From this we learn:
The binary encrypts our input via xorEncrypt__nimrod_46.\
It compares the result to a global encryptedFlag__nimrod_10.\
Inspecting the global in .rodata (addresses will vary):
```
0x116e0: len=0x22   cap=...
0x116f0: 28 f8 3e e6 3e 2f 43 0c ...

```
So the ciphertext length is 34 bytes (0x22).

Looking into xorEncrypt__nimrod_46 shows it calls:
```
keystream__nimrod_20(0x13371337, len)

```
Then XORs the input with the returned bytes:
```
cipher[i] = input[i] ^ keystream[i]

```
### 3 Exploitation 
We’ll extract the keystream at runtime. The idea:

1. Break at keystream__nimrod_20.

2. Run the program and provide 34 characters (same length as the ciphertext).

3. After the function returns, $rax will hold a pointer to the Nim seq header for the keystream.
In Nim, a seq is a heap object; the actual byte data is at header + 0x10.

4. Read the global encryptedFlag similarly (it’s also a Nim seq), then XOR.    
Step by step with GDB
```
$ gdb ./nimrod
(gdb) b keystream__nimrod_20
Breakpoint 1 at 0x...  # address will vary

(gdb) run
Starting program: ./nimrod
Enter the flag:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# (34 'a's; length MUST be 0x22 to match ciphertext)

```
At the breakpoint, confirm the requested length:
```
(gdb) p/x $rsi
$1 = 0x22

```
Continue to the end of the keystream function so $rax holds the returned seq pointer:
```
(gdb) finish
Run till exit from #0  keystream__nimrod_20 (...)
Value returned is $2 = (void *) 0x...   # Nim seq header pointer

```
Now use GDB Python to read both the ciphertext and the keystream, then XOR:
```python
(gdb) python
import gdb
inf = gdb.selected_inferior()
N = 0x22  # 34 bytes

# 1) Read the global encryptedFlag Nim seq
# &encryptedFlag__nimrod_10 is a POINTER to the seq header
enc_ptr = int(gdb.parse_and_eval("&encryptedFlag__nimrod_10"))
# Read 8 bytes at that pointer to get the seq header address
enc_hdr = int.from_bytes(inf.read_memory(enc_ptr, 8).tobytes(), "little")
# Data starts at header + 0x10
enc = inf.read_memory(enc_hdr + 0x10, N).tobytes()

# 2) Read the returned keystream Nim seq
ks_hdr = int(gdb.parse_and_eval("$rax"))
ks = inf.read_memory(ks_hdr + 0x10, N).tobytes()

# 3) XOR ciphertext with keystream
flag = bytes([e ^ k for e, k in zip(enc, ks)])
print(flag.decode())
end
```
### The output will be: ictf{a_mighty_hunter_bfc16cce9dc8}

