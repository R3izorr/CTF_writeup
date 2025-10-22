# CTF Write-up — “encrypter” (AES-256-CBC + Embedded Shellcode Key)

## Overview

- **Category:** Reversing / Crypto  
- **Difficulty:** Medium  
- **Target:** `encrypter` ELF  
- **Goal:** Recover the flag by decrypting `flag.enc`  
- **Flag:** `QnQSec{a_s1mpl3_fil3_3ncrypt3d_r3v3rs3}`  

---

## Recon

### Initial observation

Given two files:  
- `encrypter` — ELF binary  
- `flag.enc` — encrypted file  

First, check file type and embedded strings:

```bash
file encrypter
Output:

encrypter: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=752a80f792346585e1f82a8489545681ceff877d, for GNU/Linux 4.4.0, not stripped
Check for any reference to flag files:

strings encrypter | grep "flag"
Output:

flag.enc
flag.txt
Encrypted -> flag.enc
So the binary reads from flag.txt and writes to flag.enc — clearly an encryptor.
```
Static Analysis
Opened in Ghidra — main function reconstructed as:

```bash
undefined8 main(int param_1, undefined8 *param_2)
{
    int iVar1;
    undefined8 uVar2;
    long in_FS_OFFSET;
    char local_48[16];
    undefined8 local_38;
    undefined8 local_30;
    undefined8 local_28;
    undefined8 local_20;
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);

    if (param_1 < 2) {
        printf("Usage: %s encrypt", *param_2);
        uVar2 = 1;
    } else {
        memset(local_48, 0, 16);
        strncpy(local_48, "1337", 0x10);
        memset(&local_38, 0, 0x20);
        iVar1 = call_embedded_shellcode(&local_38, 0x20);

        if (iVar1 == 0) {
            fwrite("Failed to produce key via shellcode\n", 1, 0x24, stderr);
            uVar2 = 2;
        } else {
            iVar1 = strcmp((char *)param_2[1], "encrypt");
            if (iVar1 == 0) {
                iVar1 = encrypt_file("flag.txt", "flag.enc", &local_38, local_48);
                if (iVar1 == 0)
                    puts("Encrypt failed");
                else
                    puts("Encrypted -> flag.enc");
            }
        }
    }
    return uVar2;
}
```
### Key insights from main
Uses AES-256-CBC via OpenSSL (EVP_aes_256_cbc() inside do_crypto).

IV (local_48) initialized as "1337" then zero-padded → 16 bytes total.

The 32-byte key is not hard-coded — generated at runtime by executing embedded shellcode:

```
call_embedded_shellcode(&local_38, 0x20);
```
Shellcode is copied to an RWX mmap region and called.
### The encryption flow
```
encrypt_file("flag.txt", "flag.enc", key, iv);
```
→ calls do_crypto()
→ uses OpenSSL EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_EncryptFinal_ex.

So the encryption logic is standard AES-256-CBC.


### Thus, to decrypt flag.enc, we need:

- The key (produced by shellcode)

- The IV (31333337000000000000000000000000 in hex)

### Dynamic Analysis — Extracting Key and IV
We can get the key during runtime — just before OpenSSL performs encryption.

### Idea
- Break at the call to EVP_EncryptInit_ex inside libcrypto.so.

- Arguments on x86-64 SysV ABI:

Argument	Register	Meaning
- 4th	RCX	Key pointer
- 5th	R8	IV pointer

### Preparation
The program only runs if it can open flag.txt.
Create a dummy one:

```
echo -n "x" > flag.txt
```
### GDB Steps
```bash

gdb -q ./encrypter
set breakpoint pending on
set stop-on-solib-events 1
set disable-randomization on
break EVP_EncryptInit_ex
run encrypt
```
If you break at the PLT stub, single-step into the real function in libcrypto:


Once inside libcrypto, dump registers:

```bash

x/32xb $rcx    # key (32 bytes)
x/16xb $r8     # IV (16 bytes)
```
Dumped values
```perl

Key (hex): 74 68 31 5f 31 5f 73 5f 74 68 33 5f 76 61 6c 75
            33 5f 30 66 5f 6b 33 79 00 00 00 00 00 00 00 00
→ ASCII: "th1_1s_th3_valu3_0f_k3y"

IV (hex): 31 33 33 37 00 00 00 00 00 00 00 00 00 00 00 00
→ ASCII: "1337" + zero padding
```
## Decrypting flag.enc
### Using OpenSSL CLI
```bash

KEYHEX="7468315f315f735f7468335f76616c75335f30665f6b3379000000000000000000000000000000"
IVHEX="31333337000000000000000000000000"

openssl enc -aes-256-cbc -d \
  -in flag.enc -out flag.txt \
  -K "$KEYHEX" -iv "$IVHEX"
```
### Or in Python (PyCryptodome)
```python
from Crypto.Cipher import AES
from pathlib import Path

key = b"th1_1s_th3_valu3_0f_k3y" + b"\x00"*(32 - len("th1_1s_th3_valu3_0f_k3y"))
iv  = b"1337" + b"\x00"*12

ct = Path("flag.enc").read_bytes()
pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)

# PKCS#7 unpad
n = pt[-1]
if 1 <= n <= 16 and pt.endswith(bytes([n])*n):
    pt = pt[:-n]

print(pt.decode("utf-8", errors="replace"))
```
## Output:

```
QnQSec{a_s1mpl3_fil3_3ncrypt3d_r3v3rs3}
```