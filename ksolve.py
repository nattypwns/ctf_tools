#!/usr/bin/env python
import angr
import claripy
import logging
import sys
import struct

logging.basicConfig()
# angr.manager.l.setLevel('DEBUG')


decArr="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX""
def encKey(kbin):
    ink = ""
    for c in kbin:
        ink += decArr[ord(c)]
    print "Key=" + ink

def dumpstate(state):
    '''
    Print out registers/memory of interest in given state
    '''
    print '-'*80
    print "EIP=0x%08x" % state.se.eval(state.state.regs.eip)
    print "EAX=0x%08x" % state.se.eval(state.state.regs.eax)
    print "ECX=0x%08x" % state.se.eval(state.state.regs.ecx)
    print "EBP=0x%08x" % state.se.eval(state.state.regs.ebp)
    print "XMM0=0x%032x" % state.se.eval(state.state.regs.xmm0)
    print "XMM1=0x%032x" % state.se.eval(state.state.regs.xmm1)

    addr = state.state.memory.load(state.state.regs.esi, endness='Iend_LE')
    concrete_addr = state.state.se.eval(addr)
    print "pInput=" + hex(concrete_addr)
    mem = state.state.se.eval(state.state.memory.load(state.state.regs.ebp-0x38, KEYLEN), cast_to=str)
    print "Input=" + repr(mem)
    mem = state.state.se.eval(state.state.memory.load(state.state.regs.ebp - 0x3C, endness='Iend_LE'), cast_to=int)
    print "NumDecoded=0x%08x" % mem
    mem = state.state.se.eval(state.state.memory.load(state.state.regs.ebp - 0x20), cast_to=str)
    print "CRC=" + repr(mem[0])
    kmem = state.state.se.eval_upto(state.state.memory.load(state.state.regs.ebp - 0x38, KEYLEN), 1, cast_to=str)
    for k in kmem:
        encKey(k)
    print '-'*80


PROG = "./GL.dll" # changed
KEYLEN = 25 
    
BASE=0x10000000

# Set up path endpoints we want to hit and avoid
GOAL2 = BASE+0x3b497 # mov al, 1
GOAL = BASE+0x3b429 # after crc check
FAIL = BASE+0x3b377

def solve_phase2():
    print "="*80
    print sys._getframe().f_code.co_name
    print "="*80

    b = angr.Project(PROG, load_options={'auto_load_libs': False})

    # Set our program state at an area of interest in our RE function
    # Set the EBP to something reasonable in high mem
    # We are using BLANK state, so we'll set up everything we need
    START = BASE+0x3b3a2
    istate = b.factory.blank_state(addr=START)
    istate.regs.ebp = 0x7fff0000

    # print where we are - nice way to verify the disasm matches up
    block = b.factory.block(START)
    block.pp()

    # Create a BitValue Symbol (BVS) for the length of 
    # memory we want to set constraints on. Set each
    # byte to be less than the length of the "base32" decode array
    decoded = claripy.BVS('decoded', 25*8)
    for d in decoded.chop(8):
        istate.add_constraints(d < '\x20')
   
    # The last check XORs the back against the front, constrain our
    # input. This was obtained through RE/debugging
    lastHalf="\x1f\x1e\x17\x0e\x0d\x09\x1a\x18\x1e\x0d\x0c\x1d"
    ds = decoded.chop(8)
    for i in xrange(12):
	istate.add_constraints(ds[12+i] == lastHalf[i])

    # Store the bitvector where it should be on the stack
    # as per the IDA disassm.
    istate.memory.store(istate.state.regs.ebp-0x38, decoded)
   
    # Store our key length variable on the stack.
    # NOTE: Any variable accessed with a known needed-value must be set up!
    dumpstate(istate)

    # Set up our Simulation Manager with our initial state and explore!
    # Step1: Solve to the CRC check
    simgr = b.factory.simgr(istate)
    simgr.explore(find=GOAL, avoid=[FAIL])

    # Blocks until we can find a path to GOAL
    f = simgr.found[0]
    dumpstate(f)
    
  
    # The KeyVerifier function modifies our input! We need to save a copy of
    # what the valid input is before this modification occurrs. 
    def stash_key(state):
        stashkey = state.se.eval(state.memory.load(state.regs.ebp-0x38, KEYLEN), cast_to=str)
        print "Stashing key before program modifes: " + repr(stashkey)
        state.memory.store(0x77000000, stashkey)

    f.inspect.b('mem_write', when=angr.BP_BEFORE, action=stash_key, mem_write_address=f.state.regs.ebp-0x38)
   
    # Now solve from here to the end
    simgr = b.factory.simgr(f)
    simgr.explore(find=GOAL2, avoid=[FAIL])
    f = simgr.found[0]

    # dumpstate will show our modified input buffer, but we can retrieve our
    # stashed key that got us here
    dumpstate(f)

    print "FINAL:"
    # data is always loaded/stored in a "big-endian" fashion, since the primary purpose 
    # of state.memory is to load an store swaths of data. Make sure we are
    # explicitly LE when we load up our key or it will be reversed
    stashkey = f.se.eval(f.memory.load(0x77000000, KEYLEN, endness='Iend_LE'), cast_to=str)
    encKey(stashkey)

solve_phase2()
   

