#!/usr/bin/env python
import angr
import simuvex
import logging
from IPython import embed

def main():

    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('angr.path_group').setLevel(logging.DEBUG)

    #
    # Load the binary. This is a 32-bit C binary that takes a string from stdin
    # https://picoctf.com/problem-static/reversing/bitpuzzle/bitpuzzle
    #
    # $ ./bitpuzzle 
    # Bet you can't solve my puzzle!
    # Give me a string.
    # hereismyguess
    # Sorry, hereismyguess is not the right string!
    #
    p = angr.Project('bitpuzzle')

    # This block constructs the initial program state for analysis.
    st = p.factory.full_init_state(args=['./bitpuzzle'], add_options=simuvex.o.unicorn, remove_options={simuvex.o.LAZY_SOLVES})

    #
    # Set up the stdin symbolic input:
    #
    # It's reasonably easy to tell from looking at the program in IDA that the input will
    # be 33 bytes long, and the last byte is a newline.

    # Constrain the first 32 bytes to be non-null and non-newline:
    for _ in xrange(32):
        k = st.posix.files[0].read_from(1)
        st.se.add(k != 0)
        st.se.add(k != 10)

    # Constrain the last byte to be a newline
    k = st.posix.files[0].read_from(1)
    st.se.add(k == 10)

    # Reset the symbolic stdin's properties and set its length.
    st.posix.files[0].seek(0)
    st.posix.files[0].length = 33


    # Construct a path group to perform symbolic execution.
    # avoiding error blocks and finding success block
    pg = p.factory.path_group(st)
    pg.explore(find=0x080486b3, avoid=[0x0804856a,0x080486c1])

    # Get the stdout of the path in our explored path group
    for pp in pg.found:
        print pp.state.posix.dumps(0)

    # Runs in about 15 seconds!

if __name__ == "__main__":
    main()
