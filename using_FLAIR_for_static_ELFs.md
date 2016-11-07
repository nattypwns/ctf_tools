# Using FLAIR to Deal with Static, Stripped ELFs

One of the annoying roadblocks you will deal with in exploit/RE CTF challenges
is an ELF that is statically linked and stripped.  When you analyze the binary
with IDA, you get no information about the library calls the code is making.

IDA provides the FLAIR tools to help restore this information. This writeup
hopefully provides a comprehensive procedure to get it done quickly so you can
get back to pwning.

This procedure is assumed to be running on a Ubuntu LTS box and that you have a purchased
IDA Pro copy.


## Step 1: libc Identification and Obtaining

In order to generate accurate signatures, we need to try to identify the exact version
of libc.a the binary was linked against. 

In most challenges, you'll be given the binary itself and possibly an
address/socket to connect to (e.g. nc pwn.com 12345). 
Run this nmap command to try and find out more about the server:

```
sudo nmap -A pwn.com`
```

Or better yet if you can ssh into the server, log in and run:

```
cat /etc/lsb-release
aptitude show libc
etc...
```

Scan the binary itself to see if there are any clues  to at least give an idea of
what libc versions may have been around at the time:

```
readelf -a ./binary
```

Are there other challenge binaries that are dynamically linked? If so, examine
the versions of libc they link against.

If these methods don't return much, then you may need to identify multiple
candidate libc.a's and iterate the process to find the one that provides the
best result.

You can do a search on http://packages.ubuntu.com/ once you have some versions.
The libc6-dev package has libc.a.

Let's assume that this is the libc we think was used:

http://security.ubuntu.com/ubuntu/pool/main/e/eglibc/libc6-dev_2.19-0ubuntu6.9_amd64.deb

Download that deb to a directory (LIBC_DL_DIR) and extract libc.a with:

```
dpg -x ./libc6-dev_2.19-0ubuntu6.9_amd64.deb .
cp usr/lib/x86_64-linux-gnu/libc.a libc6-dev_2.19-0ubuntu6.9_amd64.a
rm -rf usr/ *.deb
```

The process is roughly the same with the 32-bit version, just different paths.

## Step 2: Use FLAIR Utilities To Make Signatures

Find your copy of IDA and locate the "flair65.zip" archive. (65 will be whatever
version of IDA you obtained). Extract it somewhere, cd to it, and chmod +x
bin/linux/*. Now run these commands to create patterns/signatures:

```
./bin/linux/pelf LIBC_DL_DIR/libc6-dev_2.19-0ubuntu6.9_amd64.a libc6-dev_2.19-0ubuntu6.9_amd64.pat
./bin/linux/sigmake -n"libc6-dev_2.19-0ubuntu6.9_amd64.a" libc6-dev_2.19-0ubuntu6.9_amd64.pat libc6-dev_2.19-0ubuntu6.9_amd64.sig
```

Edit the libc.exc collisions file, if it was created. If none of the symbols listed are ones you
think you'll care about (they probably aren't), just delete the commented lines and save the file. Then
run it again, and compress the final result:

```
./bin/linux/sigmake -n"libc6-dev_2.19-0ubuntu6.9_amd64.a" libc6-dev_2.19-0ubuntu6.9_amd64.pat libc6-dev_2.19-0ubuntu6.9_amd64.sig
./bin/linux/zipsig libc6-dev_2.19-0ubuntu6.9_amd64.sig
```

Now copy the libc6-dev_2.19-0ubuntu6.9_amd64.sig file to IDA_INSTALL_DIR/sig/. 

## Step 3: Apply Signatures

Open IDA Pro and import and analyze your challenge binary now. Then click
View...Open Subviews...Signatures. Right click in the Signatures view, and click
"Apply New Signature".  Then browse down to your signature and select it. 

IDA will now try to apply the signatures. In the case where the libc matches
"perfectly", the "#func" column will have ~780 entries. You should now have a
huge amount of the code bar remarked for "Library function" data now and a lot
of renamed functions!

Some seemingly obvious functions (like strcmp) may not be renamed. For these,
follow the execution down a few levels to see if there are defined symbols in
deeper functions that can give you a hint. Then rename the function to match.

If there is still a lot of "Regular function" data, try to identify if other
common libraries like libm.a, libz.a, etc are included and repeat the process
with those to get more.

## Extra/TODO

* Any way to do this type of enrichment for GDB?

