# Using FLAIR to Deal with Static, Stripped ELFs

One of the biggest unknowns you will deal with in the exploit/RE CTF challenges
is ELFs that are statically linked and stripped.  When you analyze the binary
with IDA, you get no information about the library calls the code is making. 

IDA provides the FLAIR tools to help restore this information. This writeup
hopefully provides a comprehensive procedure to get it done quickly so you can
get back to pwning.

This procedure is assumed to be running on a Ubuntu LTS box and have a purchased
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

Or better yet if you can ssh into the server, log in and run

```
cat /etc/lsb-release
```

Scan the binary itself for the compile time to at least give an idea of
what libc versions may have been around at the time:

```
readelf -a ./binary
```

Are there other challenge binaries that are dynamically linked? If so, examine
the versions of libc they link against.

If these methods don't return much, then you may need to identify multiple
candidate libc.a's and iterate the process to find the one that provides the
best result.

Now, clone the libc database project:

```
https://github.com/niklasb/libc-database
cd libc-database
```

Edit the "get" file to add any additional libc versions you might want to try
out. Then edit the "get_ubuntu" function in common/libc.sh to also pick out the
static libc.a files (what FLAIR operates on)

Then run "./get". You'll have version-named libc copies in db. You can always
re-run get to update.


## Step 2: Use FLAIR Utilities To Make Signatures

Find your copy of IDA and locate the "flair65.zip" archive. (65 will be whatever
version of IDA you obtained). Extract it somewhere, cd to it, and chmod +x
bin/linux/*.

```
./bin/linux/pelf /usr/lib/x86_64-linux-gnu/libc.a ./libc.pat
./bin/linux/sigmake ./libc.pat libc.sig
```

Edit the libc.exc collisions file. If none of the symbols listed are ones you
think you'll care about, just delete the commented lines and save the file. Then
run:

```
./bin/linux/sigmake -n "libc6-amd64_2.19-0ubuntu6" ./libc.pat libc.sig
./bin/linux/zipsig ./libc.sig
```

Now copy the libc.sig file to IDA_Install_Directory/sig/. 

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
