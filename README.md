CryptoDev-P
===========

This is a Pascal interface to use the cryptodev module for Linux
using the Free Pascal Compiler.

It also contains a 1:1 conversion of the Linux *ioctl.h* headers,
and the conversion of the *cryptodev.h* header.

Since the API is the same, it should work with OpenBSD and FreeBSD
but this was never tested. Patches and feedback is welcomed!

Also contains test code to test the header unit's validity against
the C equivalent. It was tested and proven to work on x86, x86_64,
ARM and 32bit PowerPC.

CryptoDev Linux
---------------

For more information about the cryptodev-linux module itself, see:

http://cryptodev-linux.org/

How To Use
----------

Use the provided *cryptodevtest.sh* to test the validity of the
header for your system. The *speed.pas* example should then by
simply using:

    fpc speed.pas

