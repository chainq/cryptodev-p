{
  A Pascal conversion of the Linux ioctl.h headers

  Copyright (c) 2013-2014  Karoly Balogh <karoly.balogh@viprinet.com>

  Conversion itself subject to the same GPLv2 license as the original,
  headers, however since using the headers doesn't create a derivative
  work, it may be used freely in applications with any license, also
  closed source.
}
{$IFDEF LINUX}

{ Note: the unit was only tested with Free Pascal, but it should work
        with Kylix as well, in case someone still needs that. }
{$IFDEF FPC}
{$IFDEF CPUPOWERPC}
{$DEFINE USE_OSF_1_ABI}
{$ENDIF}
{$IFDEF CPUMIPS}
{$DEFINE USE_OSF_1_ABI}
{$ENDIF}
{$IFDEF CPUSPARC}
{$DEFINE USE_OSF_1_ABI}
{$ENDIF}
{$ENDIF}

unit linuxioctl;

interface

uses ctypes;

{* ioctl command encoding: 32 bits total, command in lower 16 bits,
 * size of the parameter structure in the lower 14 bits of the
 * upper 16 bits.
 * Encoding the size of the parameter structure in the ioctl request
 * is useful for catching programs compiled with old versions
 * and to avoid overwriting user space outside the user buffer area.
 * The highest 2 bits are reserved for indicating the ``access mode''.
 * NOTE: This limits the max parameter size to 16kB -1 !
 *}

{*
 * The following is for compatibility across the various Linux
 * platforms.  The generic ioctl numbering scheme doesn't really enforce
 * a type field.  De facto, however, the top 8 bits of the lower 16
 * bits are indeed used as a type field, so we might just as well make
 * this explicit here.  Please be sure to use the decoding macros
 * below from now on.
 *}
const
  _IOC_NRBITS = 8;
  _IOC_TYPEBITS = 8;

{*
 * Let any architecture override either of the following before
 * including this file.
 *}
{ Pascal conversion note:
    Some Linux platforms like PowerPC, MIPS or Sparc use different 
    based on OSF/1 ABI values, see the CPU defines above }
const
{$IFDEF USE_OSF_1_ABI}
  _IOC_SIZEBITS = 13;
  _IOC_DIRBITS  = 3;
{$ELSE}
  // default, true for ARM, x86, x86_64 and m68k at least
  _IOC_SIZEBITS = 14;
  _IOC_DIRBITS  = 2;
{$ENDIF}


const
  _IOC_NRMASK   = ((1 shl _IOC_NRBITS)-1);
  _IOC_TYPEMASK = ((1 shl _IOC_TYPEBITS)-1);
  _IOC_SIZEMASK = ((1 shl _IOC_SIZEBITS)-1);
  _IOC_DIRMASK  = ((1 shl _IOC_DIRBITS)-1);

  _IOC_NRSHIFT   = 0;
  _IOC_TYPESHIFT = (_IOC_NRSHIFT + _IOC_NRBITS);
  _IOC_SIZESHIFT = (_IOC_TYPESHIFT + _IOC_TYPEBITS);
  _IOC_DIRSHIFT  = (_IOC_SIZESHIFT + _IOC_SIZEBITS);

{*
 * Direction bits, which any architecture can choose to override
 * before including this file.
 *}
{ Pascal conversion note:
    Some Linux platforms like PowerPC, MIPS or Sparc use different 
    based on OSF/1 ABI values, see the CPU defines above }
const
{$IFDEF USE_OSF_1_ABI}
  _IOC_NONE = 1;
  _IOC_READ = 2;
  _IOC_WRITE = 4;
{$ELSE}
  // default, true for ARM, x86, x86_64 and m68k at least
  _IOC_NONE = 0;
  _IOC_WRITE = 1;
  _IOC_READ = 2;
{$ENDIF}

function _IOC(dir, type_, nr, size: cuint32): cuint32;

{ Not converted for now. Todo? }
{#ifndef __KERNEL__
#define _IOC_TYPECHECK(t) (sizeof(t))
#endif}

{* used to create numbers *}
function _IO(type_, nr: cuint): cuint;
function _IOR(type_, nr, size: cuint): cuint;
function _IOW(type_, nr, size: cuint): cuint;
function _IOWR(type_, nr, size: cuint): cuint;

{ Legacy stuff, we shouldn't need this... }
{#define _IOR_BAD(type,nr,size)	_IOC(_IOC_READ,(type),(nr),sizeof(size))
#define _IOW_BAD(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#define _IOWR_BAD(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))}

{* used to decode ioctl numbers.. *}
function _IOC_DIR(nr: cuint): cuint;
function _IOC_TYPE(nr: cuint): cuint;
function _IOC_NR(nr: cuint): cuint;
function _IOC_SIZE(nr: cuint): cuint;

{* ...and for the drivers/sound files... *}
const
  IOC_IN        = (_IOC_WRITE shl _IOC_DIRSHIFT);
  IOC_OUT       = (_IOC_READ shl _IOC_DIRSHIFT);
  IOC_INOUT     = ((_IOC_WRITE or _IOC_READ) shl _IOC_DIRSHIFT);
  IOCSIZE_MASK  = (_IOC_SIZEMASK shl _IOC_SIZESHIFT);
  IOCSIZE_SHIFT = (_IOC_SIZESHIFT);

implementation

function _IOC(dir, type_, nr, size: cuint): cuint; {$IFDEF FPC}inline;{$ENDIF}
begin
  _IOC:=(cuint(dir shl _IOC_DIRSHIFT)) or
        (cuint(type_ shl _IOC_TYPESHIFT)) or
        (cuint(nr shl _IOC_NRSHIFT)) or
        (cuint(size shl _IOC_SIZESHIFT));
end;

function _IO(type_, nr: cuint): cuint; {$IFDEF FPC}inline;{$ENDIF}
begin
  _IO:=_IOC(_IOC_NONE, type_, nr, 0);
end;

function _IOR(type_, nr, size: cuint): cuint; {$IFDEF FPC}inline;{$ENDIF}
begin
  _IOR:=_IOC(_IOC_READ, type_, nr, size);
end;

function _IOW(type_, nr, size: cuint): cuint; {$IFDEF FPC}inline;{$ENDIF}
begin
  _IOW:=_IOC(_IOC_WRITE, type_, nr, size);
end;

function _IOWR(type_, nr, size: cuint): cuint; {$IFDEF FPC}inline;{$ENDIF}
begin
  _IOWR:=_IOC(_IOC_READ or _IOC_WRITE, type_, nr, size);
end;

function _IOC_DIR(nr: cuint): cuint; {$IFDEF FPC}inline;{$ENDIF}
begin
  _IOC_DIR:=(nr shr _IOC_DIRSHIFT) and _IOC_DIRMASK;
end;

function _IOC_TYPE(nr: cuint): cuint; {$IFDEF FPC}inline;{$ENDIF}
begin
  _IOC_TYPE:=(nr shr _IOC_TYPESHIFT) and _IOC_TYPEMASK;
end;

function _IOC_NR(nr: cuint): cuint; {$IFDEF FPC}inline;{$ENDIF}
begin
  _IOC_NR:=(nr shr _IOC_NRSHIFT) and _IOC_NRMASK;
end;

function _IOC_SIZE(nr: cuint): cuint; {$IFDEF FPC}inline;{$ENDIF}
begin
  _IOC_SIZE:=(nr shr _IOC_SIZESHIFT) and _IOC_SIZEMASK;
end;

end. {* unit linuxioctl *}

{$ENDIF} {* Linux only *}
