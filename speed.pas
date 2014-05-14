{*  cryptodev_test - simple benchmark tool for cryptodev
 *
 *    Copyright (C) 2010 by Phil Sutter <phil.sutter@viprinet.com>
 *
 *    Free Pascal Conversion:
 *    Copyright (C) 2013 by Karoly Balogh <karoly.balogh@viprinet.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *}

{$MODE DELPHI}
program speed;

uses
  baseunix, unix, cryptodev, linuxioctl;

const
  SI = true; { SI by default }

function udifftimeval(start: TimeVal; finish: TimeVal): Double;
begin
  udifftimeval:=(finish.tv_usec - start.tv_usec) +
                 (finish.tv_sec - start.tv_sec) * 1000.0 * 1000.0;
end;

var
  must_finish: boolean = false;

procedure alarm_handler(signo: cint); cdecl;
begin
  must_finish:=true;
end;

const
  units: array[0..4] of String = ( '','KiB','MiB','GiB','TiB' );
  si_units: array[0..4] of String = ( '', 'KB', 'MB', 'GB', 'TB' );

procedure value2human(si: boolean; bytes: Double; time: Double;
                      var data: Double; var speed: Double; var metric: String);
var
  unit_: LongInt = 0;
begin
  data := bytes;

  if (si) then begin
    while (data > 1000) and (unit_ < length(si_units)) do begin
      data := data / 1000;
      inc(unit_);
    end;
    speed := data / time;
    metric := si_units[unit_];
  end else begin
    while (data > 1000) and (unit_ < length(units)) do begin
      data := data / 1000;
      inc(unit_);
    end;
    speed := data / time;
    metric := units[unit_];
  end;
end;

function encrypt_data(var sess: TSessionOp; fdc: longint; chunksize: longint; alignmask: longint): boolean;
var
  cop: TCryptOp;
  buffer: PChar;
  iv: array[0..31] of Char;
  val: Longint = 23;
  start, finish: TTimeVal;
  total: Double = 0;
  secs, ddata, dspeed: Double;
  metric: String;
begin
  encrypt_data:=true;

  { Free Pascal's GetMem() is guaranteed to return 16 byte aligned blocks already }
  if alignmask > 15 then begin
    writeln('Required alignment is larger than 16 bytes: ',alignmask + 1,'!');
    encrypt_data:=false;
    exit;
  end else begin
    buffer := GetMem(chunksize);
    if (buffer = nil) then begin
      writeln('GetMem() failed.');
      encrypt_data:=false;
      exit;
    end;
  end;

  FillChar(iv, 32, '#');

  write(#9,'Encrypting in chunks of ',chunksize,' bytes:');

  FillChar(buffer^, chunksize, val);
  inc(val);

  must_finish := false;
  fpAlarm(5);

  fpGetTimeOfDay(@start, nil);
  repeat
    FillChar(cop, sizeof(cop), #0);
    cop.ses := sess.ses;
    cop.len := chunksize;
    cop.iv  := pcuint8(@iv);
    cop.op  := COP_ENCRYPT;
    cop.src := pcuint8(buffer);
    cop.dst := pcuint8(buffer);

    if (fpIOCtl(fdc, CIOCCRYPT, @cop) <> 0) then begin
      writeln('ioctl(CIOCCRYPT)');
      halt(1);
    end;
    total:=total+chunksize;
  until must_finish;
  fpGetTimeOfDay(@finish, nil);

  secs := udifftimeval(start, finish) / 1000000.0;
  value2human(SI, total, secs, ddata, dspeed, metric);

  writeln(' done. ',ddata:0:2,' ',metric,' in ',secs:0:2,' secs: ',
          dspeed:0:2,' ',metric,'/sec');

  FreeMem(buffer);
end;

procedure speed_main();
var
  fd, i: LongInt;
  fdc: LongInt = -1;
  alignmask: LongInt = 0;
  sess: TSessionOp;
  siop: TSessionInfoOp;
  keybuf: array[0..31] of char;
begin
  fpSignal(SIGALRM, @alarm_handler);

  fd := fpOpen('/dev/crypto', O_RDWR, 0);
  if (fd < 0) then begin
    writeln('open()');
    halt(1);
  end;

  if (fpIOCtl(fd, CRIOGET, @fdc) <> 0) then begin
    writeln('ioctl(CRIOGET)');
    halt(1);
  end;

  writeln(#10,'Testing AES-128-CBC cipher: ');
  FillChar(sess, sizeof(sess), #0);
  sess.cipher := CRYPTO_AES_CBC;
  sess.keylen := 16;
  FillChar(keybuf, 16, #66);
  sess.key := pcuint8(@keybuf);
  if (fpIOCtl(fdc, CIOCGSESSION, @sess) <> 0) then begin
    writeln('ioctl(CIOCGSESSION)');
    halt(1);
  end;

  siop.ses := sess.ses;
  if (fpIOCtl(fdc, CIOCGSESSINFO, @siop) <> 0) then begin
    writeln('ioctl(CIOCGSESSINFO)');
    halt(1);
  end;
  alignmask := siop.alignmask;
  if (alignmask <> 0) then
    writeln('Alignment required: ',alignmask+1,' bytes');

  i:=512;
  while (i <= 64 * 1024) do begin
    if (not encrypt_data(sess, fdc, i, alignmask)) then 
      break;
    i:=i * 2;
  end;

  fpClose(fdc);
  fpClose(fd);
end;

begin
  speed_main();
end.
