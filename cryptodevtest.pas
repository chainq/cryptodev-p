{* This simple test app is created with the sole purpose to check the validity
 * of the structures and ioctl IDs as defined in cryptodev.pas header *}

program cryptodevtest;

uses cryptodev;

const
  SEPARATOR = '=============================================================';

procedure DumpStructSizes;
begin
  writeln('Struct/Record sizes (in bytes):');
  writeln(SEPARATOR);
  writeln('TSessionOp:     ',sizeof(TSessionOp));
  writeln('TAlgInfo:       ',sizeof(TAlgInfo));
  writeln('TSessionInfoOp: ',sizeof(TSessionInfoOp));
  writeln('TCryptOp:       ',sizeof(TCryptOp));
  writeln('TCryptAuthOp:   ',sizeof(TCryptAuthOp));
  writeln('TCryptKOp:      ',sizeof(TCryptKOp));
end;

procedure DumpIOCtlIDs;
begin
  writeln('ioctl IDs:');
  writeln(SEPARATOR);
  writeln('CRIOGET          $',LowerCase(HexStr(CRIOGET,8)));
  writeln('CIOCGSESSION     $',LowerCase(HexStr(CIOCGSESSION,8)));
  writeln('CIOCFSESSION     $',LowerCase(HexStr(CIOCFSESSION,8)));
  writeln('CIOCCRYPT        $',LowerCase(HexStr(CIOCCRYPT,8)));
  writeln('CIOCKEY          $',LowerCase(HexStr(CIOCKEY,8)));
  writeln('CIOCASYMFEAT     $',LowerCase(HexStr(CIOCASYMFEAT,8)));
  writeln('CIOCGSESSIONINFO $',LowerCase(HexStr(CIOCGSESSINFO,8)));
  writeln('CIOCAUTHCRYPT    $',LowerCase(HexStr(CIOCAUTHCRYPT,8)));
  writeln('CIOCASYNCCRYPT   $',LowerCase(HexStr(CIOCASYNCCRYPT,8)));
  writeln('CIOCASYNCFETCH   $',LowerCase(HexStr(CIOCASYNCFETCH,8)));
end;

begin
  writeln;
  DumpStructSizes;
  writeln;
  DumpIOCtlIDs;
  writeln;
end.
