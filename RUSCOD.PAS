unit RusCod;

interface

uses
  Windows, Messages, SysUtils, Classes;

type
  TRusCod = class(Tcomponent)
  private
    { Private declarations }
  protected
    { Protected declarations }
  public
   function WinToKoi(str:string):string;
   function WinToDos(str:string):string;
   function WinToIso(str:string):string;
   function WinToCirLat(str:string):string;
   function KoiToWin(str:string):string;
   function KoiToDos(str:string):string;
   function KoiToIso(str:string):string;
   function KoiToCirLat(str:string):string;
   function DosToWin(str:string):string;
   function DosToKoi(str:string):string;
   function DosToIso(str:string):string;
   function DosToCirLat(str:string):string;
   function IsoToWin(str:string):string;
   function IsoToKoi(str:string):string;
   function IsoToDos(str:string):string;
   function IsoToCirLat(str:string):string;
  published
    constructor Create(aowner:TComponent);override;
  end;

procedure Register;

implementation

const
Win:array[0..65] of string=
('À', 'Á', 'Â', 'Ã', 'Ä', 'Å',
 '¨', 'Æ', 'Ç', 'È', 'É', 'Ê',
 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Ð',
 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö',
 '×', 'Ø', 'Ù', 'Ú', 'Û', 'Ü',
 'Ý', 'Þ', 'ß', 'à', 'á', 'â' ,
 'ã', 'ä', 'å', '¸', 'æ', 'ç',
 'è', 'é', 'ê', 'ë', 'ì', 'í',
 'î', 'ï', 'ð', 'ñ', 'ò', 'ó',
 'ô', 'õ', 'ö', '÷', 'ø', 'ù',
 'ú', 'û', 'ü', 'ý', 'þ', 'ÿ');
Koi:array[0..65] of string=
('á', 'â', '÷', 'ç', 'ä', 'å',
 '³', 'ö', 'ú', 'é', 'ê', 'ë',
 'ì', 'í', 'î', 'ï', 'ð', 'ò',
 'ó', 'ô', 'õ', 'æ', 'è', 'ã',
 'þ', 'û', 'ý', 'ÿ', 'ù', 'ø',
 'ü', 'à', 'ñ', 'Á', 'Â', '×' ,
 'Ç', 'Ä', 'Å', '£', 'Ö', 'Ú',
 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î',
 'Ï', 'Ð', 'Ò', 'Ó', 'Ô', 'Õ',
 'Æ', 'È', 'Ã', 'Þ', 'Û', 'Ý',
 'ß', 'Ù', 'Ø', 'Ü', 'À', 'Ñ');
Dos:array[0..65] of string=
('€', '', '‚', 'ƒ', '„', '…',
 'ð', '†', '‡', 'ˆ', '‰', 'Š',
 '‹', 'Œ', '', 'Ž', '', '',
 '‘', '’', '“', '”', '•', '–',
 '—', '˜', '™', 'š', '›', 'œ',
 '', 'ž', 'Ÿ', ' ', '¡', '¢' ,
 '£', '¤', '¥', 'ñ', '¦', '§',
 '¨', '©', 'ª', '«', '¬', '­',
 '®', '¯', 'à', 'á', 'â', 'ã',
 'ä', 'å', 'æ', 'ç', 'è', 'é',
 'ê', 'ë', 'ì', 'í', 'î', 'ï');
ISO:array[0..65] of string=
('°', '±', '²', '³', '´', 'µ',
 '¡', '¶', '·', '¸', '¹', 'º',
 '»', '¼', '½', '¾', '¿', 'À',
 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Æ',
 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì',
 'Í', 'Î', 'Ï', 'Ð', 'Ñ', 'Ò' ,
 'Ó', 'Ô', 'Õ', 'ñ', 'Ö', '×',
 'Ø', 'Ù', 'Ú', 'Û', 'Ü', 'Ý',
 'Þ', 'ß', 'à', 'á', 'â', 'ã',
 'ä', 'å', 'æ', 'ç', 'è', 'é',
 'ê', 'ë', 'ì', 'í', 'î', 'ï');
CirLat:array[0..65] of string=
('A', 'B', 'V', 'G', 'D', 'E',
 'E', 'ZH', 'Z', 'I', 'Y', 'K',
 'L', 'M', 'N', 'O', 'P', 'R',
 'S', 'T', 'U', 'F', 'H', 'C',
 'CH', 'SH', 'SH', '""', 'I', '"',
 'E', 'IU', 'IA', 'a', 'b', 'v' ,
 'g', 'd', 'e', 'e', 'zh', 'z',
 'i', 'y', 'k', 'l', 'm', 'n',
 'o', 'p', 'r', 's', 't', 'u',
 'f', 'h', 'c', 'ch', 'sh', 'sh',
 '""', 'y', '"', 'e', 'iu', 'ia');
constructor TrusCod.Create(aowner:TComponent);
begin
inherited Create(aowner);
end;
 //Windows
//Win >> Koi
function TRusCod.WinToKoi(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Win) to High(Win) do
if Win[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Koi[Index];
end;
end;

//Win >> Dos
function TrusCod.WinToDos(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Win) to High(Win) do
if Win[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Dos[Index];
end;
end;

//Win >> Iso
function TrusCod.WinToIso(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Win) to High(Win) do
if Win[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Iso[Index];
end;
end;

//Win >> CirLat
function TrusCod.WinToCirLat(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Win) to High(Win) do
if Win[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+CirLat[Index];
end;
end;

//Koi
//Koi >> Win
function TrusCod.KoiToWin(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Koi) to High(Koi) do
if Koi[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Win[Index];
end;
end;

//Koi >> Dos
function TrusCod.KoiToDos(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Koi) to High(Koi) do
if Koi[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Dos[Index];
end;
end;

//Koi >> Iso
function TrusCod.KoiToIso(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Koi) to High(Koi) do
if Koi[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Iso[Index];
end;
end;

//Koi >> CirLat
function TrusCod.KoiToCirLat(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Koi) to High(Koi) do
if Koi[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Cirlat[Index];
end;
end;

//Dos
//Dos >> Win
function TrusCod.DosToWin(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Dos) to High(Dos) do
if Dos[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Win[Index];
end;
end;

//Dos >> Koi
function TrusCod.DosToKoi(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Dos) to High(Dos) do
if Dos[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Koi[Index];
end;
end;

//Dos >> Iso
function TrusCod.DosToIso(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Dos) to High(Dos) do
if Dos[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Iso[Index];
end;
end;

//Dos >> CirLat
function TrusCod.DosToCirLat(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Dos) to High(Dos) do
if Dos[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Cirlat[Index];
end;
end;

//Iso
//Iso >> Win
function TrusCod.IsoToWin(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Iso) to High(Iso) do
if Iso[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Win[Index];
end;
end;

//Iso >> Koi
function TrusCod.IsoToKoi(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Iso) to High(Iso) do
if Iso[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Koi[Index];
end;
end;

//Iso >> Dos
function TrusCod.IsoToDos(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Iso) to High(Iso) do
if Iso[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Dos[Index];
end;
end;

//Iso >> CirLat
function TrusCod.IsoToCirLat(str:string):string;
var
count,x,y,Index: Integer;
begin
Result := '';
count:=length(Str);
for x:=1 to count do
begin
index:=-1;
for y:=Low(Iso) to High(Iso) do
if Iso[y] = Str[x] then
begin
Index:=y;
Break;
end;
if Index=-1 then Result:=Result+Str[x]
else Result:=Result+Cirlat[Index];
end;
end;
procedure Register;
begin
  RegisterComponents('AComponents', [TRusCod]);
end;

end.
 