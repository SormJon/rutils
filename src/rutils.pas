(*
  RUtils plugin.
  Copyright (C) 2012-2014 Silvio Clecio.

  Please see the LICENSE file.
*)

unit RUtils;

{$mode objfpc}{$H+}

interface

uses
{$IFDEF UNIX}
  MacUUID,
{$ENDIF}
  Classes, SysUtils, StrUtils, Base64, BlowFish, MD5, SHA1, RegExpr, FPJSON,
  HTTPDefs, ZStream, JSONParser;

const
  BR = '<br />';
  ES = '';
  NU = #0;
  LF = #10;
  CR = #13;
  CRLF = CR + LF;
  SP = #32; //
  DQ = #34; // "
  AM = #38; // &
  AK = #42; // *
  CS = #44; // ,
  US = #47; // /
  CO = #58; // :
  LT = #60; // <
  EQ = #61; // =
  GT = #62; // >
  QU = #63; // ?
  UUID_MASK = '%.8x-%.4x-%.4x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x';
  NUMBERS = '0123456789';
  az_ = 'abcdefghijklmnopqrstuvwxyz';
  AZ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  SYMBOLS = '!"#$%&*(){}[]<>=+-\|/,.:;?@^_~`''';
  HexCharsArray: array[0..15] of Char = ('0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');
  LatinCharsCount = 75;
  LatinChars: array[1..LatinCharsCount] of string = (
    '"', '<', '>', '^', '~', '£', '§', '°', '²', '³', 'µ', '·', '¼', '½', '¿',
    'À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Æ', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î',
    'Ï', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', 'Ù', 'Ú', 'Û', 'Ü', 'Ý', 'ß', 'á', 'à',
    'â', 'ã', 'ä', 'å', 'æ', 'ç', 'é', 'è', 'ê', 'ë', 'ì', 'í', 'î', 'ï', 'ñ',
    'ò', 'ó', 'ô', 'õ', 'ö', '÷', 'ù', 'ú', 'û', 'ü', 'ý', 'ÿ', '&', '´', '`');
  HtmlChars: array[1..LatinCharsCount] of string = (
    '&quot;', '&lt;', '&gt;', '&circ;', '&tilde;', '&pound;', '&sect;', '&deg;',
    '&sup2;', '&sup3;', '&micro;', '&middot;', '&frac14;', '&frac12;', '&iquest;',
    '&Agrave;', '&Aacute;', '&Acirc;', '&Atilde;', '&Auml;', '&Aring;', '&AElig;',
    '&Ccedil;', '&Egrave;', '&Eacute;', '&Ecirc;', '&Euml;', '&Igrave;', '&Iacute;',
    '&Icirc;', '&Iuml;', '&Ntilde;', '&Ograve;', '&Oacute;', '&Ocirc;', '&Otilde;',
    '&Ouml;', '&Ugrave;', '&Uacute;', '&Ucirc;', '&Uuml;', '&Yacute;', '&szlig;',
    '&aacute;', '&agrave;', '&acirc;', '&atilde;', '&auml;', '&aring;', '&aelig;',
    '&ccedil;', '&eacute;', '&egrave;', '&ecirc;', '&euml;', '&igrave;', '&iacute;',
    '&icirc;', '&iuml;', '&ntilde;', '&ograve;', '&oacute;', '&ocirc;', '&otilde;',
    '&ouml;', '&divide;', '&ugrave;', '&uacute;', '&ucirc;', '&uuml;', '&yacute;',
    '&yuml;', '&amp;', '&acute;', '&grave;');

type
  TArrayOfString = array of string;

  TGeneratePasswordAmount = 2..32;

  TRegExModifiers = set of (rmModifierI, rmModifierR, rmModifierS, rmModifierG,
    rmModifierM, rmModifierX);

{ (De)Compress }

procedure ZCompressStream(AIn, AOut: TStream;
  const ALevel: TCompressionLevel = clDefault);
procedure ZDecompressStream(AIn, AOut: TStream);
function ZCompressStr(const S: string;
  const ALevel: TCompressionLevel = clDefault): string;
function ZDecompressStr(const S: string): string;
procedure ZCompressFile(const AIn, AOut: TFileName;
  const ALevel: TCompressionLevel = clDefault);
procedure ZDecompressFile(const AIn, AOut: TFileName);

{ RegEx }

function Extract(const S, AExpression: string; const AMatch: Integer = 0;
  const AModifiers: TRegExModifiers = [rmModifierI]): string;
procedure Extract(AStrs: TStrings; const S, AExpression: string;
  const AMatch: Integer = 0; const AModifiers: TRegExModifiers = [rmModifierI]);
function Replace(const AStrOld, AStrNew, AExpression: string;
  const AModifiers: TRegExModifiers = [rmModifierI]): string;

{ Hash }

function UUID: string;
function UUID(const AUseSeparators: Boolean): string;
function MD5FromStr(const S: string): string;
function MD5FromFile(const AFileName: TFileName): string;
function MD5Password(const AUpperCase: Boolean = True): string;
function SHA1FromStr(const S: string): string;
function SHA1FromFile(const AFileName: TFileName): string;
function SHA1Password(const AUpperCase: Boolean = True): string;
{ Please, use Randomize on initialization of your program! }
function Password(const AAmount: TGeneratePasswordAmount = 6;
  const AAZ: Boolean = True; const A_az: Boolean = False;
  const ASymbols: Boolean = False; const ANumbers: Boolean = True): string;
function StrToBase64(S: string): string;
function Base64ToStr(const S: string;
  const AMode: TBase64DecodingMode = bdmMIME): string;
function FileToBase64(const AFileName: TFileName): string;
procedure Base64ToFile(const S: string; const AFileName: TFileName;
  const AMode: TBase64DecodingMode = bdmMIME);
function StreamToBase64(AStream: TStream): string;
procedure Base64ToStream(const S: string; AStream: TStream;
  const AMode: TBase64DecodingMode = bdmMIME);

{ HTML }

function StripHTMLMarkup(const S: string): string;
function EOLToBR(const S: string): string;
procedure EOLToBREx(var S: string);
function StrToHtml(const S: string): string;
function HtmlToStr(const S: string): string;

{ (De)Crypt }

function EncryptStr(const S, AKey: string): string;
function DecryptStr(const S, AKey: string): string;

{ Date/Time }

function MSecToDateTime(const AMSec: Double): TDateTime;
function MilliSecondToDateTime(const AMSec: Double): TDateTime;
function DTToMS(const ADateTime: TDateTime): Double;
function DateTimeToMilliSecond(const ADateTime: TDateTime): Double;
function FileDateTime(const AFileName: TFileName): TDateTime;

{ String }

function NameOf(const S: string): string;
function ValueOf(const S: string): string;
procedure NameValueOf(const S: string; out AName, AValue: string);
function FileNameOf(const S: string): string;
procedure StrToFile(const S: string; const AFileName: TFileName);
function FileToStr(const AFileName: TFileName): string;
function HiddenPassword(const APass: string; const AChar: Char = AK): string;
function StrToHex(const S: string): string;
function HexToStr(const AHex: string): string;
function DeleteLineBreaks(const S: string; const ASubstitute: Char = SP): string;
function ReplaceChar(const S: string; const AOldChar, ANewChar: Char): string;
function ReplaceChar(const S: string; const AOldChars: TSysCharSet;
  const ANewChar: Char): string;
function SizeToStr(const ASize: Extended): ShortString;
function OnlyAlphaChars(const S: string): string;
function OnlyNumbers(const S: string): string;
function OnlySpecialChars(const S: string): string;
function OnlySpecificChars(const S: string; const AChars: TSysCharSet): string;
function UnderlineStr(const S: string): string;
function Explode(const S: string; const ADelimiter: string = SP;
  const ALimit: Integer = 0): TArrayOfString;
function Implode(const AArray: TArrayOfString;
  const ADelimiter: string = SP): string;
function Implode(const AArray: array of string;
  const ADelimiter: string = SP): string;
function Occurs(const S, APart: string): SizeInt;
function Occurs(const S: string; const AParts: array of string): SizeInt;
function Exists(const S: string; const AParts: array of string): Boolean; overload;
function Exists(const S: string; const AParts: array of string;
  const AIgnoreCase: Boolean): Boolean; overload;
{ This function takes two strings and compares them. The first string can be
  anything, but should not contain pattern characters (* or ?). The pattern
  string can have as many of these pattern characters as you want.
  For example: MatchStrings('Free Pascal','*Pa*') would return True.
  Other example: MatchStrings('Free Pascal','Free?Pascal') would return True }
function MatchStrings(ASource, APattern: string): Boolean;
function SeparateRight(const S, ADelimiter: string): string; overload;
function SeparateRight(const S, ADelimiter: string;
  const AIgnoreCase: Boolean): string; overload;
function Between(const AStart, AEnd: string; const S: string): string; overload;
function Between(const AStart, AEnd: string; const S: string;
  const AIgnoreCase: Boolean): string; overload;
function RemoveDiacritics(const S: string): string;
function RemoveSpecialChars(const S: string): string;

{ Conditional }

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: string): string; overload;
function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Char): Char; overload;
function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Byte): Byte; overload;
function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Integer): Integer; overload;
function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Cardinal): Cardinal; overload;
function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Double): Double; overload;
function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Boolean): Boolean; overload;
function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Pointer): Pointer; overload;
function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Int64): Int64; overload;
function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Variant): Variant; overload;

{ JSON }

function ParamsToJSON(const AParam: string;
  const ASeparator, ADelimiter: Char): TJSONStringType;
function JSONToParams(AJSON: TJSONObject): string;
function PathToJSON(const APath: string; const ADelimiter: Char): TJSONStringType;
function JSONToPath(AJSON: TJSONArray): string;
procedure GetJSONArray(AStream: TStream; out AJSON: TJSONArray);
procedure GetJSONArray(const S: TJSONStringType; out AJSON: TJSONArray);
procedure GetJSONObject(AStream: TStream; out AJSON: TJSONObject);
procedure GetJSONObject(const S: TJSONStringType; out AJSON: TJSONObject);

{ Util }

function GetTickCount: DWord;
function ReadString(AStream: TStream; const ALength: Int64): string;

implementation

{ (De)Compress }

procedure ZCompressStream(AIn, AOut: TStream; const ALevel: TCompressionLevel);
begin
  with TCompressionStream.Create(ALevel, AOut) do
    try
      CopyFrom(AIn, AIn.Size);
    finally
      Free;
    end;
end;

procedure ZDecompressStream(AIn, AOut: TStream);
const
  BufSz = 4096;
var
  C: Integer;
  VBuff: array[0..BufSz - 1] of Byte;
  VDeCompStream: TDecompressionStream;
begin
  VBuff[0] := 0;
  VDeCompStream := TDecompressionStream.Create(AIn);
  try
    while True do
    begin
      C := VDeCompStream.Read(VBuff, BufSz);
      if C <> 0 then
        AOut.WriteBuffer(VBuff, C)
      else
        Break;
    end;
  finally
    VDeCompStream.Free;
  end;
end;

function ZCompressStr(const S: string; const ALevel: TCompressionLevel): string;
var
  L: Int64;
  VIn, VOut: TStream;
begin
  VIn := TMemoryStream.Create;
  VOut := TMemoryStream.Create;
  try
    VIn.Write(Pointer(S)^, Length(S));
    VIn.Position := 0;
    ZCompressStream(VIn, VOut, ALevel);
    VOut.Position := 0;
    L := VOut.Size;
    SetLength(Result, L);
    VOut.Read(Pointer(Result)^, L);
  finally
    VIn.Free;
    VOut.Free;
  end;
end;

function ZDecompressStr(const S: string): string;
var
  L: Int64;
  VIn, VOut: TStream;
begin
  VIn := TMemoryStream.Create;
  VOut := TMemoryStream.Create;
  try
    VIn.Write(Pointer(S)^, Length(S));
    VIn.Position := 0;
    ZDecompressStream(VIn, VOut);
    VOut.Position := 0;
    L := VOut.Size;
    SetLength(Result, L);
    VOut.Read(Pointer(Result)^, L);
  finally
    VIn.Free;
    VOut.Free;
  end;
end;

procedure ZCompressFile(const AIn, AOut: TFileName;
  const ALevel: TCompressionLevel);
var
  VIn, VOut: TMemoryStream;
begin
  VIn := TMemoryStream.Create;
  VOut := TMemoryStream.Create;
  try
    VIn.LoadFromFile(AIn);
    ZCompressStream(VIn, VOut, ALevel);
    VOut.SaveToFile(AOut);
  finally
    VOut.Free;
    VIn.Free;
  end;
end;

procedure ZDecompressFile(const AIn, AOut: TFileName);
var
  VIn, VOut: TMemoryStream;
begin
  VIn := TMemoryStream.Create;
  VOut := TMemoryStream.Create;
  try
    VIn.LoadFromFile(AIn);
    ZDecompressStream(VIn, VOut);
    VOut.SaveToFile(AOut);
  finally
    VIn.Free;
    VOut.Free;
  end;
end;

{ RegEx }

function Extract(const S, AExpression: string; const AMatch: Integer;
  const AModifiers: TRegExModifiers): string;
var
  VRegEx: TRegExpr;
begin
  VRegEx := TRegExpr.Create;
  try
    VRegEx.ModifierI := rmModifierI in AModifiers;
    VRegEx.ModifierR := rmModifierI in AModifiers;
    VRegEx.ModifierS := rmModifierI in AModifiers;
    VRegEx.ModifierG := rmModifierI in AModifiers;
    VRegEx.ModifierM := rmModifierI in AModifiers;
    VRegEx.ModifierX := rmModifierI in AModifiers;
    VRegEx.Expression := AExpression;
    if VRegEx.Exec(S) then
      Result := VRegEx.Match[AMatch];
  finally
    VRegEx.Free;
  end;
end;

procedure Extract(AStrs: TStrings; const S, AExpression: string;
  const AMatch: Integer; const AModifiers: TRegExModifiers);
var
  VRegEx: TRegExpr;
begin
  VRegEx := TRegExpr.Create;
  try
    AStrs.Clear;
    VRegEx.ModifierI := rmModifierI in AModifiers;
    VRegEx.ModifierR := rmModifierI in AModifiers;
    VRegEx.ModifierS := rmModifierI in AModifiers;
    VRegEx.ModifierG := rmModifierI in AModifiers;
    VRegEx.ModifierM := rmModifierI in AModifiers;
    VRegEx.ModifierX := rmModifierI in AModifiers;
    VRegEx.Expression := AExpression;
    if VRegEx.Exec(S) then
      repeat
        AStrs.Add(VRegEx.Match[AMatch]);
      until not VRegEx.ExecNext;
  finally
    VRegEx.Free;
  end;
end;

function Replace(const AStrOld, AStrNew, AExpression: string;
  const AModifiers: TRegExModifiers): string;
var
  VRegEx: TRegExpr;
begin
  VRegEx := TRegExpr.Create;
  try
    VRegEx.ModifierI := rmModifierI in AModifiers;
    VRegEx.ModifierR := rmModifierI in AModifiers;
    VRegEx.ModifierS := rmModifierI in AModifiers;
    VRegEx.ModifierG := rmModifierI in AModifiers;
    VRegEx.ModifierM := rmModifierI in AModifiers;
    VRegEx.ModifierX := rmModifierI in AModifiers;
    VRegEx.Expression := AExpression;
    Result := VRegEx.Replace(AStrOld, AStrNew, True);
  finally
    VRegEx.Free;
  end;
end;

{ Hash }

function UUID: string;
var
  G: TGuid;
begin
  CreateGUID(G);
  SetLength(Result, 32);
  StrLFmt(PChar(Result), 32, UUID_MASK, [G.D1, G.D2, G.D3, G.D4[0], G.D4[1],
    G.D4[2], G.D4[3], G.D4[4], G.D4[5], G.D4[6], G.D4[7]]);
end;

function UUID(const AUseSeparators: Boolean): string;
var
  G: TGUID;
begin
  if AUseSeparators then
  begin
    CreateGUID(G);
    SetLength(Result, 36);
    StrLFmt(PChar(Result), 36, UUID_MASK, [G.D1, G.D2, G.D3, G.D4[0], G.D4[1],
      G.D4[2], G.D4[3], G.D4[4], G.D4[5], G.D4[6], G.D4[7]]);
  end
  else
    Result := UUID;
end;

function MD5FromStr(const S: string): string;
begin
  Result := MD5Print(MD5String(S));
end;

function MD5FromFile(const AFileName: TFileName): string;
begin
  Result := MD5Print(MD5File(AFileName));
end;

function MD5Password(const AUpperCase: Boolean): string;
begin
  Result := MD5Print(MD5String(UUID));
  if AUpperCase then
    Result := UpperCase(Result);
end;

function SHA1FromStr(const S: string): string;
begin
  Result := SHA1Print(SHA1String(S));
end;

function SHA1FromFile(const AFileName: TFileName): string;
begin
  Result := SHA1Print(SHA1File(AFileName));
end;

function SHA1Password(const AUpperCase: Boolean): string;
begin
  Result := SHA1Print(SHA1String(UUID));
  if AUpperCase then
    Result := UpperCase(Result);
end;

function Password(const AAmount: TGeneratePasswordAmount; const AAZ: Boolean;
  const A_az: Boolean; const ASymbols: Boolean; const ANumbers: Boolean): string;
const
  Chrs = az_ + AZ + SYMBOLS;
var
  P: PChar;
  I, L: Integer;
begin
  L := 0;
  if ANumbers then
    Inc(L, 10);
  if A_az then
    Inc(L, 26);
  if AAZ then
    Inc(L, 26);
  if ASymbols then
    Inc(L, 32);
  if L = 0 then
    Exit;
  SetLength(Result, AAmount);
  P := PChar(Result);
  for I := 1 to AAmount do
  begin
    P^ := Chrs[1 + Random(L)];
    Inc(P);
  end;
end;

function StrToBase64(S: string): string;
var
  VSrcStream, VDestStream: TStringStream;
begin
  VSrcStream := TStringStream.Create(S);
  try
    VDestStream := TStringStream.Create('');
    try
      with TBase64EncodingStream.Create(VDestStream) do
        try
          CopyFrom(VSrcStream, VSrcStream.Size);
        finally
          Free;
        end;
      Result := VDestStream.DataString;
    finally
      VDestStream.Free;
    end;
  finally
    VSrcStream.Free;
  end;
end;

function Base64ToStr(const S: string; const AMode: TBase64DecodingMode): string;
var
  VDecoder: TBase64DecodingStream;
  VSrcStream, VDestStream: TStringStream;
begin
  VSrcStream := TStringStream.Create(S);
  VDestStream := TStringStream.Create('');
  try
    VDecoder := TBase64DecodingStream.Create(VSrcStream, AMode);
    try
      VDestStream.CopyFrom(VDecoder, VDecoder.Size);
    finally
      VDecoder.Free;
    end;
    Result := VDestStream.DataString;
  finally
    VDestStream.Free;
    VSrcStream.Free;
  end;
end;

function FileToBase64(const AFileName: TFileName): string;
var
  VFile: TFileStream;
  VStream: TStringStream;
begin
  VFile := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  VStream := TStringStream.Create('');
  try
    with TBase64EncodingStream.Create(VStream) do
      try
        CopyFrom(VFile, VFile.Size);
      finally
        Free;
      end;
    Result := VStream.DataString;
  finally
    VStream.Free;
    VFile.free;
  end;
end;

procedure Base64ToFile(const S: string; const AFileName: TFileName;
  const AMode: TBase64DecodingMode);
var
  VFile: TFileStream;
  VStream: TStringStream;
  VDecoder: TBase64DecodingStream;
begin
  VFile := TFileStream.Create(AFileName, fmCreate);
  VStream := TStringStream.Create(S);
  VDecoder := TBase64DecodingStream.Create(VStream, AMode);
  try
    VStream.Position := 0;
    VFile.CopyFrom(VDecoder, VDecoder.Size);
  finally
    VDecoder.Free;
    VStream.Free;
    VFile.Free;
  end;
end;

function StreamToBase64(AStream: TStream): string;
var
  VDestStream: TStringStream;
begin
  VDestStream := TStringStream.Create('');
  try
    with TBase64EncodingStream.Create(VDestStream) do
      try
        CopyFrom(AStream, AStream.Size);
      finally
        Free;
      end;
    Result := VDestStream.DataString;
  finally
    VDestStream.Free;
  end;
end;

procedure Base64ToStream(const S: string; AStream: TStream;
  const AMode: TBase64DecodingMode);
var
  VDecoder: TBase64DecodingStream;
  VSrcStream: TStringStream;
begin
  VSrcStream := TStringStream.Create(S);
  try
    VDecoder := TBase64DecodingStream.Create(VSrcStream, AMode);
    try
      AStream.CopyFrom(VDecoder, VDecoder.Size);
    finally
      VDecoder.Free;
    end;
  finally
    VSrcStream.Free;
  end;
end;

{ HTML }

function StripHTMLMarkup(const S: string): string;
var
  PSrc: PChar;
  I, C: Integer;
  VInTag: Boolean;
begin
  SetLength(Result, Length(S));
  PSrc := PChar(Result);
  VInTag := False;
  C := 0;
  for I := 1 to Length(S) do
    if VInTag then
    begin
      if S[I] = GT then
        VInTag := False;
    end
    else
      if S[I] = LT then
        VInTag := True
      else
      begin
        PSrc[C] := S[I];
        Inc(C);
      end;
  SetLength(Result, C);
end;

function EOLToBR(const S: string): string;
var
  I: SizeInt;
  PSrc, PFar: PChar;
begin
  Result := S;
  I := 0;
  PSrc := PChar(S);
  PFar := PSrc;
  while PSrc^ <> NU do
  begin
    Inc(I);
    Inc(PFar);
    if (PSrc^ = CR) and (PFar^ = LF) then
    begin
      Delete(Result, I, 2);
      Insert(BR, Result, I);
      Inc(I, 5);
      Inc(PSrc, 2);
      Inc(PFar, 1);
      Continue;
    end;
    if (PSrc^ = CR) or (PSrc^ = LF) then
    begin
      Delete(Result, I, 1);
      Insert(BR, Result, I);
      Inc(I, 5);
    end;
    Inc(PSrc);
  end;
end;

procedure EOLToBREx(var S: string);

  function Replace(const OldPatt: string): string;
  var
    P: Integer;
    VOld, VRem: string;
  begin
    VOld := OldPatt;
    VRem := S;
    Result := ES;
    while Length(S) <> 0 do
    begin
      P := Pos(VOld, S);
      if P = 0 then
      begin
        Result += VRem;
        S := ES;
      end
      else
      begin
        Result += Copy(VRem, 1, P - 1) + BR;
        P += Length(VOld);
        VRem := Copy(VRem, P, Length(VRem) - P + 1);
        S := Copy(S, P, Length(S) - P + 1);
      end;
    end;
  end;

begin
  S := Replace(CRLF);
  S := Replace(CR);
  S := Replace(LF);
end;

function StrToHtml(const S: string): string;
var
  L, C: Integer;
  VFound: Boolean;
  PComp, PSrc, PLast: PChar;
  VResStr, VCompStr: string;
begin
  L := Length(LatinChars);
  if L <> Length(HtmlChars) then
    raise Exception.Create(SErrAmountStrings);
  Dec(L);
  VCompStr := S;
  VResStr := ES;
  PSrc := @S[1];
  PComp := @VCompStr[1];
  PLast := PComp + Length(S);
  while PComp < PLast do
  begin
    VFound := False;
    for C := 1 to L do
    begin
      if (Length(LatinChars[C]) > 0) and (LatinChars[C][1] = PComp^) and
        (Length(LatinChars[C]) <= (PLast - PComp)) and
        (CompareByte(LatinChars[C][1], PComp^, Length(LatinChars[C])) = 0) then
      begin
        VResStr := VResStr + HtmlChars[C];
        PComp := PComp + Length(LatinChars[C]);
        PSrc := PSrc + Length(LatinChars[C]);
        VFound := True;
      end;
    end;
    if not VFound then
    begin
      VResStr := VResStr + PSrc^;
      Inc(PComp);
      Inc(PSrc);
    end;
  end;
  Result := VResStr;
end;

function HtmlToStr(const S: string): string;
var
  L, C: Integer;
  VFound: Boolean;
  PComp, PSrc, PLast: PChar;
  VResStr, VCompStr: string;
begin
  L := Length(HtmlChars);
  if L <> Length(LatinChars) then
    raise Exception.Create(SErrAmountStrings);
  Dec(L);
  VCompStr := S;
  VResStr := ES;
  PSrc := @S[1];
  PComp := @VCompStr[1];
  PLast := PComp + Length(S);
  while PComp < PLast do
  begin
    VFound := False;
    for C := 1 to L do
    begin
      if (Length(HtmlChars[C]) > 0) and (HtmlChars[C][1] = PComp^) and
        (Length(HtmlChars[C]) <= (PLast - PComp)) and
        (CompareByte(HtmlChars[C][1], PComp^, Length(HtmlChars[C])) = 0) then
      begin
        VResStr := VResStr + LatinChars[C];
        PComp := PComp + Length(HtmlChars[C]);
        PSrc := PSrc + Length(HtmlChars[C]);
        VFound := True;
      end;
    end;
    if not VFound then
    begin
      VResStr := VResStr + PSrc^;
      Inc(PComp);
      Inc(PSrc);
    end;
  end;
  Result := VResStr;
end;

{ (De)Crypt }

function EncryptStr(const S, AKey: string): string;
var
  VInput: TStringStream;
  VBF: TBlowFishEncryptStream;
begin
  VInput := TStringStream.Create('');
  VBF := TBlowFishEncryptStream.Create(AKey, VInput);
  try
    VBF.Write(Pointer(S)^, Length(S));
  finally
    VBF.Free;
    Result := VInput.DataString;
    VInput.Free;
  end;
end;

function DecryptStr(const S, AKey: string): string;
var
  VOutput: TStringStream;
  VBF: TBlowFishDeCryptStream;
begin
  VOutput := TStringStream.Create(S);
  VBF := TBlowFishDeCryptStream.Create(AKey, VOutput);
  try
    SetLength(Result, VOutput.Size);
    VBF.Read(Pointer(Result)^, VOutput.Size);
  finally
    VBF.Free;
    VOutput.Free;
  end;
end;

{ Date/Time }

function FileDateTime(const AFileName: TFileName): TDateTime;
begin
  if not FileExists(AFileName) then
    raise Exception.Create('File not found: ' + AFileName);
  Result := FileDateToDateTime(FileAge(AFileName));
end;

function MSecToDateTime(const AMSec: Double): TDateTime;
begin
  Result := AMSec / MSecsPerSec / SecsPerDay;
end;

function MilliSecondToDateTime(const AMSec: Double): TDateTime;
begin
  Result := MSecToDateTime(AMSec);
end;

function DTToMS(const ADateTime: TDateTime): Double;
begin
  Result := ADateTime * HoursPerDay * MinsPerHour * SecsPerMin * MSecsPerSec;
end;

function DateTimeToMilliSecond(const ADateTime: TDateTime): Double;
begin
  Result := DTToMS(ADateTime);
end;

{ String }

function NameOf(const S: string): string;
begin
  Result := Copy(S, 1, Pred(Pos(EQ, S)));
end;

function ValueOf(const S: string): string;
var
  P: Integer;
begin
  Result := S;
  P := Pos(EQ, S);
  if P <> 0 then
    Delete(Result, 1, P);
end;

procedure NameValueOf(const S: string; out AName, AValue: string);
var
  P: Integer;
begin
  AName := ES;
  AValue := S;
  P := Pos(EQ, AValue);
  if P <> 0 then
  begin
    AName := Copy(AValue, 1, Pred(P));
    Delete(AValue, 1, P);
  end;
end;

function FileNameOf(const S: string): string;
begin
  Result := Copy(S, Succ(LastDelimiter('\:/', S)), MaxInt);
end;

procedure StrToFile(const S: string; const AFileName: TFileName);
begin
  with TFileStream.Create(AFileName, fmCreate) do
    try
      Write(Pointer(S)^, Length(S));
    finally
      Free;
    end;
end;

function FileToStr(const AFileName: TFileName): string;
var
  L: LongInt;
begin
  with TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite) do
    try
      L := Size;
      SetLength(Result, L);
      Read(Pointer(Result)^, L);
    finally
      Free;
    end;
end;

function HiddenPassword(const APass: string; const AChar: Char): string;
begin
  if APass = ES then
    Result := ES
  else
    Result := StringOfChar(AChar, Length(APass));
end;

function StrToHex(const S: string): string;
var
  I: Integer;
begin
  SetLength(Result, Length(S) * 2);
  for I := 1 to Length(S) do
  begin
    Result[I * 2 - 1] := HexCharsArray[Byte(S[I]) shr 4];
    Result[I * 2] := HexCharsArray[Byte(S[I]) and $0F];
  end;
end;

function HexToStr(const AHex: string): string;
var
  I: Integer;
begin
  if Length(AHex) mod 2 <> 0 then
    Exit;
  SetLength(Result, Length(AHex) div 2);
  for I := 1 to Length(Result) do
  begin
    if AHex[I * 2 - 1] in ['0'..'9'] then
      Result[I] := Chr(Ord(AHex[I * 2 - 1]) - Ord('0'))
    else
      if AHex[I * 2 - 1] in ['A'..'F'] then
        Result[I] := Chr(Ord(AHex[I * 2 - 1]) - Ord('A') + 10)
    else
      Exit;
    Result[I] := Chr(Ord(Result[I]) shl 4);
{$HINTS OFF}
    if AHex[I * 2] in ['0'..'9'] then
      Result[I] := Chr(Ord(Result[I]) + Ord(AHex[I * 2]) - Ord('0'))
    else
      if AHex[I * 2] in ['A'..'F'] then
        Result[I] := Chr(Ord(Result[I]) + Ord(AHex[I * 2]) - Ord('A') + 10)
      else
        Exit;
{$HINTS ON}
  end;
end;

function DeleteLineBreaks(const S: string; const ASubstitute: Char): string;
var
  I: Integer;
  P: PChar;
begin
  Result := S;
  if not Assigned(Pointer(Result)) then
    Exit;
  UniqueString(Result);
  P := PChar(Result);
  for I := 1 to Length(Result) do
  begin
    case P^ of
      LF: P^ := ASubstitute;
      CR: P^ := ASubstitute;
    end;
    Inc(P);
  end;
end;

function ReplaceChar(const S: string; const AOldChar, ANewChar: Char): string;
var
  I: Integer;
  P: PChar;
begin
  Result := S;
  if not Assigned(Pointer(Result)) then
    Exit;
  UniqueString(Result);
  P := PChar(Result);
  for I := 1 to Length(Result) do
  begin
    if P^ = AOldChar then
      P^ := ANewChar;
    Inc(P);
  end;
end;

function ReplaceChar(const S: string; const AOldChars: TSysCharSet;
  const ANewChar: Char): string;
var
  I: Integer;
  P: PChar;
begin
  Result := S;
  if (not Assigned(Pointer(Result))) or (AOldChars = []) then
    Exit;
  UniqueString(Result);
  P := PChar(Result);
  for I := 1 to Length(Result) do
  begin
    if P^ in AOldChars then
      P^ := ANewChar;
    Inc(P);
  end;
end;

function SizeToStr(const ASize: Extended): ShortString;
var
  I: Extended;
begin
  I := Abs(ASize);
  if I < 1000 then
    Result := Format('%.0n B', [ASize / 1])
  else if I < 10235 then
    Result := Format('%.2n KB', [ASize / 1024])
  else if I < 102349 then
    Result := Format('%.1n KB', [ASize / 1024])
  else if I < 1023488 then
    Result := Format('%.0n KB', [ASize / 1024])
  else if I < 10480518 then
    Result := Format('%.2n MB', [ASize / 1048576])
  else if I < 104805172 then
    Result := Format('%.1n MB', [ASize / 1048576])
  else if I < 1048051712 then
    Result := Format('%.0n MB', [ASize / 1048576])
  else if I < 10732049531 then
    Result := Format('%.2n GB', [ASize / 1073741824])
  else if I < 107320495309 then
    Result := Format('%.1n GB', [ASize / 1073741824])
  else if I < 1073204953088 then
    Result := Format('%.0n GB', [ASize / 1073741824])
  else if I < 10989618719622 then
    Result := Format('%.2n TB', [ASize / 1099511627776])
  else if I < 109896187196212 then
    Result := Format('%.1n TB', [ASize / 1099511627776])
  else if I < 1098961871962112 then
    Result := Format('%.0n TB', [ASize / 1099511627776])
  else if I < 11253369568892027 then
    Result := Format('%.2n PB', [ASize / 1125899906842624])
  else if I < 112533695688920269 then
    Result := Format('%.1n PB', [ASize / 1125899906842624])
  else if I < 1125336956889202688 then
    Result := Format('%.0n PB', [ASize / 1125899906842624])
  else
    Result := Format('%.2n EB', [ASize / 1152921504606846976]);
end;

function OnlyAlphaChars(const S: string): string;
var
  I: Integer;
  PSrc, PDest: PChar;
begin
  SetLength(Result, Length(S));
  PSrc := PChar(S);
  PDest := PChar(Result);
  I := 0;
  while PSrc^ <> NU do
  begin
    if PSrc^ in ['a'..'z', 'A'..'Z'] then
    begin
      PDest^ := PSrc^;
      Inc(PDest);
      Inc(I);
    end;
    Inc(PSrc);
  end;
  SetLength(Result, I);
end;

function OnlyNumbers(const S: string): string;
var
  I: Integer;
  PSrc, PDest: PChar;
begin
  SetLength(Result, Length(S));
  PSrc := PChar(S);
  PDest := PChar(Result);
  I := 0;
  while PSrc^ <> NU do
  begin
    if PSrc^ in ['0'..'9'] then
    begin
      PDest^ := PSrc^;
      Inc(PDest);
      Inc(I);
    end;
    Inc(PSrc);
  end;
  SetLength(Result, I);
end;

function OnlySpecialChars(const S: string): string;
var
  I: Integer;
  PSrc, PDest: PChar;
begin
  SetLength(Result, Length(S));
  PSrc := PChar(S);
  PDest := PChar(Result);
  I := 0;
  while PSrc^ <> NU do
  begin
    if not (PSrc^ in ['0'..'9', 'a'..'z', 'A'..'Z']) then
    begin
      PDest^ := PSrc^;
      Inc(PDest);
      Inc(I);
    end;
    Inc(PSrc);
  end;
  SetLength(Result, I);
end;

function OnlySpecificChars(const S: string; const AChars: TSysCharSet): string;
var
  I: Integer;
  PSrc, PDest: PChar;
begin
  SetLength(Result, Length(S));
  PSrc := PChar(S);
  PDest := PChar(Result);
  I := 0;
  while PSrc^ <> NU do
  begin
    if PSrc^ in AChars then
    begin
      PDest^ := PSrc^;
      Inc(PDest);
      Inc(I);
    end;
    Inc(PSrc);
  end;
  SetLength(Result, I);
end;

function UnderlineStr(const S: string): string;
var
  PSrc, PDest: PChar;
  VWord, VSrc: string;
  I: SizeInt;
begin
  SetLength(VSrc, Length(S));
  PSrc := PChar(S);
  PDest := PChar(VSrc);
  while PSrc^ <> NU do
  begin
    if PSrc^ in ['_', '0'..'9', 'a'..'z', 'A'..'Z'] then
      PDest^ := PSrc^
    else
      PDest^ := ' ';
    Inc(PDest);
    Inc(PSrc);
  end;
  I := 1;
  VWord := '';
  Result := '';
  repeat
    VWord := ExtractWord(I, VSrc, [' ']);
    if Length(VWord) > 3 then
      Result += VWord + '_';
    Inc(I);
  until VWord = '';
  SetLength(Result, Length(Result) - 1);
end;

function Explode(const S: string; const ADelimiter: string;
  const ALimit: Integer): TArrayOfString;
var
  PFar, PSrc: PChar;
  VLen, VSepLen, VIndex: Integer;
begin
  SetLength(Result, 0);
  if (S = ES) or (ALimit < 0) then
    Exit;
  if ADelimiter = ES then
  begin
    SetLength(Result, 1);
    Result[0] := S;
    Exit;
  end;
  VSepLen := Length(ADelimiter);
  VLen := ALimit;
  SetLength(Result, VLen);
  VIndex := 0;
  PSrc := PChar(S);
  while PSrc^ <> NU do
  begin
    PFar := PSrc;
    PSrc := StrPos(PSrc, PChar(ADelimiter));
    if (PSrc = nil) or ((ALimit > 0) and (VIndex = ALimit - 1)) then
      PSrc := StrEnd(PFar);
    if VIndex >= VLen then
    begin
      Inc(VLen, 5);
      SetLength(Result, VLen);
    end;
    SetString(Result[VIndex], PFar, PSrc - PFar);
    Inc(VIndex);
    if PSrc^ <> NU then
      Inc(PSrc, VSepLen);
  end;
  if VIndex < VLen then
    SetLength(Result, VIndex);
end;

function Implode(const AArray: TArrayOfString; const ADelimiter: string): string;
var
  S: string;
  L: SizeInt;
begin
  Result := ES;
  for S in AArray do
    Result += S + ADelimiter;
  L := Length(Result);
  if L > 0 then
    SetLength(Result, L - Length(ADelimiter));
end;

function Implode(const AArray: array of string; const ADelimiter: string): string;
var
  S: string;
  L: SizeInt;
begin
  Result := ES;
  for S in AArray do
    Result += S + ADelimiter;
  L := Length(Result);
  if L > 0 then
    SetLength(Result, L - Length(ADelimiter));
end;

function Occurs(const S, APart: string): SizeInt;
var
  VOffset: SizeInt;
begin
  Result := 0;
  VOffset := PosEx(APart, S, 1);
  while VOffset <> 0 do
  begin
    VOffset := PosEx(APart, S, VOffset + Length(APart));
    Inc(Result);
  end;
end;

function Occurs(const S: string; const AParts: array of string): SizeInt;
var
  I: Integer;
  VOffset: SizeInt;
begin
  Result := 0;
  for I := 0 to High(AParts) do
  begin
    VOffset := PosEx(AParts[I], S, 1);
    while VOffset <> 0 do
    begin
      VOffset := PosEx(AParts[I], S, VOffset + Length(AParts[I]));
      Inc(Result);
    end;
  end;
end;

function Exists(const S: string; const AParts: array of string): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(AParts) do
  begin
    Result := S = AParts[I];
    if Result then
      Exit;
  end;
  Result := False;
end;

function Exists(const S: string; const AParts: array of string;
  const AIgnoreCase: Boolean): Boolean;
var
  I: Integer;
begin
  if AIgnoreCase then
  begin
    for I := 0 to High(AParts) do
    begin
      Result := CompareText(S, AParts[I]) = 0;
      if Result then
        Exit;
    end;
    Result := False;
  end
  else
    Result := Exists(S, AParts);
end;

function MatchStrings(ASource, APattern: string): Boolean;
var
  PSrc: array[0..255] of Char;
  PPatt: array[0..255] of Char;

  function MatchPattern(AElement, APattern: PChar): Boolean;

    function IsPatternWild(APattern: PChar): Boolean;
    begin
      Result := Assigned(StrScan(APattern, AK));
      if not Result then
        Result := Assigned(StrScan(APattern, QU));
    end;

  begin
    if StrComp(APattern, AK) = 0 then
      Result := True
    else
    if (AElement^ = NU) and (APattern^ <> NU) then
      Result := False
    else
    if AElement^ = NU then
      Result := True
    else
      case APattern^ of
        AK:
          if MatchPattern(AElement, @APattern[1]) then
            Result := True
          else
            Result := MatchPattern(@AElement[1], APattern);
        QU: Result := MatchPattern(@AElement[1], @APattern[1]);
      else
        if AElement^ = APattern^ then
          Result := MatchPattern(@AElement[1], @APattern[1])
        else
          Result := False;
      end;
  end;

begin
  StrPCopy(PSrc, ASource);
  StrPCopy(PPatt, APattern);
  Result := MatchPattern(PSrc, PPatt);
end;

function SeparateRight(const S, ADelimiter: string): string;
var
  P: Integer;
begin
  P := Pos(ADelimiter, S);
  if P > 0 then
    P := P + Length(ADelimiter) - 1;
  Result := Copy(S, P + 1, Length(S) - P);
end;

function SeparateRight(const S, ADelimiter: string;
  const AIgnoreCase: Boolean): string;
var
  P: Integer;
begin
  if AIgnoreCase then
  begin
    P := Pos(LowerCase(ADelimiter), LowerCase(S));
    if P > 0 then
      P := P + Length(ADelimiter) - 1;
    Result := Copy(S, P + 1, Length(S) - P);
  end
  else
    Result := SeparateRight(S, ADelimiter);
end;

function Between(const AStart, AEnd: string; const S: string): string;
var
  I, C, L1, L2, L3: Integer;
  S1, S2: string;
begin
  L1 := Length(S);
  L2 := Length(AStart);
  L3 := Length(AEnd);
  if (S = AStart + AEnd) then
  begin
    Result := ES;
    Exit;
  end;
  if (L1 < L2 + L3) then
  begin
    Result := ES;
    Exit;
  end;
  S1 := SeparateRight(S, AStart);
  if (S1 = S) then
  begin
    Result := ES;
    Exit;
  end;
  L1 := Pos(AEnd, S1);
  if (L1 = 0) then
  begin
    Result := ES;
    Exit;
  end;
  Result := ES;
  I := 1;
  C := Length(S1) - L3 + 1;
  for L1 := 1 to C do
  begin
    S2 := Copy(S1, L1, L3);
    if (S2 = AEnd) then
    begin
      Dec(I);
      if (I <= 0) then
        Break;
    end;
    S2 := Copy(S1, L1, L2);
    if (S2 = AStart) then
      Inc(I);
    Result := Result + S1[L1];
  end;
end;

function Between(const AStart, AEnd: string; const S: string;
  const AIgnoreCase: Boolean): string;
var
  I, C, L1, L2, L3: Integer;
  S1, S2: string;
begin
  if AIgnoreCase then
  begin
    L1 := Length(S);
    L2 := Length(AStart);
    L3 := Length(AEnd);
    if (S = AStart + AEnd) then
    begin
      Result := ES;
      Exit;
    end;
    if (L1 < L2 + L3) then
    begin
      Result := ES;
      Exit;
    end;
    S1 := SeparateRight(S, AStart, True);
    if (S1 = S) then
    begin
      Result := ES;
      Exit;
    end;
    L1 := Pos(LowerCase(AEnd), LowerCase(S1));
    if (L1 = 0) then
    begin
      Result := ES;
      Exit;
    end;
    Result := ES;
    I := 1;
    C := Length(S1) - L3 + 1;
    for L1 := 1 to C do
    begin
      S2 := Copy(S1, L1, L3);
      if (S2 = AEnd) then
      begin
        Dec(I);
        if (I <= 0) then
          Break;
      end;
      S2 := Copy(S1, L1, L2);
      if (S2 = AStart) then
        Inc(I);
      Result := Result + S1[L1];
    end;
  end
  else
    Result := Between(AStart, AEnd, S);
end;

function RemoveDiacritics(const S: string): string;
var
  F: Boolean;
  I: SizeInt;
  PS, PD: PChar;
begin
  SetLength(Result, Length(S));
  PS := PChar(S);
  PD := PChar(Result);
  I := 0;
  while PS^ <> #0 do
  begin
    F := PS^ = #195;
    if F then
      case PS[1] of
        #128..#134: PD^ := 'A';
        #135: PD^ := 'C';
        #136..#139: PD^ := 'E';
        #140..#143: PD^ := 'I';
        #144: PD^ := 'D';
        #145: PD^ := 'N';
        #146..#150, #152: PD^ := 'O';
        #151: PD^ := 'x';
        #153..#156: PD^ := 'U';
        #157: PD^ := 'Y';
        #158: PD^ := 'P';
        #159: PD^ := 's';
        #160..#166: PD^ := 'a';
        #167: PD^ := 'c';
        #168..#171: PD^ := 'e';
        #172..#175: PD^ := 'i';
        #176: PD^ := 'd';
        #177: PD^ := 'n';
        #178..#182, #184: PD^ := 'o';
        #183: PD^ := '-';
        #185..#188: PD^ := 'u';
        #190: PD^ := 'p';
        #189, #191: PD^ := 'y';
      else
        F := False;
      end;
    if F then
      Inc(PS)
    else
      PD^ := PS^;
    Inc(I);
    Inc(PD);
    Inc(PS);
  end;
  SetLength(Result, I);
end;

function RemoveSpecialChars(const S: string): string;
var
  F: Boolean;
  I: SizeInt;
  PS, PD: PChar;
begin
  SetLength(Result, Length(S));
  PS := PChar(S);
  PD := PChar(Result);
  I := 0;
  while PS^ <> #0 do
  begin
    F := PS^ = #194;
    if F then
      case PS[1] of
        #161: PD^ := '!';
        #162, #169: PD^ := 'c';
        #163: PD^ := 'l';
        #164: PD^ := 'o';
        #165: PD^ := 'y';
        #166: PD^ := '|';
        #167: PD^ := 's';
        #168: PD^ := '"';
        #170, #172, #173: PD^ := '-';
        #171: PD^ := '<';
        #174: PD^ := 'r';
        #175, #176, #178, #179, #183, #185: PD^ := '^';
        #177: PD^ := '+';
        #180: PD^ := '\';
        #181: PD^ := '/';
        #182: PD^ := 'P';
        #184: PD^ := ',';
        #186: PD^ := '_';
        #187: PD^ := '>';
        #188, #189: PD^ := '1';
        #190: PD^ := '3';
        #191: PD^ := '?';
      else
        F := False;
      end;
    if F then
      Inc(PS)
    else
      PD^ := PS^;
    Inc(I);
    Inc(PD);
    Inc(PS);
  end;
  SetLength(Result, I);
end;

{ Conditional }

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: string): string;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Char): Char;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Byte): Byte;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Integer): Integer;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Cardinal): Cardinal;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Double): Double;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Boolean): Boolean;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Pointer): Pointer;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Int64): Int64;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

function Iif(const ACondition: Boolean;
  const ATruePart, AFalsePart: Variant): Variant;
begin
  if ACondition then
    Result := ATruePart
  else
    Result := AFalsePart;
end;

{ JSON }

function ParamsToJSON(const AParam: string; const ASeparator,
  ADelimiter: Char): TJSONStringType;
var
  VChar: Char;
  I, J, VPos: Integer;
  S, VName, VValue, VResult: string;
begin
  Result := AParam;
  if Length(Result) = 0 then
  begin
    Result := '{}';
    Exit;
  end;
  VResult := ES;
  I := 1;
  J := 1;
  while I <= Length(Result) do
  begin
    VChar := Result[I];
    if VChar = ASeparator then
      Result[I] := CO;
    if VChar = ADelimiter then
      Result[I] := CS;
    if VChar = ADelimiter then
    begin
      S := Copy(Result, J, I - J);
      VPos := Pos(CO, S);
      VName := Copy(S, 1, Pred(VPos));
      VValue := ES;
      if VName <> ES then
        VValue := Copy(S, Succ(VPos), MaxInt);
      VResult += DQ + VName + '": "' +
        StringToJSONString(HTTPDecode(VValue)) + '", ';
      J := I + 1;
    end;
    Inc(I);
  end;
  if Length(VResult) > 0 then
  begin
    S := Copy(Result, J, I - J);
    VPos := Pos(CO, S);
    VName := Copy(S, 1, Pred(VPos));
    VValue := ES;
    if VName <> ES then
      VValue := Copy(S, Succ(VPos), MaxInt);
    VResult += DQ + VName + '": "' +
      StringToJSONString(HTTPDecode(VValue)) + DQ;
  end
  else
  begin
    VPos := Pos(CO, Result);
    VName := Copy(Result, 1, Pred(VPos));
    VValue := ES;
    if VName <> ES then
      VValue := Copy(Result, Succ(VPos), MaxInt);
    VResult := DQ + VName + '": "' +
      StringToJSONString(HTTPDecode(VValue)) + DQ;
  end;
  Result := '{ ' + VResult + ' }';
end;

function JSONToParams(AJSON: TJSONObject): string;
var
  I: Integer;
begin
  Result := ES;
  for I := 0 to Pred(AJSON.Count) do
    Result += AJSON.Names[I] + EQ + AJSON.Items[I].AsString + AM;
  SetLength(Result, Length(Result) - Length(AM));
end;

function PathToJSON(const APath: string; const ADelimiter: Char): TJSONStringType;
var
  S: string;
  I, L: LongInt;
begin
  Result := APath;
  L := Length(Result);
  if L < 2 then
  begin
    Result := '[]';
    Exit;
  end;
  S := ES;
  for I := 1 to L do
    if Result[I] = ADelimiter then
    begin
      if (I = 1) or (I = L) then
        S += DQ
      else
        S += '", "';
    end
    else
      S += Result[I];
  if S[1] <> DQ then
    Insert(DQ, S, 1);
  L := Length(S);
  if S[L] <> DQ then
    Insert(DQ, S, L + 1);
  Result := '[ ' + HTTPDecode(S) + ' ]'
end;

function JSONToPath(AJSON: TJSONArray): string;
var
  I: Integer;
begin
  Result := ES;
  for I := 0 to Pred(AJSON.Count) do
    Result += AJSON[I].AsString;
  SetLength(Result, Length(Result) - Length(US));
end;

procedure GetJSONArray(AStream: TStream; out AJSON: TJSONArray);
var
  VParser: TJSONParser;
begin
  VParser := TJSONParser.Create(AStream);
  try
    AJSON := VParser.Parse as TJSONArray;
  finally
    VParser.Free;
  end;
end;

procedure GetJSONArray(const S: TJSONStringType; out AJSON: TJSONArray);
var
  VParser: TJSONParser;
begin
  VParser := TJSONParser.Create(S);
  try
    AJSON := VParser.Parse as TJSONArray;
  finally
    VParser.Free;
  end;
end;

procedure GetJSONObject(AStream: TStream; out AJSON: TJSONObject);
var
  VParser: TJSONParser;
begin
  VParser := TJSONParser.Create(AStream);
  try
    AJSON := VParser.Parse as TJSONObject;
  finally
    VParser.Free;
  end;
end;

procedure GetJSONObject(const S: TJSONStringType; out AJSON: TJSONObject);
var
  VParser: TJSONParser;
begin
  VParser := TJSONParser.Create(S);
  try
    AJSON := VParser.Parse as TJSONObject;
  finally
    VParser.Free;
  end;
end;

{ Util }

function GetTickCount: DWord;
begin
  Result := DWord(Trunc(Now * HoursPerDay * MinsPerHour * SecsPerMin * MSecsPerSec));
end;

function ReadString(AStream: TStream; const ALength: Int64): string;
begin
  SetLength(Result, ALength);
  AStream.Read(Pointer(Result)^, ALength);
end;

end.
